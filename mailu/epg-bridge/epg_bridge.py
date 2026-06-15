import asyncio
import imaplib
import json
import logging
import os
import smtplib
import time
import uuid
from email import message_from_bytes

import redis
from aiosmtpd.controller import Controller

logging.basicConfig(level=logging.INFO, format="%(asctime)s [BRIDGE] %(levelname)s %(message)s")
logger = logging.getLogger("EPG-Bridge")

REDIS_HOST     = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT     = int(os.environ.get("REDIS_PORT", 6379))
EMAIL_DIR      = os.environ.get("EMAIL_DIR", "/data/emails")
MAILU_HOST     = os.environ.get("MAILU_HOST", "mailserver")
IMAP_PORT      = int(os.environ.get("IMAP_PORT", 993))
IMAP_USER      = os.environ.get("IMAP_USER", "admin@jawabi.app")
IMAP_PASS      = os.environ.get("IMAP_PASS", "admin123")
SMTP_HOSTNAME  = os.environ.get("SMTP_HOSTNAME", "jawabi.app")
LOCAL_DOMAIN   = os.environ.get("LOCAL_DOMAIN", "jawabi.app")  # Recipients on this domain = IMAP delivery
RELAY_PORT     = int(os.environ.get("RELAY_PORT", 25))         # Haraka port for outbound internet relay
RESULT_TIMEOUT = int(os.environ.get("RESULT_TIMEOUT", "120"))

os.makedirs(EMAIL_DIR, exist_ok=True)


def get_redis() -> redis.Redis:
    """Return a fresh sync Redis client. Thread-safe — no shared async state."""
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


class EPGBridgeHandler:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        # Prevent open relaying: only accept emails meant for our own domain
        if not address.lower().endswith(f"@{LOCAL_DOMAIN.lower()}"):
            logger.warning(f"Rejected relay attempt from {session.peer} to {address}")
            return f"550 Relaying denied to {address}"
        
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope) -> str:
        message_id = str(uuid.uuid4())
        sender = envelope.mail_from or "unknown"
        recipients = envelope.rcpt_tos

        logger.info(f"[{message_id[:8]}] Receiving from {sender} to {recipients}")
        try:
            peer_ip = session.peer[0] if session.peer else "127.0.0.1"
            msg = message_from_bytes(envelope.content)
            received = (f"from {session.host_name} ([{peer_ip}]) by {SMTP_HOSTNAME} "
                        f"with ESMTP id {message_id}; {time.strftime('%a, %d %b %Y %H:%M:%S %z')}")
            msg._headers.insert(0, ('Received', received))
            if not msg.get("From"):       msg["From"]       = sender
            if not msg.get("To"):         msg["To"]         = ", ".join(recipients)
            if not msg.get("Message-ID"): msg["Message-ID"] = f"<{message_id}@{SMTP_HOSTNAME}>"
            if not msg.get("Date"):       msg["Date"]       = time.strftime("%a, %d %b %Y %H:%M:%S %z")
            content_to_save = msg.as_bytes()
        except Exception as e:
            logger.error(f"Failed to inject headers: {e}")
            content_to_save = envelope.content

        eml_path = os.path.join(EMAIL_DIR, f"{message_id}.eml")
        with open(eml_path, "wb") as f:
            f.write(content_to_save)

        rdb = get_redis()
        job = {"eml_path": eml_path, "envelope": {"from": sender, "to": recipients, "message_id": message_id}}
        rdb.rpush("email_queue", json.dumps(job))
        logger.info(f"[{message_id[:8]}] Queued for EPG pipeline")

        result_key = f"result:{message_id}"
        result = None
        for _ in range(RESULT_TIMEOUT):
            raw = rdb.get(result_key)
            if raw:
                result = json.loads(raw)
                break
            await asyncio.sleep(1)

        if result is None:
            logger.warning(f"[{message_id[:8]}] Pipeline timeout, accepting")
            self._deliver(sender, recipients, content_to_save)
            return "250 Accepted (timeout)"

        action  = result.get("action",        "DELIVERED")
        verdict = result.get("final_verdict",  "CLEAN")
        reason  = result.get("block_reason",   "Policy violation")

        if action == "BLOCKED":
            # Silent drop — sender gets no bounce, attacker gets zero feedback
            logger.info(f"[{message_id[:8]}] SILENTLY DROPPED - {verdict} - {reason}")
            return "250 Message accepted"

        if action == "TAGGED":
            try:
                msg = message_from_bytes(content_to_save)
                msg["X-Spam-Flag"]   = "YES"
                msg["X-Spam-Status"] = "Yes"
                msg["X-EPG-Verdict"] = verdict
                original_subject = msg.get("Subject", "")
                del msg["Subject"]
                msg["Subject"] = f"*****SPAM***** {original_subject}"
                content_to_save = msg.as_bytes()
                logger.info(f"[{message_id[:8]}] TAGGED - Added spam headers")
            except Exception as e:
                logger.error(f"Error modifying tagged email: {e}")

        elif action == "SUSPICIOUS_SPAM":
            try:
                msg = message_from_bytes(content_to_save)
                msg["X-Spam-Flag"]   = "YES"
                msg["X-Spam-Status"] = "Yes"
                msg["X-EPG-Verdict"] = verdict
                original_subject = msg.get("Subject", "")
                del msg["Subject"]
                msg["Subject"] = f"*****SUSPICIOUS SPAM***** {original_subject}"
                content_to_save = msg.as_bytes()
                logger.info(f"[{message_id[:8]}] SUSPICIOUS_SPAM - Added suspicious spam headers")
            except Exception as e:
                logger.error(f"Error modifying suspicious spam email: {e}")

        if action == "QUARANTINED":
            try:
                msg = message_from_bytes(content_to_save)
                msg["X-EPG-Warning"] = f"[{verdict}] Held for review"
                original_subject = msg.get("Subject", "")
                del msg["Subject"]
                msg["Subject"] = f"[QUARANTINE] {original_subject}"
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_maintype() != 'multipart' and part.get('Content-Disposition'):
                            filename = part.get_filename() or "unknown_file"
                            warning_text = (
                                f"SECURITY WARNING:\n\n"
                                f"The original attachment '{filename}' was flagged as {verdict}.\n"
                                f"It has been removed and is held in quarantine pending SOC team review."
                            )
                            part.set_payload(warning_text)
                            del part["Content-Type"]
                            part["Content-Type"] = "text/plain; charset=utf-8"
                            if "Content-Transfer-Encoding" in part: del part["Content-Transfer-Encoding"]
                            if "Content-Disposition"       in part: del part["Content-Disposition"]
                content_to_save = msg.as_bytes()
            except Exception as e:
                logger.error(f"Error modifying quarantined email: {e}")

        logger.info(f"[{message_id[:8]}] Forwarding to Mail Server ({action})")
        folder  = "Junk" if action in ["TAGGED", "SUSPICIOUS_SPAM"] else "INBOX"
        success, err_msg = self._deliver(sender, recipients, content_to_save, folder)
        return "250 Message delivered" if success else f"451 Temporary failure forwarding to backend: {err_msg}"

    # ──────────────────────────────────────────────────────────────────────────
    # SMART ROUTER — local vs remote recipients
    # ──────────────────────────────────────────────────────────────────────────
    def _deliver(self, sender, recipients, content_bytes, folder="INBOX"):
        """
        Routes email after EPG scanning:
          • Local recipients  (@jawabi.app)  → IMAP APPEND (bypasses Haraka MX check)
          • Remote recipients (@gmail.com…)  → SMTP relay via Haraka port 25
        """
        # We cannot use IMAP APPEND with a single hardcoded admin account, 
        # otherwise all local mail goes to the admin's inbox!
        # Instead, we relay everything via SMTP. 
        # To support routing to the Junk folder, we inject an X-Spam header.
        
        from email import message_from_bytes
        
        if folder == "Junk":
            try:
                msg = message_from_bytes(content_bytes)
                if not msg.get("X-Spam-Flag"):
                    msg.add_header("X-Spam-Flag", "YES")
                content_bytes = msg.as_bytes()
            except Exception as e:
                logger.error(f"Failed to add spam flag: {e}")
                
        return self._relay_via_smtp(sender, recipients, content_bytes)


    def _relay_via_smtp(self, sender, recipients, content_bytes):
        """Relay email to external (internet) recipients via the mailserver's Haraka SMTP."""
        try:
            logger.info(f"SMTP RELAY to internet: {recipients} via {MAILU_HOST}:{RELAY_PORT}")
            with smtplib.SMTP(MAILU_HOST, RELAY_PORT, timeout=30) as smtp:
                smtp.sendmail(sender, recipients, content_bytes)
            logger.info(f"SMTP RELAY delivered to {recipients}")
            return True, ""
        except Exception as e:
            logger.error(f"SMTP RELAY failed for {recipients}: {e}")
            return False, str(e)


async def main():
    handler = EPGBridgeHandler()
    ctrl25  = Controller(handler, hostname="0.0.0.0", port=25,  server_hostname=SMTP_HOSTNAME)
    ctrl587 = Controller(handler, hostname="0.0.0.0", port=587, server_hostname=SMTP_HOSTNAME)
    ctrl25.start()
    ctrl587.start()
    logger.info(f"EPG Bridge listening on :25 and :587 | IMAP delivery to {MAILU_HOST}:{IMAP_PORT} | SMTP relay via {MAILU_HOST}:{RELAY_PORT}")
    try:
        await asyncio.Event().wait()
    finally:
        ctrl25.stop()
        ctrl587.stop()


if __name__ == "__main__":
    asyncio.run(main())
