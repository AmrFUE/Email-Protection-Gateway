import sys

with open("d:/New_EGPInAzure/EGPInAzure/mailu/epg-bridge/epg_bridge.py", "r") as f:
    content = f.read()

# Replace 1
old1 = """        logger.info(f"[{message_id[:8]}] Forwarding to Mail Server ({action})")
        folder  = "Junk" if action in ["TAGGED", "SUSPICIOUS_SPAM"] else "INBOX"
        success = self._deliver(sender, recipients, content_to_save, folder)
        return "250 Message delivered" if success else "451 Temporary failure forwarding to backend\""""
new1 = """        logger.info(f"[{message_id[:8]}] Forwarding to Mail Server ({action})")
        folder  = "Junk" if action in ["TAGGED", "SUSPICIOUS_SPAM"] else "INBOX"
        success, err_msg = self._deliver(sender, recipients, content_to_save, folder)
        return "250 Message delivered" if success else f"451 Temporary failure forwarding to backend: {err_msg}\""""
content = content.replace(old1, new1)

# Replace 2
old2 = """                msg.add_header("X-Spam-Flag", "YES")
                content_bytes = msg.as_bytes()
            except Exception as e:
                logger.error(f"Failed to add spam flag: {e}")
                
        return self._relay_via_smtp(sender, recipients, content_bytes)

    def _relay_via_smtp(self, sender, recipients, content_bytes):"""
new2 = """                msg.add_header("X-Spam-Flag", "YES")
                content_bytes = msg.as_bytes()
            except Exception as e:
                logger.error(f"Failed to add spam flag: {e}")
                
        return self._relay_via_smtp(sender, recipients, content_bytes)

    def _relay_via_smtp(self, sender, recipients, content_bytes):"""
content = content.replace(old2, new2)

# Replace 3
old3 = """            with smtplib.SMTP(MAILU_HOST, RELAY_PORT, timeout=30) as smtp:
                smtp.sendmail(sender, recipients, content_bytes)
            logger.info(f"SMTP RELAY delivered to {recipients}")
            return True
        except Exception as e:
            logger.error(f"SMTP RELAY failed for {recipients}: {e}")
            return False"""
new3 = """            with smtplib.SMTP(MAILU_HOST, RELAY_PORT, timeout=30) as smtp:
                smtp.sendmail(sender, recipients, content_bytes)
            logger.info(f"SMTP RELAY delivered to {recipients}")
            return True, ""
        except Exception as e:
            logger.error(f"SMTP RELAY failed for {recipients}: {e}")
            return False, str(e)"""
content = content.replace(old3, new3)

with open("d:/New_EGPInAzure/EGPInAzure/mailu/epg-bridge/epg_bridge.py", "w") as f:
    f.write(content)
print("Done")
