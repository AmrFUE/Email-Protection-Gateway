import email
from email.message import Message
import re
from bs4 import BeautifulSoup
from typing import Dict, List, Any, Optional

class EmailParser:
    @staticmethod
    def parse_from_string(raw_email_str: str) -> Dict[str, Any]:
        """Parses a raw email string into a structured dictionary."""
        msg = email.message_from_string(raw_email_str)
        return EmailParser.parse_message(msg)

    @staticmethod
    def parse_message(msg: Message) -> Dict[str, Any]:
        """Extracts fields and structures from an email.message.Message object."""
        result = {
            "sender": msg.get("From", ""),
            "receiver": msg.get("To", ""),
            "date": msg.get("Date", ""),
            "subject": msg.get("Subject", ""),
            "reply_to": msg.get("Reply-To", ""),
            "x_mailer": msg.get("X-Mailer", "") or msg.get("User-Agent", ""),
            "body_text": "",
            "body_html": "",
            "urls": [],  # List of {"href": str, "text": str}
            "auth_headers": {
                "spf": "NONE",
                "dkim": "NONE",
                "dmarc": "NONE",
                "raw_auth_results": msg.get("Authentication-Results", "") or msg.get("Received-SPF", "")
            }
        }

        # Parse authentication headers
        auth_results = result["auth_headers"]["raw_auth_results"]
        if auth_results:
            auth_results_lower = auth_results.lower()
            
            # Detect SPF
            if "spf=pass" in auth_results_lower:
                result["auth_headers"]["spf"] = "PASS"
            elif "spf=fail" in auth_results_lower or "spf=softfail" in auth_results_lower:
                result["auth_headers"]["spf"] = "FAIL"
            elif "spf=neutral" in auth_results_lower or "spf=none" in auth_results_lower:
                result["auth_headers"]["spf"] = "NEUTRAL"

            # Detect DKIM
            if "dkim=pass" in auth_results_lower:
                result["auth_headers"]["dkim"] = "PASS"
            elif "dkim=fail" in auth_results_lower:
                result["auth_headers"]["dkim"] = "FAIL"

            # Detect DMARC
            if "dmarc=pass" in auth_results_lower:
                result["auth_headers"]["dmarc"] = "PASS"
            elif "dmarc=fail" in auth_results_lower:
                result["auth_headers"]["dmarc"] = "FAIL"

        # If we didn't find authentication status, check specific headers
        if result["auth_headers"]["spf"] == "NONE":
            spf_header = msg.get("Received-SPF", "")
            if spf_header:
                spf_lower = spf_header.lower()
                if "pass" in spf_lower:
                    result["auth_headers"]["spf"] = "PASS"
                elif "fail" in spf_lower:
                    result["auth_headers"]["spf"] = "FAIL"

        # Walk through message parts
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                # Skip attachments
                if "attachment" in content_disposition:
                    continue
                
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        text = payload.decode(charset, errors='ignore')
                        if content_type == "text/plain":
                            result["body_text"] += text
                        elif content_type == "text/html":
                            result["body_html"] += text
                except Exception:
                    pass
        else:
            content_type = msg.get_content_type()
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    text = payload.decode(charset, errors='ignore')
                    if content_type == "text/html":
                        result["body_html"] = text
                    else:
                        result["body_text"] = text
            except Exception:
                pass

        # If body_html is empty but body_text contains HTML, move it
        if not result["body_html"] and ("<html" in result["body_text"].lower() or "<body" in result["body_text"].lower()):
            result["body_html"] = result["body_text"]
            result["body_text"] = ""

        # Extract URLs and display text from HTML
        if result["body_html"]:
            soup = BeautifulSoup(result["body_html"], "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                text = a_tag.get_text().strip()
                if href:
                    result["urls"].append({"href": href, "text": text})
        
        # If no URLs found in HTML, or we only have plain text, extract URLs via regex
        url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
        text_to_search = result["body_text"] or result["body_html"]
        if text_to_search:
            raw_urls = url_pattern.findall(text_to_search)
            # Remove trailing punctuations often caught in regex
            cleaned_urls = []
            for url in raw_urls:
                cleaned_url = url.rstrip('.,;:)("]')
                cleaned_urls.append(cleaned_url)
            
            # Merge with unique URLs (using href as key)
            existing_hrefs = {u["href"] for u in result["urls"]}
            for url in cleaned_urls:
                if url not in existing_hrefs:
                    result["urls"].append({"href": url, "text": url})
                    existing_hrefs.add(url)

        return result

    @staticmethod
    def parse_from_dict(row: Dict[str, Any]) -> Dict[str, Any]:
        """Parses an email representation from a dataset row (e.g. Nazario dataset format)."""
        sender = row.get("sender", "")
        receiver = row.get("receiver", "")
        date = row.get("date", "")
        subject = row.get("subject", "")
        body = row.get("body", "")
        urls_raw = row.get("urls", "")
        
        # Extract individual URLs
        urls = []
        if isinstance(urls_raw, str) and urls_raw.strip():
            # Check if it looks like a list represented as a string e.g. "['http://url1', 'http://url2']"
            if urls_raw.startswith("[") and urls_raw.endswith("]"):
                try:
                    import ast
                    parsed_urls = ast.literal_eval(urls_raw)
                    if isinstance(parsed_urls, list):
                        urls = [{"href": u, "text": u} for u in parsed_urls]
                except Exception:
                    pass
            if not urls:
                # Fallback to simple split or regex extraction
                url_pattern = re.compile(r'https?://[^\s<>"\',]+')
                for u in url_pattern.findall(urls_raw):
                    urls.append({"href": u, "text": u})
        elif isinstance(urls_raw, list):
            urls = [{"href": u, "text": u} for u in urls_raw]

        # Structure body
        body_text = ""
        body_html = ""
        if "<html" in body.lower() or "<div" in body.lower() or "<p" in body.lower():
            body_html = body
            # Extract plain text from HTML
            try:
                soup = BeautifulSoup(body, "html.parser")
                body_text = soup.get_text()
                # If HTML parse yields URLs, append them
                existing_hrefs = {u["href"] for u in urls}
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"].strip()
                    text = a_tag.get_text().strip()
                    if href and href not in existing_hrefs:
                        urls.append({"href": href, "text": text})
                        existing_hrefs.add(href)
            except Exception:
                body_text = body
        else:
            body_text = body

        return {
            "sender": sender,
            "receiver": receiver,
            "date": date,
            "subject": subject,
            "reply_to": "",  # Standard datasets might not have it
            "x_mailer": "",
            "body_text": body_text,
            "body_html": body_html,
            "urls": urls,
            "auth_headers": {
                "spf": "NONE",
                "dkim": "NONE",
                "dmarc": "NONE",
                "raw_auth_results": ""
            }
        }
