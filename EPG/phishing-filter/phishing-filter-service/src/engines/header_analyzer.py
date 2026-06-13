import email.utils
import re
import tldextract
from typing import Dict, Any, List
from src.config import SUSPICIOUS_MAILERS
from src.utils.domain_utils import check_typosquatting, is_homograph_attack

class HeaderAnalyzer:
    def __init__(self, brand_list: List[str] = None):
        self.brand_list = brand_list

    def analyze(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes email headers for identity spoofing and routing anomalies.
        Returns a dictionary of feature flags, heuristic risk scores, and reasons.
        """
        sender_raw = email_data.get("sender", "")
        reply_to_raw = email_data.get("reply_to", "")
        x_mailer = email_data.get("x_mailer", "") or ""
        auth_headers = email_data.get("auth_headers", {})
        
        # 1. Parse display name and email address
        display_name, sender_address = email.utils.parseaddr(sender_raw)
        
        # Extract domains
        sender_domain = ""
        if sender_address and "@" in sender_address:
            sender_domain = sender_address.split("@")[-1].lower()
            
        reply_to_domain = ""
        if reply_to_raw:
            _, reply_to_address = email.utils.parseaddr(reply_to_raw)
            if reply_to_address and "@" in reply_to_address:
                reply_to_domain = reply_to_address.split("@")[-1].lower()

        # Initialize results
        features = {
            "display_name_spoofing": 0,
            "reply_to_mismatch": 0,
            "spf_fail": 0,
            "dkim_fail": 0,
            "dmarc_fail": 0,
            "suspicious_mailer": 0,
            "lookalike_sender_domain": 0,
            "homograph_sender_domain": 0,
            "public_sender_domain": 0  # e.g., gmail, yahoo sending corporate claims
        }
        
        reasons = []
        heuristic_score = 0.0
        
        # --- Display Name Spoofing Check ---
        # Attack A: Email embedded in Display Name, e.g. "PayPal <hacker@evil.com>" -> display name has email.
        email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
        emails_in_display = re.findall(email_pattern, display_name)
        
        if emails_in_display:
            embedded_email = emails_in_display[0].lower()
            if sender_address and embedded_email != sender_address.lower():
                features["display_name_spoofing"] = 1
                heuristic_score += 40.0
                reasons.append(f"Display name contains email spoofing: '{embedded_email}' claims to be sender, but actual mail envelope is '{sender_address}'")
        else:
            # Attack B: Display name says "PayPal Support" but sender domain is public (e.g. gmail.com) or suspicious
            # Check if display name matches any of our target brands
            display_name_clean = display_name.lower().replace(" ", "")
            if self.brand_list:
                for brand in self.brand_list:
                    brand_extracted = tldextract.extract(brand)
                    brand_name = brand_extracted.domain.lower()
                    
                    if brand_name in display_name_clean:
                        # Display name claims to be a brand, check if sender domain matches
                        if sender_domain and brand_name not in sender_domain:
                            # Also check if it's a public domain
                            is_public = any(pub in sender_domain for pub in ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"])
                            features["display_name_spoofing"] = 1
                            if is_public:
                                features["public_sender_domain"] = 1
                                heuristic_score += 35.0
                                reasons.append(f"Display name matches brand '{brand_name}' but sent from public address '{sender_address}'")
                            else:
                                heuristic_score += 20.0
                                reasons.append(f"Display name matches brand '{brand_name}' but sent from non-matching domain '{sender_domain}'")
                            break

        # --- Reply-To Mismatch Check ---
        if reply_to_domain and sender_domain:
            if reply_to_domain != sender_domain:
                # Exclude common marketing tools that have valid mismatch if SPF is valid (but here, we flag it as an indicator)
                features["reply_to_mismatch"] = 1
                heuristic_score += 15.0
                reasons.append(f"Reply-To domain mismatch: '{reply_to_domain}' does not match From domain '{sender_domain}'")

        # --- SPF/DKIM/DMARC Analysis ---
        if auth_headers.get("spf") == "FAIL":
            features["spf_fail"] = 1
            heuristic_score += 20.0
            reasons.append("SPF alignment check failed (Sender Policy Framework)")
            
        if auth_headers.get("dkim") == "FAIL":
            features["dkim_fail"] = 1
            heuristic_score += 15.0
            reasons.append("DKIM signature validation failed (DomainKeys Identified Mail)")
            
        if auth_headers.get("dmarc") == "FAIL":
            features["dmarc_fail"] = 1
            heuristic_score += 30.0
            reasons.append("DMARC alignment check failed")

        # --- Suspicious X-Mailer Check ---
        if x_mailer:
            x_mailer_lower = x_mailer.lower()
            for susp in SUSPICIOUS_MAILERS:
                if susp in x_mailer_lower:
                    features["suspicious_mailer"] = 1
                    heuristic_score += 25.0
                    reasons.append(f"Suspicious User-Agent/X-Mailer detected: '{x_mailer}' (suggests automation or scripting tools)")
                    break

        # --- Domain Intelligence Check ---
        if sender_domain:
            # 1. Homograph Attack (Cyrillic lookalikes)
            if is_homograph_attack(sender_domain):
                features["homograph_sender_domain"] = 1
                heuristic_score += 50.0
                reasons.append(f"Homograph domain spoofing detected in sender domain: '{sender_domain}' contains mixed-scripts or Punycode")

            # 2. Typosquatting / Lookalike domains
            typo_res = check_typosquatting(sender_domain, self.brand_list)
            if typo_res["is_spoof"]:
                features["lookalike_sender_domain"] = 1
                heuristic_score += 45.0
                reasons.append(f"Lookalike/Typosquatting sender domain detected: '{sender_domain}' mimics legitimate brand '{typo_res['matched_brand']}' (edit distance: {typo_res['distance']})")

        # Cap the heuristic header score at 100
        score = min(heuristic_score, 100.0)

        return {
            "score": score,
            "features": features,
            "reasons": reasons,
            "details": {
                "sender_address": sender_address,
                "display_name": display_name,
                "sender_domain": sender_domain,
                "reply_to_domain": reply_to_domain,
                "x_mailer": x_mailer,
                "auth_headers": auth_headers
            }
        }
