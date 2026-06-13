import re
import tldextract
import urllib.parse
from typing import Dict, Any, List
from src.config import HIGH_RISK_TLDS, LEGITIMATE_BRANDS
from src.utils.domain_utils import check_typosquatting, is_homograph_attack, get_domain_entropy

class URLAnalyzer:
    def __init__(self, brand_list: List[str] = None):
        self.brand_list = brand_list or LEGITIMATE_BRANDS
        # Common url shorteners list
        self.shorteners = {
            "bit.ly", "tinyurl.com", "goo.gl", "t.co", "rebrand.ly", "is.gd",
            "buff.ly", "ow.ly", "db.tt", "git.io", "linktr.ee", "tiny.cc",
            "shorte.st", "ady.ou", "t2mio.com"
        }

    def analyze(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes all URLs extracted from the email.
        Returns aggregate scoring, feature indicators, and details on each URL.
        """
        urls = email_data.get("urls", [])
        
        features = {
            "num_urls": len(urls),
            "url_mismatch_detected": 0,
            "has_shortener": 0,
            "has_long_url": 0,
            "has_encoded_url": 0,
            "has_redirect_chain_param": 0,
            "has_punycode_url": 0,
            "has_homograph_url": 0,
            "has_lookalike_url": 0,
            "max_url_entropy": 0.0,
            "has_high_risk_tld": 0,
            "has_suspicious_url_token": 0
        }
        
        reasons = []
        url_analyses = []
        max_single_url_score = 0.0
        
        url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
        
        for url_item in urls:
            href = url_item.get("href", "").strip()
            display_text = url_item.get("text", "").strip()
            
            if not href:
                continue
                
            url_score = 0.0
            url_reasons = []
            
            # --- 1. Href vs Display Text Mismatch ---
            # If display text looks like a URL but the href domain is different
            display_is_url = False
            # Check if display text contains a domain or URL-like pattern
            if url_pattern.match(display_text) or any(tld in display_text.lower() for tld in [".com", ".net", ".org", ".co", ".info", ".biz", ".us"]):
                display_is_url = True
                
            if display_is_url:
                # Extract domains
                # Strip protocol to parse safely if missing
                href_to_parse = href if href.startswith("http") else f"http://{href}"
                text_to_parse = display_text if display_text.startswith("http") else f"http://{display_text}"
                
                try:
                    href_ext = tldextract.extract(href_to_parse.lower())
                    text_ext = tldextract.extract(text_to_parse.lower())
                    
                    href_domain = f"{href_ext.domain}.{href_ext.suffix}"
                    text_domain = f"{text_ext.domain}.{text_ext.suffix}"
                    
                    # If domains differ and aren't equivalent (e.g. subdomains of same root)
                    if href_domain != text_domain and href_ext.domain != text_ext.domain:
                        features["url_mismatch_detected"] = 1
                        url_score += 45.0
                        url_reasons.append(f"Link mismatch: Display text claims '{text_domain}' but link leads to '{href_domain}'")
                except Exception:
                    pass

            # --- 2. Obfuscation Techniques ---
            # Extract domain of actual href link
            href_to_parse = href if href.startswith("http") else f"http://{href}"
            try:
                parsed_url = urllib.parse.urlparse(href_to_parse)
                href_domain_raw = parsed_url.netloc.lower()
                # Remove port if exists
                if ":" in href_domain_raw:
                    href_domain_raw = href_domain_raw.split(":")[0]
                href_ext = tldextract.extract(href_to_parse.lower())
                href_domain = f"{href_ext.domain}.{href_ext.suffix}" if href_ext.suffix else href_ext.domain
            except Exception:
                href_domain_raw = href
                href_domain = href
                parsed_url = None

            # A. URL Shorteners
            if href_domain in self.shorteners or any(short in href_domain_raw for short in self.shorteners):
                features["has_shortener"] = 1
                url_score += 25.0
                url_reasons.append("URL shortener service detected (masks real destination)")
                
            # B. Excessively Long URLs
            if len(href) > 75:
                features["has_long_url"] = 1
                url_score += 15.0
                url_reasons.append(f"Excessively long URL (length: {len(href)} characters)")

            # C. Encoded URLs
            # Check for hex encoding or double encoding (e.g. %2520, %3D, etc.)
            encoding_matches = len(re.findall(r'%[0-9a-fA-F]{2}', href))
            if encoding_matches > 3:
                features["has_encoded_url"] = 1
                url_score += 10.0
                url_reasons.append(f"Highly encoded URL path ({encoding_matches} percent-encoded chars)")

            # D. Redirect Chains in Param
            # Check if there are parameters containing http/https in value
            if parsed_url and parsed_url.query:
                query_params = urllib.parse.parse_qs(parsed_url.query)
                for key, val_list in query_params.items():
                    for val in val_list:
                        if val.startswith("http://") or val.startswith("https://") or "www." in val:
                            # Verify if redirect parameter
                            if any(token in key.lower() for token in ["url", "redirect", "next", "link", "to", "goto", "dest", "out"]):
                                features["has_redirect_chain_param"] = 1
                                url_score += 20.0
                                url_reasons.append(f"Potential open-redirect/chain parameter detected: '{key}={val}'")

            # --- 3. Punycode and Homographs ---
            if href_domain.startswith("xn--"):
                features["has_punycode_url"] = 1
                url_score += 40.0
                url_reasons.append(f"Punycode encoded domain: '{href_domain}' (potential homograph spoof)")

            if is_homograph_attack(href_domain):
                features["has_homograph_url"] = 1
                url_score += 45.0
                url_reasons.append(f"Homograph unicode characters detected in domain: '{href_domain}'")

            # --- 4. Lookalike check for link domain ---
            typo_res = check_typosquatting(href_domain, self.brand_list)
            if typo_res["is_spoof"]:
                features["has_lookalike_url"] = 1
                url_score += 45.0
                url_reasons.append(f"Link domain mimics legitimate brand '{typo_res['matched_brand']}' (distance: {typo_res['distance']})")

            # --- 5. TLD Risk ---
            tld = href_ext.suffix.lower() if href_ext.suffix else ""
            if tld in HIGH_RISK_TLDS:
                features["has_high_risk_tld"] = 1
                risk_weight = HIGH_RISK_TLDS[tld]
                url_score += risk_weight * 25.0
                url_reasons.append(f"High-risk TLD detected: '.{tld}' (threat score: {risk_weight})")

            # --- 6. Suspicious Path Tokens ---
            suspicious_path_tokens = ["login", "secure", "verify", "update", "signin", "password", "account", "banking", "credentials", "billing", "signin", "reset"]
            found_tokens = []
            url_path_query = (parsed_url.path + parsed_url.query).lower() if parsed_url else href.lower()
            for token in suspicious_path_tokens:
                if token in url_path_query:
                    found_tokens.append(token)
                    
            if found_tokens:
                features["has_suspicious_url_token"] = 1
                url_score += min(len(found_tokens) * 8.0, 25.0)
                url_reasons.append(f"Suspicious intent tokens in URL path/params: {found_tokens}")

            # --- 7. Domain Entropy ---
            entropy = get_domain_entropy(href_domain)
            if entropy > features["max_url_entropy"]:
                features["max_url_entropy"] = entropy
                
            if entropy > 4.2: # High entropy indicator for DGA
                url_score += 15.0
                url_reasons.append(f"High domain character entropy ({entropy:.2f}), suggestive of DGA/random generation")

            # Cap single URL score at 100
            url_score = min(url_score, 100.0)
            
            if url_score > max_single_url_score:
                max_single_url_score = url_score
                
            url_analyses.append({
                "url": href,
                "text": display_text,
                "domain": href_domain,
                "tld": tld,
                "entropy": entropy,
                "score": url_score,
                "reasons": url_reasons
            })
            
            # Add unique explanations to top level reasons
            for r in url_reasons:
                if r not in reasons:
                    reasons.append(r)

        # Aggregate URL score: Max single URL score + minor adjustments for multiple URLs
        agg_score = max_single_url_score
        if len(url_analyses) > 1 and agg_score < 100:
            # Boost score slightly if multiple suspicious URLs are found
            suspicious_count = sum(1 for item in url_analyses if item["score"] > 20)
            if suspicious_count > 1:
                agg_score = min(agg_score + min(suspicious_count * 2.0, 10.0), 100.0)

        return {
            "score": agg_score,
            "features": features,
            "reasons": reasons,
            "urls_checked": url_analyses
        }
