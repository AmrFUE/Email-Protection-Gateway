import re
import unicodedata
import tldextract
from src.config import LEGITIMATE_BRANDS

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein edit distance between two strings."""
    s1, s2 = s1.lower(), s2.lower()
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
        
    return previous_row[-1]

def is_homograph_attack(domain: str) -> bool:
    """
    Detect Homograph attacks (IDN spoofing) in domains.
    Flags domains that use Punycode (xn--) or mix Unicode scripts (e.g. Cyrillic and Latin)
    that look similar to ASCII strings.
    """
    domain = domain.lower()
    
    # 1. Punycode check
    if domain.startswith("xn--"):
        return True
        
    # 2. Check for mixed scripts or non-ASCII characters
    scripts = set()
    has_non_ascii = False
    
    # Extract only the main domain label (excluding TLD)
    extracted = tldextract.extract(domain)
    domain_label = extracted.domain
    
    for char in domain_label:
        if ord(char) > 127:
            has_non_ascii = True
        try:
            name = unicodedata.name(char)
            # Find script type (e.g., LATIN, CYRILLIC, GREEK)
            script = name.split()[0]
            scripts.add(script)
        except ValueError:
            pass
            
    # If it has non-ascii and mixes scripts, or is Cyrillic/Greek mimicking Latin
    if has_non_ascii:
        # A domain label mixing LATIN and other scripts is highly suspicious
        if len(scripts) > 1 and "LATIN" in scripts:
            return True
        # If it's pure CYRILLIC but is in a context that mimics a Latin brand, or just has CYRILLIC characters
        if "CYRILLIC" in scripts or "GREEK" in scripts:
            return True
            
    return False

def check_typosquatting(domain: str, brand_list=LEGITIMATE_BRANDS) -> dict:
    """
    Checks if a domain is a lookalike/typosquatting attempt of a legitimate brand.
    Returns a dict with 'is_spoof', 'matched_brand', and 'distance'.
    """
    extracted = tldextract.extract(domain.lower())
    domain_name = f"{extracted.domain}.{extracted.suffix}"
    domain_label = extracted.domain
    
    if not domain_label:
        return {"is_spoof": False, "matched_brand": None, "distance": 0}
        
    for brand in brand_list:
        brand_extracted = tldextract.extract(brand.lower())
        brand_label = brand_extracted.domain
        
        # If exactly the brand domain, it's not typosquatting (it's the actual brand)
        if domain_name == brand:
            return {"is_spoof": False, "matched_brand": brand, "distance": 0}
            
        # Check Levenshtein distance on the domain labels
        distance = levenshtein_distance(domain_label, brand_label)
        
        # Typo thresholds: 1 or 2 edits.
        # Also protect against very short domains where edit distance 1 or 2 is a large percentage.
        if 1 <= distance <= 2 and len(domain_label) >= 4:
            return {
                "is_spoof": True,
                "matched_brand": brand,
                "distance": distance
            }
            
        # Check if the brand label is a substring of the domain label with extra suspicious text
        # e.g., 'login-microsoft.com' or 'paypal-security.com'
        if len(brand_label) >= 5:
            if brand_label in domain_label and domain_label != brand_label:
                # Check for hyphens or concats
                if any(delim in domain_label for delim in ["-", "login", "secure", "verify", "update", "signin"]):
                    return {
                        "is_spoof": True,
                        "matched_brand": brand,
                        "distance": len(domain_label) - len(brand_label)
                    }
                    
    return {"is_spoof": False, "matched_brand": None, "distance": 0}

def get_domain_entropy(domain: str) -> float:
    """Calculate the Shannon entropy of a domain label to detect randomly generated domains (DGA)."""
    extracted = tldextract.extract(domain.lower())
    label = extracted.domain
    if not label:
        return 0.0
        
    import math
    from collections import Counter
    
    len_label = len(label)
    counts = Counter(label)
    entropy = 0.0
    for count in counts.values():
        p = count / len_label
        entropy -= p * math.log2(p)
        
    return entropy
