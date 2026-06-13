import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from src.utils.domain_utils import levenshtein_distance, is_homograph_attack, check_typosquatting
from src.engines.header_analyzer import HeaderAnalyzer
from src.engines.url_analyzer import URLAnalyzer

def test_levenshtein_distance():
    assert levenshtein_distance("microsoft", "microsoft") == 0
    assert levenshtein_distance("microsoft", "rnicrosoft") == 2
    assert levenshtein_distance("paypal", "paypa1") == 1
    assert levenshtein_distance("paypal", "apple") == 4

def test_homograph_attack():
    # 'раypal.com' using Cyrillic 'a' (U+0430) and 'p' (U+0440)
    cyrillic_paypal = "раypal.com"
    assert is_homograph_attack(cyrillic_paypal) is True
    # Punycode form of Cyrillic paypal
    punycode_paypal = "xn--ypal-e5d0d.com"
    assert is_homograph_attack(punycode_paypal) is True
    # Normal latin paypal
    assert is_homograph_attack("paypal.com") is False

def test_check_typosquatting():
    brands = ["microsoft.com", "paypal.com"]
    
    # Try lookalike domain
    res1 = check_typosquatting("rnicrosoft.com", brands)
    assert res1["is_spoof"] is True
    assert res1["matched_brand"] == "microsoft.com"
    
    # Try actual domain
    res2 = check_typosquatting("microsoft.com", brands)
    assert res2["is_spoof"] is False
    
    # Try different unrelated domain
    res3 = check_typosquatting("wikipedia.org", brands)
    assert res3["is_spoof"] is False
    
    # Try domain combining suspicious keyword
    res4 = check_typosquatting("login-microsoft.com", brands)
    assert res4["is_spoof"] is True

def test_display_name_spoofing():
    analyzer = HeaderAnalyzer(brand_list=["paypal.com"])
    
    # Display name spoof attack A: embedded mismatching email
    email1 = {
        "sender": '"support@paypal.com" <hacker@evil-domain.com>',
        "subject": "Update account details",
        "auth_headers": {}
    }
    res1 = analyzer.analyze(email1)
    assert res1["features"]["display_name_spoofing"] == 1
    
    # Display name spoof attack B: display name mimics brand name but sent from public address
    email2 = {
        "sender": '"PayPal Support" <some_random_sender@gmail.com>',
        "subject": "Account locked",
        "auth_headers": {}
    }
    res2 = analyzer.analyze(email2)
    assert res2["features"]["display_name_spoofing"] == 1
    assert res2["features"]["public_sender_domain"] == 1

def test_url_analyzer_mismatch():
    analyzer = URLAnalyzer(brand_list=["paypal.com"])
    
    email_data = {
        "urls": [
            {"href": "http://evil-site.com/login", "text": "https://www.paypal.com"}
        ]
    }
    res = analyzer.analyze(email_data)
    assert res["features"]["url_mismatch_detected"] == 1
    assert res["score"] > 40.0
