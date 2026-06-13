"""
redirect_graph.py — Step 6: Redirect chain analysis.

Follows HTTP redirects for a URL and records how many hops occur
before arriving at the final destination.
"""

import requests
from urllib.parse import urlparse

from .config import REQUEST_TIMEOUT
from .logger import get_logger

log = get_logger("redirect_graph")

# Some servers reject requests without a browser-looking user agent
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    )
}


def analyze_redirects(url: str) -> dict:
    """
    Follow the redirect chain of a URL and extract behavioural features.

    Features returned:
        phish_redirect_count            — number of intermediate redirects (0 = no redirects)
        final_url                       — the ultimate destination URL after all redirects
        phish_redirect_domains          — count of unique domains involved in the chain
        phish_cross_domain_redirects    — number of times the domain changed between hops
        phish_open_redirect_abuse       — boolean, True if a hop's query string contains the next hop's URL/domain
        phish_redirect_time             — total elapsed parsing time across all hops in seconds
        phish_redirect_loop             — boolean, True if requests.TooManyRedirects was hit
        visual_graph                    — text-based representation of the redirect chain

    Args:
        url: URL to probe.

    Returns:
        Dict with redirect features.
    """
    defaults = {
        "phish_redirect_count": 0,
        "final_url": url,
        "phish_redirect_domains": 1,
        "phish_cross_domain_redirects": 0,
        "phish_open_redirect_abuse": False,
        "phish_redirect_time": 0.0,
        "phish_redirect_loop": False,
        "visual_graph": f"{url}\n"
    }

    try:
        response = requests.get(
            url,
            allow_redirects=True,
            timeout=REQUEST_TIMEOUT,
            headers=_HEADERS,
            stream=True,       # Don't download body — we only need headers
        )

        redirect_count = len(response.history)
        final = response.url

        defaults["phish_redirect_count"] = redirect_count
        defaults["final_url"] = final

        if response.history:
            chain = []
            total_time = 0.0
            
            # response.history contains the list of redirected responses
            for r in response.history:
                chain.append(r.url)
                total_time += r.elapsed.total_seconds()
                
            chain.append(final)
            total_time += response.elapsed.total_seconds()
            
            defaults["phish_redirect_time"] = round(total_time, 3)
            
            domains_seen = set()
            cross_domain_hops = 0
            is_open_redirect = False
            
            # Build Visual Graph and compute domain features
            visual_graph_lines = []
            
            for i, current_url in enumerate(chain):
                parsed_current = urlparse(current_url)
                current_domain = parsed_current.netloc
                domains_seen.add(current_domain)
                
                # Visual Graph logic
                if i == 0:
                    visual_graph_lines.append(current_url)
                else:
                    indent = "    " * (i - 1)
                    visual_graph_lines.append(f"{indent}└── {current_url}")
                
                # Check relation to next hop
                if i < len(chain) - 1:
                    next_url = chain[i+1]
                    parsed_next = urlparse(next_url)
                    next_domain = parsed_next.netloc
                    
                    if current_domain != next_domain:
                        cross_domain_hops += 1
                        
                    # Open redirect abuse check: does current_url's query contain next_url or next_domain?
                    query_string = parsed_current.query
                    if next_domain in query_string or next_url in query_string:
                        is_open_redirect = True

            defaults["phish_redirect_domains"] = len(domains_seen)
            defaults["phish_cross_domain_redirects"] = cross_domain_hops
            defaults["phish_open_redirect_abuse"] = is_open_redirect
            defaults["visual_graph"] = "\n".join(visual_graph_lines)

        log.info(
            "Redirect chain for '%s': %d hop(s) → '%s'",
            url, redirect_count, final,
        )
        return defaults

    except requests.TooManyRedirects:
        log.warning("Too many redirects for '%s'.", url)
        defaults["phish_redirect_count"] = 20   # sentinel: runaway redirect
        defaults["phish_redirect_loop"] = True
        return defaults

    except Exception as exc:
        log.warning("analyze_redirects failed for '%s': %s", url, exc)
        return defaults
