"""
Hybrid Risk Aggregator — Enterprise-Grade Binary Phishing Detection

Decision Hierarchy:
1. Hard Safety Rules (E.g., No technical indicators → CLEAN)
2. Threat Override Layer (Highest Priority)
   - Bypasses trust reductions if active threats are present.
   - Handles lookalike domains, homographs, punycode, fake brand domains,
     and explicit rules like (url_score >= 40 and credential_theft_score >= 0.70).
3. URL/Infrastructure Analysis
4. Header Analysis
5. NLP Semantic Analysis
6. Trust Reduction Layer (Lowest Priority - Executes Last)
7. Confidence Calibration
"""

from typing import Dict, Any, List
from src.config import MODELS_DIR, WEIGHTS
from src.utils.pure_ml import PureLogisticRegression

# Trusted domain suffixes — emails from these are protected from false positives ONLY if no active threats exist
TRUSTED_DOMAIN_SUFFIXES = [
    ".edu", ".edu.eg", ".edu.sa", ".edu.uk", ".ac.uk", ".edu.au",
    ".gov", ".gov.eg", ".gov.uk", ".gov.sa",
    ".mil",
]

# Official domains of heavily impersonated brands to detect fake lookalike brand domains
OFFICIAL_BRAND_DOMAINS = {
    "microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com",
    "paypal.com", "paypal-objects.com",
    "google.com", "gmail.com", "accounts.google.com",
    "apple.com", "icloud.com",
    "amazon.com", "aws.amazon.com",
    "facebook.com", "fb.com"
}


class HybridRiskAggregator:
    def __init__(self):
        self.model_path = MODELS_DIR / "pure_aggregator.json"
        self.model = None
        self.load_model()

    def load_model(self):
        """Loads serialized pure-Python logistic regression aggregator model."""
        try:
            if self.model_path.exists():
                self.model = PureLogisticRegression()
                self.model.load(self.model_path)
        except Exception as e:
            print(f"[HybridRiskAggregator] Warning loading model: {e}. Running in heuristic mode.")
            self.model = None

    def _compile_feature_vector(self, header_res: Dict[str, Any], url_res: Dict[str, Any], nlp_res: Dict[str, Any]) -> List[float]:
        """Flattens features from all three engines into a single feature array for the ML model."""
        hf = header_res.get("features", {})
        uf = url_res.get("features", {})
        nf = nlp_res.get("features", {})

        vector = [
            # Header features (9)
            float(hf.get("display_name_spoofing", 0)),
            float(hf.get("reply_to_mismatch", 0)),
            float(hf.get("spf_fail", 0)),
            float(hf.get("dkim_fail", 0)),
            float(hf.get("dmarc_fail", 0)),
            float(hf.get("suspicious_mailer", 0)),
            float(hf.get("lookalike_sender_domain", 0)),
            float(hf.get("homograph_sender_domain", 0)),
            float(hf.get("public_sender_domain", 0)),

            # URL features (12) — normalized to [0.0, 1.0]
            float(uf.get("url_mismatch_detected", 0)),
            float(uf.get("has_shortener", 0)),
            float(uf.get("has_long_url", 0)),
            float(uf.get("has_encoded_url", 0)),
            float(uf.get("has_redirect_chain_param", 0)),
            float(uf.get("has_punycode_url", 0)),
            float(uf.get("has_homograph_url", 0)),
            float(uf.get("has_lookalike_url", 0)),
            min(float(uf.get("max_url_entropy", 0.0)) / 6.0, 1.0),
            float(uf.get("has_high_risk_tld", 0)),
            float(uf.get("has_suspicious_url_token", 0)),
            min(float(uf.get("num_urls", 0)) / 10.0, 1.0),

            # NLP features (7)
            float(nlp_res.get("phishing_probability", 0.0)),
            float(nlp_res.get("urgency_score", 0.0)),
            float(nlp_res.get("credential_theft_score", 0.0)),
            float(nlp_res.get("BEC_probability", 0.0)),
            float(nf.get("urgency_keyword_score", 0.0)),
            float(nf.get("credential_keyword_score", 0.0)),
            float(nf.get("bec_keyword_score", 0.0)),
        ]

        return vector

    # ------------------------------------------------------------------
    # Technical helper counters and checkers
    # ------------------------------------------------------------------

    def _count_header_indicators(self, header_res: Dict[str, Any]) -> int:
        """Count how many distinct malicious header indicators fired."""
        hf = header_res.get("features", {})
        count = 0
        for key in [
            "display_name_spoofing", "reply_to_mismatch",
            "spf_fail", "dkim_fail", "dmarc_fail",
            "suspicious_mailer", "lookalike_sender_domain",
            "homograph_sender_domain"
        ]:
            if hf.get(key, 0) == 1:
                count += 1
        return count

    def _count_url_indicators(self, url_res: Dict[str, Any]) -> int:
        """Count how many distinct malicious URL indicators fired."""
        uf = url_res.get("features", {})
        count = 0
        for key in [
            "url_mismatch_detected", "has_shortener", "has_encoded_url",
            "has_redirect_chain_param", "has_punycode_url",
            "has_homograph_url", "has_lookalike_url",
            "has_high_risk_tld", "has_suspicious_url_token"
        ]:
            if uf.get(key, 0) == 1:
                count += 1
        return count

    def _is_trusted_domain(self, header_res: Dict[str, Any]) -> bool:
        """Check if the sender domain is from a trusted institutional suffix."""
        details = header_res.get("details", {})
        sender_domain = details.get("sender_domain", "").lower()
        for suffix in TRUSTED_DOMAIN_SUFFIXES:
            if sender_domain.endswith(suffix):
                return True
        return False

    def _has_clean_auth(self, header_res: Dict[str, Any]) -> bool:
        """Check if SPF, DKIM, and DMARC all pass."""
        hf = header_res.get("features", {})
        return (
            hf.get("spf_fail", 0) == 0 and
            hf.get("dkim_fail", 0) == 0 and
            hf.get("dmarc_fail", 0) == 0
        )

    # ------------------------------------------------------------------
    # Main aggregation
    # ------------------------------------------------------------------

    def aggregate(self, header_res: Dict[str, Any], url_res: Dict[str, Any], nlp_res: Dict[str, Any]) -> Dict[str, Any]:
        """
        Produces a binary verdict: CLEAN or PHISHING.
        """
        header_score = header_res.get("score", 0.0)
        url_score = url_res.get("score", 0.0)
        nlp_prob = nlp_res.get("phishing_probability", 0.0)
        nlp_score = nlp_prob * 100.0

        # Compile XAI reasons (deduplicated)
        all_reasons = []
        all_reasons.extend(header_res.get("reasons", []))
        all_reasons.extend(url_res.get("reasons", []))
        all_reasons.extend(nlp_res.get("reasons", []))
        seen = set()
        reasons = []
        for r in all_reasons:
            if r not in seen:
                reasons.append(r)
                seen.add(r)

        # Count technical indicators
        header_indicator_count = self._count_header_indicators(header_res)
        url_indicator_count = self._count_url_indicators(url_res)
        total_technical_indicators = header_indicator_count + url_indicator_count

        # =====================================================================
        # 1. HARD SAFETY RULE: No technical indicators → CLEAN
        # NLP alone CANNOT produce a PHISHING verdict.
        # =====================================================================
        if header_score == 0 and url_score == 0:
            return self._build_result(
                verdict="CLEAN",
                risk_score=min(nlp_score * 0.15, 14.9),  # capped below threshold
                confidence=self._calibrate_confidence(0, 0, nlp_prob, False),
                reasons=reasons,
                header_score=header_score,
                url_score=url_score,
                nlp_score=nlp_score,
                mode="Hard Safety Rule (no technical indicators)"
            )

        # =====================================================================
        # 2. THREAT OVERRIDE LAYER (Highest Priority)
        # Identify active threats that bypass trust reduction logic entirely.
        # =====================================================================
        hf = header_res.get("features", {})
        uf = url_res.get("features", {})
        cred_theft_score = nlp_res.get("credential_theft_score", 0.0)

        # Check for fake brand domains (impersonating Microsoft, PayPal, Google, etc.)
        fake_brand_detected = False
        details = header_res.get("details", {})
        sender_domain = details.get("sender_domain", "").lower()
        for brand in ["microsoft", "paypal", "google"]:
            if brand in sender_domain and sender_domain not in OFFICIAL_BRAND_DOMAINS:
                fake_brand_detected = True
                break

        if not fake_brand_detected:
            urls_checked = url_res.get("urls_checked", [])
            for u in urls_checked:
                u_domain = u.get("domain", "").lower()
                for brand in ["microsoft", "paypal", "google"]:
                    if brand in u_domain and u_domain not in OFFICIAL_BRAND_DOMAINS:
                        fake_brand_detected = True
                        break
                if fake_brand_detected:
                    break

        # Check lookalike domain/URL conditions
        lookalike_url_detected = (
            uf.get("has_lookalike_url", 0) == 1 or
            uf.get("has_homograph_url", 0) == 1 or
            uf.get("has_punycode_url", 0) == 1
        )

        lookalike_sender_detected = (
            hf.get("lookalike_sender_domain", 0) == 1 or
            hf.get("homograph_sender_domain", 0) == 1
        )

        # Explicit Phishing Rule: url_score >= 40 and credential_theft_score >= 0.70
        explicit_rule_triggered = (url_score >= 40 and cred_theft_score >= 0.70)

        # Determine if any active threat is present
        active_threat_detected = (
            lookalike_url_detected or
            lookalike_sender_detected or
            uf.get("url_mismatch_detected", 0) == 1 or
            uf.get("has_high_risk_tld", 0) == 1 or
            uf.get("has_suspicious_url_token", 0) == 1 or
            hf.get("reply_to_mismatch", 0) == 1 or
            fake_brand_detected or
            explicit_rule_triggered
        )

        # =====================================================================
        # 3. WEIGHTED HYBRID SCORING
        # (header_score * 0.35) + (url_score * 0.45) + (nlp_score * 0.20)
        # =====================================================================
        w_header = WEIGHTS.get("header_score", 0.35)
        w_url = WEIGHTS.get("url_score", 0.45)
        w_nlp = WEIGHTS.get("nlp_score", 0.20)

        # Evaluate base model or use weighted score
        if self.model:
            try:
                vector = self._compile_feature_vector(header_res, url_res, nlp_res)
                prob = float(self.model.predict_proba(vector))
                base_score = prob * 100.0
            except Exception:
                base_score = (header_score * w_header) + (url_score * w_url) + (nlp_score * w_nlp)
        else:
            base_score = (header_score * w_header) + (url_score * w_url) + (nlp_score * w_nlp)

        risk_score = base_score

        # Apply threat override boosts (Bypasses trust reductions)
        if active_threat_detected:
            # Lookalike domain override (Minimum score 75)
            if lookalike_url_detected or lookalike_sender_detected:
                risk_score = max(risk_score, 75.0)

            # Explicit rule: url_score >= 40 and credential_theft_score >= 0.70 (Minimum score 80)
            if explicit_rule_triggered:
                risk_score = max(risk_score, 80.0)

            # General active threat boost (Minimum score 70 to ensure PHISHING)
            risk_score = max(risk_score, 70.0)

        # =====================================================================
        # 4. TRUST REDUCTION LAYER (Lowest Priority - Executes Last)
        # Only apply when NO active threats are present.
        # =====================================================================
        else:
            trusted_domain = self._is_trusted_domain(header_res)
            clean_auth = self._has_clean_auth(header_res)

            if trusted_domain and clean_auth:
                # Institutional trust reduction (highly protective)
                risk_score = (header_score * 0.10 + url_score * 0.05 + nlp_score * 0.05)
                risk_score = min(risk_score, 14.9)
            elif clean_auth:
                # Moderate reduction for standard authenticated low-risk emails
                risk_score *= 0.4

        # =====================================================================
        # 5. FINAL VERDICT AND CONFIDENCE CALIBRATION
        # =====================================================================
        if risk_score >= 50.0:
            verdict = "PHISHING"
        else:
            verdict = "CLEAN"

        confidence = self._calibrate_confidence(
            header_indicator_count, url_indicator_count, nlp_prob, active_threat_detected
        )

        return self._build_result(
            verdict=verdict,
            risk_score=float(round(risk_score, 1)),
            confidence=confidence,
            reasons=reasons,
            header_score=header_score,
            url_score=url_score,
            nlp_score=nlp_score,
            mode="Pure-ML Aggregator" if self.model else "Weighted Heuristics"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _calibrate_confidence(self, header_indicators: int, url_indicators: int, nlp_prob: float, active_threat: bool) -> float:
        """
        Confidence calibration:
        - Base confidence starts at 0.50.
        - Active threat increases confidence.
        - Never returns >= 0.95 unless multiple engines agree and technical threats exist.
        """
        conf = 0.50

        if active_threat:
            conf += 0.20

        total_tech = header_indicators + url_indicators
        if total_tech >= 3:
            conf += 0.15
        elif total_tech >= 1:
            conf += 0.05

        if nlp_prob >= 0.8:
            conf += 0.10

        # Multi-engine agreement
        if header_indicators >= 1 and url_indicators >= 1 and nlp_prob >= 0.8:
            conf += 0.05

        # Avoid high confidence (>= 0.95) unless multiple engines agree and technical indicators exist
        if conf >= 0.95:
            multiple_engines = (
                (header_indicators >= 1 and url_indicators >= 1) or
                (header_indicators >= 1 and nlp_prob >= 0.7) or
                (url_indicators >= 1 and nlp_prob >= 0.7)
            )
            technical_exists = (header_indicators >= 1 or url_indicators >= 1)
            if not (multiple_engines and technical_exists):
                conf = 0.85

        return float(round(min(conf, 0.98), 2))

    def _build_result(self, verdict: str, risk_score: float, confidence: float,
                      reasons: list, header_score: float, url_score: float,
                      nlp_score: float, mode: str) -> Dict[str, Any]:
        return {
            "verdict": verdict,
            "risk_score": risk_score,
            "confidence": confidence,
            "reasons": reasons,
            "metrics": {
                "header_score": header_score,
                "url_score": url_score,
                "nlp_score": nlp_score
            },
            "mode": mode
        }
