import os
import re
from typing import Dict, Any, List
from src.config import MODELS_DIR, URGENCY_KEYWORDS, CREDENTIAL_KEYWORDS, BEC_KEYWORDS
from src.utils.pure_ml import PureNaiveBayes

class NLPAnalyzer:
    def __init__(self):
        self.phishing_model_path = MODELS_DIR / "pure_nlp_phishing.json"
        self.urgency_model_path = MODELS_DIR / "pure_nlp_urgency.json"
        self.credential_model_path = MODELS_DIR / "pure_nlp_credential.json"
        self.bec_model_path = MODELS_DIR / "pure_nlp_bec.json"
        
        self.phishing_model = None
        self.urgency_model = None
        self.credential_model = None
        self.bec_model = None
        
        self.load_models()

    def load_models(self):
        """Loads serialized pure-Python Naive Bayes models if they exist."""
        try:
            if (self.phishing_model_path.exists() and 
                self.urgency_model_path.exists() and 
                self.credential_model_path.exists() and 
                self.bec_model_path.exists()):
                
                self.phishing_model = PureNaiveBayes()
                self.phishing_model.load(self.phishing_model_path)
                
                self.urgency_model = PureNaiveBayes()
                self.urgency_model.load(self.urgency_model_path)
                
                self.credential_model = PureNaiveBayes()
                self.credential_model.load(self.credential_model_path)
                
                self.bec_model = PureNaiveBayes()
                self.bec_model.load(self.bec_model_path)
                
                # print("[NLPAnalyzer] Pure Python ML models loaded successfully.")
            else:
                pass
                # print("[NLPAnalyzer] Pure Python ML models not found. Running in heuristic fallback mode.")
        except Exception as e:
            print(f"[NLPAnalyzer] Warning loading models: {e}. Running in heuristic fallback.")
            self.phishing_model = None

    def preprocess_text(self, subject: str, body: str) -> str:
        """Combine subject and body and preprocess for feature extraction."""
        text = f"{subject} {body}"
        # Remove extra whitespaces and convert to lowercase
        text = re.sub(r'\s+', ' ', text)
        text = text.lower().strip()
        return text

    def _heuristic_score(self, text: str, keywords: List[str]) -> float:
        """Helper to calculate a heuristic score based on word occurrence density."""
        if not text:
            return 0.0
        words = text.split()
        if not words:
            return 0.0
            
        match_count = 0
        for kw in keywords:
            # Check for exact word boundary matches
            pattern = rf'\b{re.escape(kw)}\b'
            match_count += len(re.findall(pattern, text))
            
        # Density metric with a logarithmic scaler to prevent spikes
        raw_ratio = match_count / len(words) if len(words) > 0 else 0
        # Boost ratio so small numbers of matches are visible, cap at 1.0
        score = min(raw_ratio * 30.0 + (0.3 if match_count > 0 else 0.0), 1.0)
        
        # Additional scaling based on raw match count: if we match 3+ distinct keywords, it's highly suspicious
        unique_matches = sum(1 for kw in keywords if re.search(rf'\b{re.escape(kw)}\b', text))
        if unique_matches >= 3:
            score = max(score, 0.85)
        elif unique_matches == 2:
            score = max(score, 0.60)
        elif unique_matches == 1:
            score = max(score, 0.35)
            
        return float(score)

    def analyze(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Performs NLP semantic analysis.
        Returns:
            - phishing_probability
            - urgency_score
            - credential_theft_score
            - BEC_probability
            - reasons: XAI reasoning items
        """
        subject = email_data.get("subject", "")
        body_text = email_data.get("body_text", "")
        
        preprocessed_text = self.preprocess_text(subject, body_text)
        
        # Initialize output dictionary
        results = {
            "phishing_probability": 0.0,
            "urgency_score": 0.0,
            "credential_theft_score": 0.0,
            "BEC_probability": 0.0,
            "features": {},
            "reasons": [],
            "mode": "Pure-ML"
        }

        # 1. Run Heuristics (as baseline and feature inputs)
        urg_h = self._heuristic_score(preprocessed_text, URGENCY_KEYWORDS)
        cred_h = self._heuristic_score(preprocessed_text, CREDENTIAL_KEYWORDS)
        bec_h = self._heuristic_score(preprocessed_text, BEC_KEYWORDS)
        
        # NLP features for downstream ML aggregator
        results["features"] = {
            "urgency_keyword_score": urg_h,
            "credential_keyword_score": cred_h,
            "bec_keyword_score": bec_h,
            "body_length": len(body_text),
            "subject_length": len(subject)
        }

        # 2. ML Inference (if models are loaded)
        if self.phishing_model:
            try:
                results["phishing_probability"] = float(self.phishing_model.predict_proba(preprocessed_text))
                results["urgency_score"] = float(self.urgency_model.predict_proba(preprocessed_text))
                results["credential_theft_score"] = float(self.credential_model.predict_proba(preprocessed_text))
                results["BEC_probability"] = float(self.bec_model.predict_proba(preprocessed_text))
            except Exception as e:
                # Fallback to heuristics on error
                results["mode"] = f"Heuristic Fallback (ML error: {e})"
                results["phishing_probability"] = max(urg_h, cred_h, bec_h)
                results["urgency_score"] = urg_h
                results["credential_theft_score"] = cred_h
                results["BEC_probability"] = bec_h
        else:
            # Fallback to heuristics
            results["mode"] = "Heuristic Fallback"
            results["phishing_probability"] = min(max(urg_h * 0.8 + cred_h * 0.9 + bec_h * 0.9, 0.05), 1.0)
            if results["phishing_probability"] > 0.1 and "<html" in email_data.get("body_html", ""):
                results["phishing_probability"] = min(results["phishing_probability"] + 0.1, 1.0)
            results["urgency_score"] = urg_h
            results["credential_theft_score"] = cred_h
            results["BEC_probability"] = bec_h

        # Generate XAI Reasons based on scores
        if results["urgency_score"] > 0.5:
            matched_kws = [kw for kw in URGENCY_KEYWORDS if re.search(rf'\b{re.escape(kw)}\b', preprocessed_text)]
            results["reasons"].append(f"Urgency-based coercion identified (score: {results['urgency_score']:.2f}). Matched words: {matched_kws[:3]}")
            
        if results["credential_theft_score"] > 0.5:
            matched_kws = [kw for kw in CREDENTIAL_KEYWORDS if re.search(rf'\b{re.escape(kw)}\b', preprocessed_text)]
            results["reasons"].append(f"Credential harvesting intent detected (score: {results['credential_theft_score']:.2f}). Matched words: {matched_kws[:3]}")
            
        if results["BEC_probability"] > 0.5:
            matched_kws = [kw for kw in BEC_KEYWORDS if re.search(rf'\b{re.escape(kw)}\b', preprocessed_text)]
            results["reasons"].append(f"Business Email Compromise (BEC) language identified (score: {results['BEC_probability']:.2f}). Matched words: {matched_kws[:3]}")

        if results["phishing_probability"] > 0.7:
            results["reasons"].append(f"NLP semantic model classified email body as highly suspicious (phishing probability: {results['phishing_probability']:.2f})")

        return results
