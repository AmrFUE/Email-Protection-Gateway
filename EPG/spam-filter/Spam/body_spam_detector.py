import re
import email
import joblib
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import word_tokenize

nltk.download("punkt", quiet=True)
nltk.download("punkt_tab", quiet=True)
nltk.download("stopwords", quiet=True)
nltk.download("wordnet", quiet=True)

stop_words = set(stopwords.words("english"))
lemmatizer = WordNetLemmatizer()


# ──────────────────────────────────────────────────────────────────────
#  Text Preprocessing
# ──────────────────────────────────────────────────────────────────────

def preprocess_body(text):
    """
    Clean and normalize email body text for NLP processing.

    Steps:
      1. Lowercase
      2. Remove email addresses
      3. Remove URLs
      4. Remove HTML tags
      5. Remove numbers
      6. Keep only letters and spaces
      7. Tokenize
      8. Remove stopwords
      9. Lemmatize
    """
    if not text or not isinstance(text, str):
        return ""

    text = text.lower()

    # Remove email addresses
    text = re.sub(r'\S+@\S+', '', text)

    # Remove URLs
    text = re.sub(r'http\S+|www\S+', '', text)

    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', text)

    # Remove numbers
    text = re.sub(r'\d+', '', text)

    # Keep only letters and spaces
    text = re.sub(r'[^a-zA-Z\s]', '', text)

    # Collapse multiple spaces
    text = re.sub(r'\s+', ' ', text).strip()

    tokens = word_tokenize(text)
    tokens = [w for w in tokens if w not in stop_words]
    tokens = [lemmatizer.lemmatize(w) for w in tokens]

    return " ".join(tokens)


# ──────────────────────────────────────────────────────────────────────
#  Email Body Extraction
# ──────────────────────────────────────────────────────────────────────

def extract_email_body(msg):
    """
    Extract plain-text body from a parsed email.message.Message object.

    Handles:
      - Simple single-part emails (text/plain)
      - Multipart emails (walks parts, prefers text/plain)
      - Falls back to text/html with tag stripping if no plain text found
    """
    if msg.is_multipart():
        plain_parts = []
        html_parts = []

        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            # Skip attachments
            if "attachment" in disposition:
                continue

            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue

                # Try UTF-8 first, then latin-1 as fallback
                charset = part.get_content_charset() or "utf-8"
                try:
                    text = payload.decode(charset)
                except (UnicodeDecodeError, LookupError):
                    text = payload.decode("latin-1", errors="replace")

                if content_type == "text/plain":
                    plain_parts.append(text)
                elif content_type == "text/html":
                    html_parts.append(text)

            except Exception:
                continue

        # Prefer plain text over HTML
        if plain_parts:
            return "\n".join(plain_parts)
        elif html_parts:
            # Strip HTML tags as fallback
            html_text = "\n".join(html_parts)
            return re.sub(r'<[^>]+>', ' ', html_text)

        return ""

    else:
        # Single-part email
        try:
            payload = msg.get_payload(decode=True)
            if payload is None:
                return msg.get_payload() or ""

            charset = msg.get_content_charset() or "utf-8"
            try:
                return payload.decode(charset)
            except (UnicodeDecodeError, LookupError):
                return payload.decode("latin-1", errors="replace")

        except Exception:
            return str(msg.get_payload()) if msg.get_payload() else ""


# ──────────────────────────────────────────────────────────────────────
#  Model Loading & Prediction
# ──────────────────────────────────────────────────────────────────────

def load_body_model(path="body_spam_model.pkl"):
    """Load the saved TF-IDF + classifier pipeline from disk."""
    return joblib.load(path)


def predict_body_spam(text, model):
    """
    Predict spam probability for email body text.

    Args:
        text:  Raw email body text (will be preprocessed internally).
        model: Loaded sklearn Pipeline (TF-IDF + classifier).

    Returns:
        (ham_probability, spam_probability) tuple.
    """
    clean_text = preprocess_body(text)

    if not clean_text.strip():
        # Empty body → can't determine, return neutral
        return 0.5, 0.5

    probabilities = model.predict_proba([clean_text])[0]

    # probabilities[0] = ham, probabilities[1] = spam
    return probabilities[0], probabilities[1]
