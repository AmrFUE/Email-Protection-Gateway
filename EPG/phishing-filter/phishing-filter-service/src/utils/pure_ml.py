import math
import re
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple

class PureNaiveBayes:
    def __init__(self):
        self.class_counts = {0: 0, 1: 0}
        self.total_docs = 0
        self.word_counts = {0: {}, 1: {}}
        self.vocab = set()
        self.prior = {0: 0.5, 1: 0.5}

    def _tokenize(self, text: str) -> List[str]:
        # Simple word tokenization
        text = text.lower()
        return re.findall(r'\b[a-z]{3,15}\b', text)

    def fit(self, texts: List[str], labels: List[int]):
        """Train the Naive Bayes classifier using Laplace smoothing."""
        self.total_docs = len(texts)
        if self.total_docs == 0:
            return
            
        self.class_counts = {0: 0, 1: 0}
        self.word_counts = {0: {}, 1: {}}
        self.vocab = set()
        
        for text, label in zip(texts, labels):
            self.class_counts[label] += 1
            tokens = self._tokenize(text)
            for token in tokens:
                self.vocab.add(token)
                self.word_counts[label][token] = self.word_counts[label].get(token, 0) + 1

        # Calculate priors
        for c in [0, 1]:
            self.prior[c] = max((self.class_counts[c] / self.total_docs), 0.001)

    def predict_proba(self, text: str) -> float:
        """
        Calculate probability of class 1 given the text.
        Returns float between 0.0 and 1.0.
        """
        tokens = self._tokenize(text)
        
        # Calculate sum of words in each class for Laplace smoothing denominator
        vocab_len = len(self.vocab)
        total_words = {
            0: sum(self.word_counts[0].values()),
            1: sum(self.word_counts[1].values())
        }
        
        # Log probability scores to prevent underflow
        log_prob = {
            0: math.log(self.prior[0]),
            1: math.log(self.prior[1])
        }
        
        for token in tokens:
            if token in self.vocab:
                for c in [0, 1]:
                    # Word frequency in class + 1 (smoothing) / total words in class + vocab size
                    count = self.word_counts[c].get(token, 0)
                    prob = (count + 1) / (total_words[c] + vocab_len + 1)
                    log_prob[c] += math.log(prob)
                    
        # Convert log scale back to probability safely
        max_log = max(log_prob[0], log_prob[1])
        try:
            exp_0 = math.exp(log_prob[0] - max_log)
            exp_1 = math.exp(log_prob[1] - max_log)
            p1 = exp_1 / (exp_0 + exp_1)
        except Exception:
            p1 = 0.5
            
        return p1

    def save(self, path: Path):
        data = {
            "class_counts": self.class_counts,
            "total_docs": self.total_docs,
            "word_counts": self.word_counts,
            "vocab": list(self.vocab),
            "prior": self.prior
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def load(self, path: Path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.class_counts = {int(k): v for k, v in data["class_counts"].items()}
        self.total_docs = data["total_docs"]
        self.word_counts = {int(k): v for k, v in data["word_counts"].items()}
        self.vocab = set(data["vocab"])
        self.prior = {int(k): v for k, v in data["prior"].items()}


class PureLogisticRegression:
    def __init__(self, lr=0.01, iters=500):
        self.lr = lr
        self.iters = iters
        self.weights = []
        self.bias = 0.0

    def fit(self, X: List[List[float]], y: List[int]):
        """Train standard logistic regression using gradient descent."""
        n_samples = len(X)
        if n_samples == 0:
            return
        n_features = len(X[0])
        
        self.weights = [0.0] * n_features
        self.bias = 0.0
        
        # Min-max scaling variables internally to stabilize gradient descent
        X_array = [list(x) for x in X]
        
        for _ in range(self.iters):
            for i in range(n_samples):
                # Calculate prediction
                linear_model = sum(X_array[i][j] * self.weights[j] for j in range(n_features)) + self.bias
                
                # Sigmoid
                try:
                    if linear_model >= 0:
                        y_predicted = 1.0 / (1.0 + math.exp(-linear_model))
                    else:
                        y_predicted = 1.0 - 1.0 / (1.0 + math.exp(linear_model))
                except OverflowError:
                    y_predicted = 0.0 if linear_model < 0 else 1.0
                
                # Compute error and update weights
                error = y[i] - y_predicted
                for j in range(n_features):
                    self.weights[j] += self.lr * error * X_array[i][j]
                self.bias += self.lr * error

    def predict_proba(self, x: List[float]) -> float:
        """Calculate probability of class 1 given feature vector x."""
        if not self.weights:
            return 0.5
        n_features = len(self.weights)
        linear_model = sum(x[j] * self.weights[j] for j in range(min(len(x), n_features))) + self.bias
        try:
            if linear_model >= 0:
                p1 = 1.0 / (1.0 + math.exp(-linear_model))
            else:
                p1 = 1.0 - 1.0 / (1.0 + math.exp(linear_model))
        except OverflowError:
            p1 = 0.0 if linear_model < 0 else 1.0
        return p1

    def save(self, path: Path):
        data = {
            "weights": self.weights,
            "bias": self.bias,
            "lr": self.lr,
            "iters": self.iters
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def load(self, path: Path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.weights = data["weights"]
        self.bias = data["bias"]
        self.lr = data["lr"]
        self.iters = data["iters"]
