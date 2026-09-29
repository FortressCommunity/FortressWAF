import os
import pickle
import logging
from typing import Optional, Tuple, Dict, List

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.pipeline import Pipeline

logger = logging.getLogger(__name__)

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "persisted")
os.makedirs(MODEL_DIR, exist_ok=True)

CLASSIFIER_MODEL_PATH = os.path.join(MODEL_DIR, "classifier_model.pkl")
CLASSIFIER_VECTORIZER_PATH = os.path.join(MODEL_DIR, "classifier_vectorizer.pkl")

ATTACK_CLASSES = [
    "sql-injection", "xss", "rce", "path-traversal", "ssrf", "lfi",
    "command-injection", "ssti", "ldap-injection", "xxe", "deserialization",
    "csrf", "open-redirect", "webshell", "crypto-failure", "no-attack",
]

ATTACK_CLASS_INDEX = {c: i for i, c in enumerate(ATTACK_CLASSES)}

SQLI_PATTERNS = [
    r"'(\s*or\s*|\s*and\s*|\s*union\s*|\s*--|\s*#)", r"(\bselect\b.*\bfrom\b)",
    r"(\binsert\b.*\binto\b)", r"(\bupdate\b.*\bset\b)", r"(\bdelete\b.*\bfrom\b)",
    r"(\bdrop\b.*\btable\b)", r"(\bunion\b.*\bselect\b)", r"(\border\b.*\bby\b)",
    r"admin'--", r"1=1", r"1=2", r"';\s*drop\s", r"';\s*exec\s",
]

XSS_PATTERNS = [
    r"<script[^>]*>", r"onerror\s*=", r"onload\s*=", r"onclick\s*=",
    r"onmouseover\s*=", r"javascript\s*:", r"<img[^>]+src\s*=",
    r"<svg[^>]*>", r"alert\s*\(", r"eval\s*\(", r"fromCharCode",
    r"<iframe[^>]*>", r"document\.cookie", r"window\.location",
]


class AttackClassifier:
    def __init__(self):
        self.bert_model = None
        self.bert_tokenizer = None
        self.fallback_model: Optional[Pipeline] = None
        self._bert_available = False
        self._bert_cache = None
        self._bert_device = None
        self._load_bert()
        self._load_fallback()

    def _load_bert(self):
        try:
            import torch
            from transformers import DistilBertForSequenceClassification, DistilBertTokenizerFast

            model_name = "distilbert-base-uncased"
            num_labels = len(ATTACK_CLASSES)

            cache_dir = os.path.join(MODEL_DIR, "bert_cache")
            os.makedirs(cache_dir, exist_ok=True)

            self.bert_tokenizer = DistilBertTokenizerFast.from_pretrained(
                model_name, cache_dir=cache_dir
            )

            model_path = os.path.join(MODEL_DIR, "bert_classifier")
            if os.path.exists(model_path) and os.path.isdir(model_path):
                self.bert_model = DistilBertForSequenceClassification.from_pretrained(
                    model_path, cache_dir=cache_dir
                )
            else:
                self.bert_model = DistilBertForSequenceClassification.from_pretrained(
                    model_name, num_labels=num_labels, cache_dir=cache_dir
                )

            self._bert_device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self.bert_model.to(self._bert_device)
            self.bert_model.eval()
            self._bert_available = True
            logger.info(f"BERT model loaded on {self._bert_device}")

        except Exception as e:
            logger.warning(f"BERT model unavailable, using fallback: {e}")
            self._bert_available = False

    def _load_fallback(self):
        path = CLASSIFIER_MODEL_PATH
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    data = pickle.load(f)
                if isinstance(data, dict):
                    self.fallback_model = data.get("model")
                    self._vectorizer = data.get("vectorizer")
                else:
                    self.fallback_model = data
                    self._vectorizer = None
                logger.info(f"Fallback classifier loaded")
            except Exception as e:
                logger.error(f"Failed to load fallback classifier: {e}")

    def _predict_bert(self, payload: str) -> Tuple[str, float]:
        import torch

        inputs = self.bert_tokenizer(
            payload,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=512,
        )
        inputs = {k: v.to(self._bert_device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = self.bert_model(**inputs)
            logits = outputs.logits
            probabilities = torch.nn.functional.softmax(logits, dim=-1)
            confidence, predicted = torch.max(probabilities, dim=-1)

        predicted_class = ATTACK_CLASSES[predicted.item()]
        confidence_score = confidence.item()

        return predicted_class, confidence_score

    def _predict_fallback(self, payload: str) -> Tuple[str, float]:
        if self.fallback_model is None:
            logger.warning("No fallback model available, using pattern matching")

        if self.fallback_model is not None:
            try:
                probs = self.fallback_model.predict_proba([payload])[0]
                max_idx = np.argmax(probs)
                predicted_class = ATTACK_CLASSES[max_idx] if max_idx < len(ATTACK_CLASSES) else "no-attack"
                confidence = float(probs[max_idx])
                return predicted_class, confidence
            except Exception as e:
                logger.error(f"Fallback prediction error: {e}")

        return self._pattern_match(payload)

    def _pattern_match(self, payload: str) -> Tuple[str, float]:
        import re

        payload_lower = payload.lower()

        sqli_score = sum(1 for p in SQLI_PATTERNS if re.search(p, payload_lower, re.IGNORECASE))
        xss_score = sum(1 for p in XSS_PATTERNS if re.search(p, payload_lower, re.IGNORECASE))

        rce_indicators = ["/bin/", "/usr/bin", "bash -c", "powershell", "cmd.exe", "; rm ", "; cat ", "| cat ", "&& curl", "&& wget", "`id`", "$(id)"]
        rce_score = sum(1 for p in rce_indicators if p in payload_lower)

        pt_indicators = ["../", "..\\", "%2e%2e", "....//", "/etc/passwd", "c:\\windows", "/proc/self/"]
        pt_score = sum(1 for p in pt_indicators if p in payload_lower)

        ssti_indicators = ["{{", "}}", "${", "{%", "%}", "{{7*7}}", "${7*7}"]
        ssti_score = sum(1 for p in ssti_indicators if p in payload_lower)

        scores = {
            "sql-injection": sqli_score * 0.3,
            "xss": xss_score * 0.3,
            "rce": rce_score * 0.3,
            "path-traversal": pt_score * 0.3,
            "ssti": ssti_score * 0.3,
            "no-attack": 0.1,
        }

        # Check for path traversal in path-like payloads
        if "/../" in payload or "/..\\" in payload:
            scores["path-traversal"] += 0.4

        # Check for command injection
        if any(c in payload for c in [";", "|", "`", "$"]) and any(cmd in payload_lower for cmd in ["id", "ls", "cat", "whoami", "pwd", "uname"]):
            scores["command-injection"] = max(scores.get("command-injection", 0), 0.5)
            scores["rce"] = max(scores.get("rce", 0), 0.3)

        if all(s < 0.2 for s in scores.values()):
            return "no-attack", 0.95

        best_class = max(scores, key=scores.get)
        best_score = scores[best_class]
        return best_class, min(1.0, best_score + 0.5)

    def predict(self, payload: str) -> Tuple[str, float]:
        if not payload or not payload.strip():
            return "no-attack", 1.0

        if self._bert_available and self.bert_model is not None:
            try:
                return self._predict_bert(payload)
            except Exception as e:
                logger.error(f"BERT prediction failed, using fallback: {e}")

        return self._predict_fallback(payload)

    def train_fallback(self, texts: List[str], labels: List[str]):
        vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 3),
            sublinear_tf=True,
            min_df=2,
            max_df=0.95,
            token_pattern=r"(?u)\b\w+\b",
        )
        label_ids = [ATTACK_CLASS_INDEX.get(l, ATTACK_CLASS_INDEX["no-attack"]) for l in labels]

        X = vectorizer.fit_transform(texts)
        model = LogisticRegression(
            C=1.0,
            solver="lbfgs",
            max_iter=500,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X, label_ids)

        self.fallback_model = Pipeline([
            ("vectorizer", vectorizer),
            ("classifier", model),
        ])
        self._save_fallback()

    def evaluate_fallback(self, texts: List[str], labels: List[str]) -> float:
        """Return cross-validated accuracy of a *candidate* pipeline, or 0 when
        there is not enough labelled data to judge. Used to reject a retrain
        that would make the classifier worse than what is already loaded."""
        if len(texts) < 10:
            return 0.0
        label_ids = [ATTACK_CLASS_INDEX.get(l, ATTACK_CLASS_INDEX["no-attack"]) for l in labels]
        if len(set(label_ids)) < 2:
            # A single class cannot be scored; treat as unjudgeable.
            return 0.0
        try:
            vectorizer = TfidfVectorizer(
                max_features=5000, ngram_range=(1, 3), sublinear_tf=True,
                token_pattern=r"(?u)\b\w+\b",
            )
            X = vectorizer.fit_transform(texts)
            n_splits = min(5, min(label_ids.count(c) for c in set(label_ids)))
            if n_splits < 2:
                return 0.0
            cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
            model = LogisticRegression(
                max_iter=500, random_state=42, n_jobs=-1,
            )
            scores = cross_val_score(model, X, label_ids, cv=cv, scoring="accuracy")
            return float(np.mean(scores))
        except Exception as e:
            logger.warning(f"evaluate_fallback failed: {e}")
            return 0.0

    def build_candidate(self, texts: List[str], labels: List[str]):
        """Fit and return a candidate pipeline without adopting it, so the
        caller can score it against the current model before swapping."""
        vectorizer = TfidfVectorizer(
            max_features=5000, ngram_range=(1, 3), sublinear_tf=True,
            min_df=2, max_df=0.95, token_pattern=r"(?u)\b\w+\b",
        )
        label_ids = [ATTACK_CLASS_INDEX.get(l, ATTACK_CLASS_INDEX["no-attack"]) for l in labels]
        X = vectorizer.fit_transform(texts)
        model = LogisticRegression(
            max_iter=500, random_state=42, n_jobs=-1,
        )
        model.fit(X, label_ids)
        return Pipeline([("vectorizer", vectorizer), ("classifier", model)])

    def adopt(self, pipeline: Pipeline):
        """Install a candidate pipeline as the live model and persist it."""
        self.fallback_model = pipeline
        self._save_fallback()

    def _save_fallback(self):
        if self.fallback_model is not None:
            path = CLASSIFIER_MODEL_PATH
            with open(path, "wb") as f:
                pickle.dump(self.fallback_model, f)
            logger.info(f"Fallback classifier saved to {path}")

    def export_bert(self, save_dir: Optional[str] = None):
        if self.bert_model is not None and self.bert_tokenizer is not None:
            save_path = save_dir or os.path.join(MODEL_DIR, "bert_classifier")
            os.makedirs(save_path, exist_ok=True)
            self.bert_model.save_pretrained(save_path)
            self.bert_tokenizer.save_pretrained(save_path)
            logger.info(f"BERT model exported to {save_path}")

    @property
    def version(self) -> str:
        if self._bert_available:
            return "distilbert-v2.0"
        elif self.fallback_model is not None:
            return "tfidf-lr-v2.0"
        return "pattern-match-v2.0"

    @property
    def is_loaded(self) -> bool:
        return self._bert_available or self.fallback_model is not None
