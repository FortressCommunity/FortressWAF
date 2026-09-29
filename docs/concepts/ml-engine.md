# ML Engine Architecture

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

> **Note:** The ML sidecar supports four models (anomaly detection, attack classification, bot detection, risk scoring) via separate API endpoints. Continuous learning, A/B testing, and the training pipeline described below require additional infrastructure and are not yet automated.

FortressWAF includes an optional ML sidecar for anomaly detection. The ML engine scores requests based on learned patterns and can flag deviations from normal traffic.

## ML Engine Overview

The FortressWAF ML engine consists of four primary models that work together to provide comprehensive threat detection:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          ML ENGINE ARCHITECTURE                          │
└─────────────────────────────────────────────────────────────────────────┘

                           ┌──────────────────┐
                           │  Request Input   │
                           └────────┬─────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
           ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
           │  Isolation  │ │  DistilBERT │ │   Random    │
           │   Forest    │ │     NLP     │ │    Forest   │
           │  (Anomaly)  │ │ (Content)   │ │ (Classifier)│
           └─────────────┘ └─────────────┘ └─────────────┘
                    │               │               │
                    │               │               │
                    └───────────────┼───────────────┘
                                    │
                                    ▼
                           ┌──────────────────┐
                           │    Gradient      │
                           │    Boosting      │
                           │   (Ensemble)     │
                           └────────┬─────────┘
                                    │
                                    ▼
                           ┌──────────────────┐
                           │  Final Threat    │
                           │     Score        │
                           └──────────────────┘
```

## Models

### 1. Isolation Forest

**Purpose**: Anomaly detection on structured request features

**How It Works**: Isolation Forest isolates anomalies by randomly selecting features and split values. Anomalies are easier to isolate (shorter path lengths) than normal points.

**Features Used**:
| Feature | Description | Type |
|---------|-------------|------|
| `path_length` | URL path length | integer |
| `query_length` | Query string length | integer |
| `header_count` | Number of headers | integer |
| `body_length` | Request body length | integer |
| `path_entropy` | Character entropy of path | float |
| `query_entropy` | Character entropy of query | float |
| `special_char_ratio` | Ratio of special characters | float |
| `digit_ratio` | Ratio of digits | float |
| `upper_ratio` | Ratio of uppercase letters | float |
| `null_bytes_present` | Contains null bytes | boolean |
| `control_chars_present` | Contains control characters | boolean |

**Configuration**:
```yaml
ml:
  models:
    isolation_forest:
      enabled: true
      n_estimators: 100
      max_samples: 256
      contamination: 0.1  # Expected proportion of anomalies
      random_state: 42
```

**Output**: Anomaly score (0.0 - 1.0), where higher values indicate more anomalous requests.

### 2. DistilBERT NLP

**Purpose**: Natural language processing for content-based threat detection

**How It Works**: DistilBERT is a distilled version of BERT that understands context. We use it to analyze request content (paths, query strings, body) for malicious patterns that rule-based systems might miss.

**Capabilities**:
- Contextual understanding of obfuscated attacks
- Detection of encoded malicious content
- Identification of suspicious text patterns
- Zero-day attack detection

**Example Threat Detection**:
```python
# Input: "/search?q=<script>alert('XSS')</script>"
# DistilBERT understands the HTML context and marks as malicious

# Input: "/api/user?id=1' OR '1'='1"
# DistilBERT recognizes SQL context and marks as malicious
```

**Configuration**:
```yaml
ml:
  models:
    distilbert:
      enabled: true
      model_name: "distilbert-base-uncased"
      max_length: 512
      batch_size: 32
      device: "cuda"  # or "cpu"
      fallback_enabled: true
```

**Input Processing**:
```python
# Request content is concatenated and tokenized
text = f"{method} {path} {query} {body}"
inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)

# Model outputs logits for threat classification
outputs = model(**inputs)
threat_score = softmax(outputs.logits)[1]  # Probability of being malicious
```

### 3. Random Forest

**Purpose**: Multi-class classification of request types

**How It Works**: Random Forest is an ensemble of decision trees that votes on the most likely request category. It provides interpretable decisions and handles mixed feature types well.

**Classification Categories**:
| Class | Description |
|-------|-------------|
| `normal` | Legitimate request |
| `sql_injection` | SQL injection attempt |
| `xss` | Cross-site scripting attempt |
| `cmdi` | Command injection attempt |
| `lfi` | Local file inclusion attempt |
| `rfi` | Remote file inclusion attempt |
| `scanner` | Security scanner probe |
| `crawler` | Automated crawler |
| `bruteforce` | Brute force attempt |
| `suspicious` | Other suspicious activity |

**Features Used**:
```python
features = [
    # Request characteristics
    request.method_one_hot,
    request.path_length,
    request.query_length,
    request.body_length,

    # Character analysis
    path_has_sql_keywords,
    path_has_xss_keywords,
    path_has_cmd_keywords,

    # Structural analysis
    header_count,
    has_unusual_headers,
    has_authorization_header,

    # Behavioral
    requests_per_minute_from_ip,
    similar_requests_count,
    is_authenticated,

    # Context
    hour_of_day,
    day_of_week,
]
```

**Configuration**:
```yaml
ml:
  models:
    random_forest:
      enabled: true
      n_estimators: 100
      max_depth: 10
      min_samples_split: 5
      min_samples_leaf: 2
      class_weight: "balanced"
```

**Output**: Class probabilities for each category, with the highest probability being the predicted class.

### 4. Gradient Boosting

**Purpose**: Ensemble scoring combining all signals

**How It Works**: Gradient Boosting builds an ensemble model that learns to correct the errors of simpler models. We use it to combine scores from other models into a final threat score.

**Input Features**:
```python
ensemble_features = [
    isolation_forest_score,     # 0.0 - 1.0
    distilbert_threat_score,   # 0.0 - 1.0
    random_forest_class_prob,  # 0.0 - 1.0
    ip_reputation_score,       # 0.0 - 1.0
    bot_detection_score,        # 0.0 - 1.0
    rate_limit_exceeded,        # 0.0 - 1.0
    hour_of_day,                # 0.0 - 1.0
    day_of_week,                # 0.0 - 1.0
    is_authenticated,           # 0.0 - 1.0
    request_frequency,          # 0.0 - 1.0
]
```

**Training**: The model is trained on labeled historical data with known attack/benign labels.

**Configuration**:
```yaml
ml:
  models:
    gradient_boosting:
      enabled: true
      n_estimators: 100
      learning_rate: 0.1
      max_depth: 5
      subsample: 0.8
      objective: "binary:logistic"
```

**Output**: Final threat probability (0.0 - 1.0)

## Feature Extraction

### Real-Time Feature Pipeline

```
Request → Feature Extraction → Normalization → Model Input
```

**Feature Extraction Process**:

```python
class FeatureExtractor:
    def extract(self, request: Request) -> FeatureVector:
        features = {}

        # Basic request features
        features['method'] = self._encode_method(request.method)
        features['path_length'] = len(request.path)
        features['query_length'] = len(request.query)
        features['body_length'] = len(request.body)
        features['header_count'] = len(request.headers)

        # Character analysis
        features['path_entropy'] = self._calculate_entropy(request.path)
        features['query_entropy'] = self._calculate_entropy(request.query)
        features['special_char_ratio'] = self._count_special_chars(request.path)
        features['digit_ratio'] = self._count_digits(request.path)
        features['upper_ratio'] = self._count_uppercase(request.path)

        # Content analysis
        features['sql_keywords'] = self._count_sql_keywords(request)
        features['xss_keywords'] = self._count_xss_keywords(request)
        features['cmd_keywords'] = self._count_cmd_keywords(request)

        # Context features
        features['hour'] = self._get_hour_of_day()
        features['day'] = self._get_day_of_week()
        features['is_authenticated'] = request.user is not None

        return FeatureVector(features)

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        import math
        if not text:
            return 0.0

        counter = Counter(text)
        length = len(text)

        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy / 8.0  # Normalize to 0-1
```

### Feature Caching

Features are cached in Redis to avoid redundant computation:

```python
# Cache key format
cache_key = f"ml:features:{request_id}"
cache_ttl = 300  # 5 minutes

# Store extracted features
redis.setex(cache_key, cache_ttl, features)
```

## Model Training Pipeline

### Training Data Collection

```
Request → Annotation Pipeline → Labeled Dataset → Training
```

**Data Sources**:
1. **FortressWAF Global Network**: Anonymized requests from all deployments
2. **Internal Red Team**: Simulated attack data
3. **Public Datasets**: OWASP, CVE, security research
4. **Customer Data**: On-premise learning (optional)

**Annotation Process**:
```python
# Automated labeling using multiple signals
def label_request(request: Request) -> Label:
    # Rule-based labels (high confidence)
    if rule_matched("sql_injection", request):
        return Label.attack("sql_injection")

    # ML ensemble labels (with confidence threshold)
    ml_label = ml_model.predict(request)
    if ml_label.confidence > 0.9:
        return ml_label

    # Human review for uncertain cases
    if ml_label.confidence < 0.7:
        send_to_human_review(request)

    # Default to benign with low confidence
    return Label.benign()
```

### Training Schedule

| Model | Training Frequency | Data Volume | Duration |
|-------|-------------------|-------------|----------|
| Isolation Forest | Weekly | 1M samples | 30 min |
| DistilBERT | Monthly | 500K samples | 4 hours |
| Random Forest | Weekly | 2M samples | 1 hour |
| Gradient Boosting | Daily | 5M samples | 2 hours |

### Training Process

```python
def train_isolation_forest(training_data: pd.DataFrame):
    """Train Isolation Forest model"""
    from sklearn.ensemble import IsolationForest

    # Extract features
    X = feature_extractor.extract_batch(training_data)

    # Handle missing values
    X = X.fillna(0)

    # Train model
    model = IsolationForest(
        n_estimators=100,
        max_samples=256,
        contamination=0.1,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X)

    # Evaluate
    predictions = model.predict(X)
    scores = model.score_samples(X)

    # Log metrics
    log_metrics({
        "accuracy": accuracy_score(y_true, predictions),
        "auc": roc_auc_score(y_true, scores),
    })

    return model

def train_distilbert(training_data: pd.DataFrame):
    """Fine-tune DistilBERT for threat classification"""
    from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
    from transformers import Trainer, TrainingArguments

    # Load pre-trained model
    tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
    model = DistilBertForSequenceClassification.from_pretrained(
        'distilbert-base-uncased',
        num_labels=2  # benign/malicious
    )

    # Tokenize data
    def tokenize(batch):
        texts = [f"{r.method} {r.path} {r.query} {r.body}" for r in batch]
        return tokenizer(texts, truncation=True, max_length=512, padding=True)

    tokenized_data = tokenize(training_data)

    # Training arguments
    training_args = TrainingArguments(
        output_dir="./models/distilbert",
        num_train_epochs=3,
        per_device_train_batch_size=32,
        learning_rate=2e-5,
        logging_steps=1000,
        save_strategy="epoch",
    )

    # Train
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_data,
    )

    trainer.train()

    return model
```

## Online Learning

FortressWAF supports online learning to adapt to new threats in real-time:

### Concept Drift Detection

```python
class ConceptDriftDetector:
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.recent_predictions = deque(maxlen=window_size)
        self.baseline_distribution = None

    def detect(self, prediction: float, actual: bool):
        """Detect concept drift in model predictions"""
        self.recent_predictions.append((prediction, actual))

        # Calculate current distribution
        current_dist = self._calculate_distribution()

        # Compare to baseline using KL divergence
        if self.baseline_distribution is not None:
            divergence = self._kl_divergence(current_dist, self.baseline_distribution)

            if divergence > self.drift_threshold:
                self._trigger_retraining()

    def _calculate_distribution(self, bins: int = 10) -> np.ndarray:
        """Calculate probability distribution of predictions"""
        predictions = [p for p, _ in self.recent_predictions]
        hist, _ = np.histogram(predictions, bins=bins, range=(0, 1))
        return hist / len(predictions)
```

### Incremental Updates

```python
class OnlineLearner:
    def update_models(self, new_data: List[Request]):
        """Incrementally update models with new data"""

        # Update Isolation Forest with new anomalies
        if self._count_anomalies(new_data) > self.anomaly_threshold:
            self.isolation_forest.fit_incremental(new_data)

        # Update Gradient Boosting with confirmed labels
        confirmed_labels = self._get_confirmed_labels(new_data)
        if len(confirmed_labels) > self.min_batch_size:
            self.gradient_boosting.fit_incremental(confirmed_labels)

    def retrain_if_needed(self):
        """Full retrain if online updates insufficient"""
        drift_detected = self.drift_detector.check_drift()

        if drift_detected:
            logger.info("Concept drift detected, initiating full retrain")
            self.full_retrain()
```

## Threshold Configuration

### Threshold Tuning

The ML engine uses configurable thresholds to balance security and usability:

```yaml
ml:
  # Global threshold for blocking
  anomaly_threshold: 0.75

  # Per-model thresholds
  thresholds:
    isolation_forest: 0.6   # Contamination threshold
    distilbert: 0.8          # Threat classification threshold
    random_forest: 0.7       # Classification confidence
    gradient_boosting: 0.75  # Ensemble confidence

  # Actions by threshold range
  actions:
    low (0.0-0.5):      allow
    medium (0.5-0.7):   monitor
    high (0.7-0.85):    challenge
    critical (0.85-1.0): block
```

### Threshold Optimization

```python
def optimize_thresholds(
    historical_data: pd.DataFrame,
    true_labels: List[bool],
    target_fpr: float = 0.01  # Target 1% false positive rate
) -> Dict[str, float]:
    """Optimize thresholds to achieve target false positive rate"""

    from sklearn.metrics import roc_curve

    # Get model predictions
    predictions = ml_model.predict_proba(historical_data)[:, 1]

    # Find threshold for target FPR
    fpr, tpr, thresholds = roc_curve(true_labels, predictions)

    # Find threshold where FPR <= target
    optimal_idx = np.where(fpr <= target_fpr)[0][-1]
    optimal_threshold = thresholds[optimal_idx]

    return {
        "threshold": optimal_threshold,
        "fpr_at_threshold": fpr[optimal_idx],
        "tpr_at_threshold": tpr[optimal_idx],
    }
```

## Fallback Behavior

When the ML engine is unavailable, FortressWAF falls back to rule-based detection:

```yaml
ml:
  # Enable ML engine
  enabled: true

  # Fallback when ML is unavailable
  fallback_enabled: true
  fallback_action: "log_and_challenge"  # "log", "log_and_challenge", "allow"

  # Health check configuration
  health_check:
    enabled: true
    interval: 30s
    timeout: 5s
    failure_threshold: 3

  # Circuit breaker
  circuit_breaker:
    enabled: true
    failure_threshold: 5
    recovery_timeout: 60s
```

### Fallback Decision Matrix

| ML Status | Fallback Action | Description |
|-----------|----------------|-------------|
| Healthy | Use ML scores | Normal operation |
| Degraded | Use ML scores with higher thresholds | Reduced sensitivity |
| Unavailable | Rule-based only | Fallback to rules |
| Overloaded | Rate limit ML requests | Backpressure handling |

## Performance Considerations

### Latency Budget

ML inference must complete within strict latency limits:

| Model | P50 | P95 | P99 | Max |
|-------|-----|-----|-----|-----|
| Isolation Forest | 1ms | 3ms | 5ms | 10ms |
| DistilBERT | 3ms | 10ms | 20ms | 50ms |
| Random Forest | 0.5ms | 2ms | 3ms | 5ms |
| Gradient Boosting | 1ms | 3ms | 5ms | 10ms |
| **Total** | **6ms** | **20ms** | **40ms** | **80ms** |

### Optimization Techniques

1. **Model Quantization**: INT8 quantization for faster inference
2. **Batch Processing**: Group requests for batch inference
3. **Caching**: Cache frequent patterns
4. **Early Exits**: Skip models for obvious cases
5. **GPU Acceleration**: Use GPU when available

### Resource Requirements

| Model | CPU | Memory | GPU (optional) |
|-------|-----|--------|----------------|
| Isolation Forest | 1 core | 100MB | Not required |
| DistilBERT | 4 cores | 500MB | 2GB VRAM |
| Random Forest | 2 cores | 200MB | Not required |
| Gradient Boosting | 2 cores | 300MB | Not required |

## Monitoring and Observability

### ML Metrics

```yaml
metrics:
  - fortresswaf_ml_score                    # Current ML score
  - fortresswaf_ml_inference_duration       # Inference latency
  - fortresswaf_ml_model_health             # Model health status
  - fortresswaf_ml_predictions_total        # Total predictions
  - fortresswaf_ml_confidence histogram     # Prediction confidence
```

### Alerting

```yaml
alerts:
  - name: ml_model_degraded
    condition: ml_health_score < 0.8
    severity: warning

  - name: ml_model_unavailable
    condition: ml_health_score == 0
    severity: critical

  - name: ml_latency_high
    condition: ml_inference_p99 > 50ms
    severity: warning

  - name: ml_false_positive_rate_high
    condition: fpr > 0.05
    severity: warning
```

## Model Versioning

Models are versioned and stored in object storage:

```python
model_versions = {
    "isolation_forest": {
        "current": "v2024.01.15.1",
        "previous": "v2024.01.08.3",
        "canary": "v2024.01.22.1"
    },
    "distilbert": {
        "current": "v2024.01.01.0",
        "previous": "v2023.12.15.0"
    }
}

# Rollback if issues detected
def rollback_model(model_name: str):
    previous_version = model_versions[model_name]["previous"]
    load_model_from_storage(model_name, previous_version)
    logger.info(f"Rolled back {model_name} to {previous_version}")
```
