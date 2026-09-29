import os
import time
import logging
from datetime import datetime, timezone
from contextlib import asynccontextmanager

import numpy as np

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
import prometheus_client

from api.schemas import (
    InspectRequest, InspectResponse, ClassifyRequest, ClassifyResponse,
    FingerprintRequest, FingerprintResponse, BotScoreRequest, BotScoreResponse,
    ModelStatus, RetrainConfig,
)
from models import AnomalyDetector, AttackClassifier, BotDetector, RiskScorer
from training.feature_engineering import compute_request_fingerprint

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

anomaly_detector = AnomalyDetector()
attack_classifier = AttackClassifier()
bot_detector = BotDetector()
risk_scorer = RiskScorer()

MODEL_VERSION = "2.0.0"
MODEL_START_TIME = datetime.now(timezone.utc)

# The training corpus the collector appends to. CORPUS_DIR can be overridden by
# env so the sidecar and the Go collector agree on one location.
CORPUS_DIR = os.environ.get(
    "CORPUS_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "training", "data"),
)
MIN_TRAINING_SAMPLES = int(os.environ.get("MIN_TRAINING_SAMPLES", "40"))

# Live model metrics, updated by a successful retrain.
MODEL_METRICS: dict = {"classifier_accuracy": 0.0, "classifier_samples": 0, "last_trained": None}


def load_training_corpus(data_dir: str):
    """Load every labelled sample from the corpus.

    Each subdirectory is an attack category whose name is the label; a
    "no-attack" directory holds benign samples. Lines are payloads; a trailing
    "\\t# ..." annotation (added by the live collector) is stripped. Returns
    (texts, labels, per-category counts).
    """
    texts: list = []
    labels: list = []
    stats: dict = {}

    if not os.path.isdir(data_dir):
        return texts, labels, stats

    for category in sorted(os.listdir(data_dir)):
        cat_path = os.path.join(data_dir, category)
        if not os.path.isdir(cat_path):
            continue
        count = 0
        for fname in sorted(os.listdir(cat_path)):
            if not fname.endswith((".txt", ".json", ".csv")):
                continue
            fpath = os.path.join(cat_path, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    for raw in f:
                        line = raw.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "\t#" in line:
                            line = line.split("\t#", 1)[0].strip()
                        if not line:
                            continue
                        texts.append(line)
                        labels.append(category)
                        count += 1
            except OSError as e:
                logger.warning(f"could not read {fpath}: {e}")
        if count:
            stats[category] = count
    return texts, labels, stats


REQUEST_COUNT = prometheus_client.Counter(
    "waf_requests_total", "Total WAF requests", ["endpoint", "method", "status"]
)
REQUEST_LATENCY = prometheus_client.Histogram(
    "waf_request_latency_seconds", "Request latency", ["endpoint"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)
ANOMALY_SCORE = prometheus_client.Gauge("waf_anomaly_score", "Per-request anomaly score", ["source_ip"])
BOT_SCORE = prometheus_client.Gauge("waf_bot_score", "Per-request bot score", ["source_ip"])
RISK_SCORE = prometheus_client.Gauge("waf_risk_score", "Per-session risk score", ["session_id"])
MODEL_HEALTH = prometheus_client.Gauge("waf_model_health", "Model health status", ["model_name"])


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting FortressWAF ML Engine")
    MODEL_HEALTH.labels(model_name="anomaly").set(1 if anomaly_detector.is_loaded else 0)
    MODEL_HEALTH.labels(model_name="classifier").set(1 if attack_classifier.is_loaded else 0)
    MODEL_HEALTH.labels(model_name="bot_detector").set(1 if bot_detector.is_loaded else 0)
    MODEL_HEALTH.labels(model_name="risk_scorer").set(1 if risk_scorer.is_loaded else 0)
    yield
    logger.info("Shutting down FortressWAF ML Engine")


app = FastAPI(
    title="FortressWAF ML Engine",
    version=MODEL_VERSION,
    lifespan=lifespan,
)

# The sidecar is an internal service: only the Go proxy calls it, over the
# container network. It is not a browser-facing API and serves no cookies, so
# cross-origin access is denied outright rather than opened up with a wildcard.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_credentials=False,
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type"],
)

# Cap the request body before FastAPI parses it. The proxy already limits what
# it forwards, but the sidecar must not trust that: an attacker with a direct
# route to :8000 could otherwise make it buffer an unbounded body.
MAX_REQUEST_BYTES = 10 * 1024 * 1024  # 10 MiB


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    length = request.headers.get("content-length")
    if length is not None:
        try:
            if int(length) > MAX_REQUEST_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"error": "payload too large"},
                )
        except ValueError:
            return JSONResponse(status_code=400, content={"error": "invalid content-length"})
    return await call_next(request)


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    start_time = time.time()
    try:
        response = await call_next(request)
    except Exception as e:
        logger.error(f"Request failed: {request.method} {request.url.path}: {e}")
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )
    duration = time.time() - start_time
    logger.info(
        f"{request.method} {request.url.path} -> {response.status_code} ({duration:.4f}s)"
    )
    REQUEST_COUNT.labels(
        endpoint=request.url.path, method=request.method, status=response.status_code
    ).inc()
    REQUEST_LATENCY.labels(endpoint=request.url.path).observe(duration)
    response.headers["X-Request-Duration-Ms"] = str(round(duration * 1000, 2))
    return response


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "path": request.url.path},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.url.path}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "path": request.url.path},
    )


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": MODEL_VERSION,
        "models": {
            "anomaly": anomaly_detector.is_loaded,
            "classifier": attack_classifier.is_loaded,
            "bot_detector": bot_detector.is_loaded,
            "risk_scorer": risk_scorer.is_loaded,
        },
    }


@app.get("/metrics")
async def metrics():
    data = prometheus_client.generate_latest()
    return Response(content=data, media_type="text/plain; version=0.0.4; charset=utf-8")


@app.post("/v1/inspect", response_model=InspectResponse)
async def inspect_request(req: InspectRequest):
    try:
        anomaly_score = anomaly_detector.score(req.model_dump())
        is_anomaly = anomaly_score >= 0.7

        payload_text = (req.body or "") + " " + " ".join(f"{k}={v}" for k, v in req.query_params.items())
        attack_type = None
        attack_confidence = None
        if payload_text.strip():
            attack_type, attack_confidence = attack_classifier.predict(payload_text)
            if attack_type == "no-attack":
                attack_type = None
                attack_confidence = None

        bot_score, is_bot, bot_type = bot_detector.classify(
            user_agent=req.user_agent,
            headers=req.headers,
            request_timing_ms=0,
            accept_language=req.headers.get("accept-language", ""),
        )

        session_id = f"session_{req.source_ip}"
        risk_scorer.record_request(
            session_id=session_id,
            endpoint=req.path,
            method=req.method,
            status_code=200,
            anomaly_score=anomaly_score,
        )
        risk_score, risk_details = risk_scorer.score(session_id, current_anomaly=anomaly_score)

        fingerprint = compute_request_fingerprint(
            method=req.method,
            path=req.path,
            headers=req.headers,
            user_agent=req.user_agent,
            body=req.body,
            query_params=req.query_params,
        )

        ANOMALY_SCORE.labels(source_ip=req.source_ip).set(anomaly_score)
        BOT_SCORE.labels(source_ip=req.source_ip).set(bot_score)
        RISK_SCORE.labels(session_id=session_id).set(risk_score)

        return InspectResponse(
            anomaly_score=round(anomaly_score, 4),
            is_anomaly=is_anomaly,
            attack_type=attack_type,
            attack_confidence=round(attack_confidence, 4) if attack_confidence is not None else None,
            bot_score=round(bot_score, 4),
            risk_score=risk_score,
            fingerprint=fingerprint,
            model_version=MODEL_VERSION,
        )

    except Exception as e:
        logger.error(f"Inspect error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/v1/classify", response_model=ClassifyResponse)
async def classify_payload(req: ClassifyRequest):
    try:
        if not req.payload or not req.payload.strip():
            raise HTTPException(status_code=400, detail="Empty payload")

        attack_type, confidence = attack_classifier.predict(req.payload)

        return ClassifyResponse(
            attack_type=attack_type,
            confidence=round(confidence, 4),
            model_version=attack_classifier.version,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Classify error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/v1/fingerprint", response_model=FingerprintResponse)
async def generate_fingerprint(req: FingerprintRequest):
    try:
        fingerprint = compute_request_fingerprint(
            method=req.method,
            path=req.path,
            headers=req.headers,
            user_agent=req.user_agent,
        )

        return FingerprintResponse(
            fingerprint=fingerprint,
            hash_algorithm="SHA-256",
        )

    except Exception as e:
        logger.error(f"Fingerprint error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/v1/bot-score", response_model=BotScoreResponse)
async def score_bot(req: BotScoreRequest):
    try:
        bot_score, is_bot, bot_type = bot_detector.classify(
            user_agent=req.user_agent,
            headers=req.headers,
            request_timing_ms=req.request_timing_ms,
            accept_language=req.accept_language,
            js_challenge_result=req.js_challenge_result,
        )

        return BotScoreResponse(
            bot_score=round(bot_score, 4),
            is_bot=is_bot,
            bot_type=bot_type,
        )

    except Exception as e:
        logger.error(f"Bot score error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/v1/model/status", response_model=ModelStatus)
async def model_status():
    return ModelStatus(
        model_version=MODEL_VERSION,
        last_trained=MODEL_START_TIME.isoformat(),
        anomaly_model_loaded=anomaly_detector.is_loaded,
        classifier_model_loaded=attack_classifier.is_loaded,
        bot_model_loaded=bot_detector.is_loaded,
        risk_model_loaded=risk_scorer.is_loaded,
        total_samples_trained=anomaly_detector.trained_samples,
    )


@app.post("/v1/model/retrain")
async def retrain_model(config: RetrainConfig = RetrainConfig()):
    """Retrain the classifier on the on-disk corpus, adopting the new model only
    if it is at least as good as the current one.

    Data quality is enforced upstream: the collector only writes high-confidence
    blocks, labelled by rule family. This endpoint refuses to train on a corpus
    too small to judge, and refuses to keep a model that scores worse than what
    is already loaded -- a bad batch cannot degrade the live model.
    """
    texts, labels, stats = load_training_corpus(CORPUS_DIR)
    if len(texts) < MIN_TRAINING_SAMPLES:
        raise HTTPException(
            status_code=422,
            detail=(
                f"corpus has {len(texts)} samples, need at least "
                f"{MIN_TRAINING_SAMPLES} to train a reliable model"
            ),
        )

    # Score the candidate before adopting it.
    candidate_acc = attack_classifier.evaluate_fallback(texts, labels)
    if candidate_acc <= 0.0:
        raise HTTPException(
            status_code=422,
            detail="could not score the candidate model (too few classes or samples per class)",
        )

    current = MODEL_METRICS.get("classifier_accuracy", 0.0)
    result = {
        "status": "rejected",
        "reason": "",
        "candidate_accuracy": round(candidate_acc, 4),
        "current_accuracy": round(current, 4),
        "samples": len(texts),
        "by_category": stats,
    }

    # Only adopt when the candidate is not worse than the incumbent. A first
    # train (current == 0) is always adopted.
    if current > 0 and candidate_acc + 1e-9 < current:
        result["reason"] = (
            f"candidate accuracy {candidate_acc:.3f} is below the incumbent "
            f"{current:.3f}; kept the existing model"
        )
        logger.warning(f"retrain rejected: {result['reason']}")
        return JSONResponse(status_code=200, content=result)

    pipeline = attack_classifier.build_candidate(texts, labels)
    attack_classifier.adopt(pipeline)
    MODEL_METRICS["classifier_accuracy"] = candidate_acc
    MODEL_METRICS["classifier_samples"] = len(texts)
    MODEL_METRICS["last_trained"] = datetime.now(timezone.utc).isoformat()
    MODEL_HEALTH.labels(model_name="classifier").set(1)

    result["status"] = "adopted"
    result["reason"] = "candidate is at least as accurate as the incumbent"
    logger.info(f"retrain adopted: acc={candidate_acc:.3f} on {len(texts)} samples")
    return result


@app.get("/v1/model/training-status")
async def training_status():
    """Report what the corpus holds and how the live model scored, so the
    console can show training health honestly."""
    texts, labels, stats = load_training_corpus(CORPUS_DIR)
    return {
        "corpus_dir": CORPUS_DIR,
        "total_samples": len(texts),
        "by_category": stats,
        "min_required": MIN_TRAINING_SAMPLES,
        "classifier_accuracy": round(MODEL_METRICS.get("classifier_accuracy", 0.0), 4),
        "classifier_samples": MODEL_METRICS.get("classifier_samples", 0),
        "last_trained": MODEL_METRICS.get("last_trained"),
        "model_version": attack_classifier.version,
        "ready_to_train": len(texts) >= MIN_TRAINING_SAMPLES,
    }


@app.post("/v1/model/retrain-legacy-placeholder")
async def retrain_placeholder(config: RetrainConfig = RetrainConfig()):
    # Kept only for the demonstration opt-in; the real path is /v1/model/retrain.
    if os.environ.get("FORTRESSWAF_ALLOW_PLACEHOLDER_RETRAIN") != "1":
        raise HTTPException(
            status_code=501,
            detail=(
                "placeholder retraining disabled; set "
                "FORTRESSWAF_ALLOW_PLACEHOLDER_RETRAIN=1 to run the random-data "
                "warm-up for demonstration only"
            ),
        )

    logger.warning("placeholder retrain running on random data (demonstration only)")
    dummy_anomaly = np.random.randn(100, 38)
    anomaly_detector.partial_fit(dummy_anomaly)

    dummy_bot = np.random.randn(50, 30)
    dummy_labels = np.random.randint(0, 2, 50)
    bot_detector.train(dummy_bot, dummy_labels)

    dummy_risk = np.random.randn(50, 30)
    dummy_risk_labels = np.random.randint(0, 100, 50)
    risk_scorer.train(dummy_risk, dummy_risk_labels)

    MODEL_HEALTH.labels(model_name="anomaly").set(1)
    MODEL_HEALTH.labels(model_name="classifier").set(1)
    MODEL_HEALTH.labels(model_name="bot_detector").set(1)
    MODEL_HEALTH.labels(model_name="risk_scorer").set(1)

    return {
        "status": "success",
        "message": "placeholder retrain complete (random data, demonstration only)",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": {
            "anomaly_detector": f"{anomaly_detector.trained_samples} samples",
            "classifier": attack_classifier.version,
            "bot_detector": "trained",
            "risk_scorer": "trained",
        },
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.app:app", host="0.0.0.0", port=8000, reload=True)
