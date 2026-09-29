import os
import sys
import json
from unittest.mock import patch, MagicMock, PropertyMock
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from api.app import app, anomaly_detector, attack_classifier, bot_detector, risk_scorer

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_metrics():
    import prometheus_client
    prometheus_client.REGISTRY.unregister(prometheus_client.REGISTRY._names_to_collectors.get("waf_requests_total", None))
    prometheus_client.REGISTRY.unregister(prometheus_client.REGISTRY._names_to_collectors.get("waf_request_latency_seconds", None))
    prometheus_client.REGISTRY.unregister(prometheus_client.REGISTRY._names_to_collectors.get("waf_anomaly_score", None))
    prometheus_client.REGISTRY.unregister(prometheus_client.REGISTRY._names_to_collectors.get("waf_bot_score", None))
    prometheus_client.REGISTRY.unregister(prometheus_client.REGISTRY._names_to_collectors.get("waf_risk_score", None))
    prometheus_client.REGISTRY.unregister(prometheus_client.REGISTRY._names_to_collectors.get("waf_model_health", None))
    yield


class TestHealthEndpoint:
    def test_health_check(self):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "models" in data
        assert "anomaly" in data["models"]
        assert "classifier" in data["models"]
        assert "bot_detector" in data["models"]
        assert "risk_scorer" in data["models"]

    def test_metrics_endpoint(self):
        response = client.get("/metrics")
        assert response.status_code == 200
        assert "text/plain" in response.headers["content-type"]


class TestInspectEndpoint:
    def test_inspect_valid_request(self):
        payload = {
            "method": "GET",
            "path": "/api/users",
            "headers": {
                "Host": "example.com",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html",
            },
            "body": None,
            "query_params": {"page": "1"},
            "source_ip": "192.168.1.1",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "content_type": "application/json",
        }
        response = client.post("/v1/inspect", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "anomaly_score" in data
        assert "is_anomaly" in data
        assert "attack_type" in data
        assert "attack_confidence" in data
        assert "bot_score" in data
        assert "risk_score" in data
        assert "fingerprint" in data
        assert "model_version" in data
        assert 0 <= data["anomaly_score"] <= 1
        assert 0 <= data["bot_score"] <= 1
        assert 0 <= data["risk_score"] <= 100

    def test_inspect_sqli_payload(self):
        payload = {
            "method": "POST",
            "path": "/login",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": "username=admin' OR '1'='1&password=test",
            "query_params": {},
            "source_ip": "10.0.0.1",
            "user_agent": "Mozilla/5.0",
            "content_type": "application/x-www-form-urlencoded",
        }
        response = client.post("/v1/inspect", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "anomaly_score" in data

    def test_inspect_xss_payload(self):
        payload = {
            "method": "GET",
            "path": "/search",
            "headers": {"User-Agent": "test"},
            "body": None,
            "query_params": {"q": "<script>alert('xss')</script>"},
            "source_ip": "10.0.0.2",
            "user_agent": "test",
            "content_type": None,
        }
        response = client.post("/v1/inspect", json=payload)
        assert response.status_code == 200

    def test_inspect_missing_fields(self):
        payload = {
            "method": "GET",
            "path": "/test",
        }
        response = client.post("/v1/inspect", json=payload)
        assert response.status_code == 422

    def test_inspect_empty_request(self):
        response = client.post("/v1/inspect", json={})
        assert response.status_code == 422


class TestClassifyEndpoint:
    def test_classify_sqli(self):
        payload = {"payload": "' OR '1'='1' --"}
        response = client.post("/v1/classify", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["attack_type"] in ["sql-injection", "no-attack"]
        assert 0 <= data["confidence"] <= 1
        assert "model_version" in data

    def test_classify_xss(self):
        payload = {"payload": "<script>alert(1)</script>"}
        response = client.post("/v1/classify", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "attack_type" in data
        assert "confidence" in data

    def test_classify_normal(self):
        payload = {"payload": "Hello, this is a normal request"}
        response = client.post("/v1/classify", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["attack_type"] in ATTACK_TYPES

    def test_classify_empty_payload(self):
        payload = {"payload": ""}
        response = client.post("/v1/classify", json=payload)
        assert response.status_code == 400

    def test_classify_with_context(self):
        payload = {"payload": "test", "context": {"source": "web", "endpoint": "/api"}}
        response = client.post("/v1/classify", json=payload)
        assert response.status_code == 200

    def test_classify_missing_payload(self):
        response = client.post("/v1/classify", json={})
        assert response.status_code == 422


class TestFingerprintEndpoint:
    def test_fingerprint_generation(self):
        payload = {
            "method": "GET",
            "path": "/api/users",
            "headers": {"Host": "example.com", "User-Agent": "Mozilla/5.0"},
            "user_agent": "Mozilla/5.0",
        }
        response = client.post("/v1/fingerprint", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "fingerprint" in data
        assert data["hash_algorithm"] == "SHA-256"
        assert len(data["fingerprint"]) == 64

    def test_fingerprint_deterministic(self):
        payload = {
            "method": "GET",
            "path": "/api/users",
            "headers": {"Host": "example.com", "User-Agent": "Mozilla/5.0"},
            "user_agent": "Mozilla/5.0",
        }
        r1 = client.post("/v1/fingerprint", json=payload).json()["fingerprint"]
        r2 = client.post("/v1/fingerprint", json=payload).json()["fingerprint"]
        assert r1 == r2

    def test_fingerprint_different_inputs(self):
        p1 = {"method": "GET", "path": "/a", "headers": {}, "user_agent": "ua1"}
        p2 = {"method": "POST", "path": "/b", "headers": {}, "user_agent": "ua2"}
        r1 = client.post("/v1/fingerprint", json=p1).json()["fingerprint"]
        r2 = client.post("/v1/fingerprint", json=p2).json()["fingerprint"]
        assert r1 != r2

    def test_fingerprint_missing_fields(self):
        response = client.post("/v1/fingerprint", json={"method": "GET"})
        assert response.status_code == 422

    def test_fingerprint_empty_headers(self):
        payload = {"method": "GET", "path": "/", "headers": {}, "user_agent": "test"}
        response = client.post("/v1/fingerprint", json=payload)
        assert response.status_code == 200


class TestBotScoreEndpoint:
    def test_bot_score_known_good(self):
        payload = {
            "user_agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "headers": {"User-Agent": "Googlebot", "Accept": "text/html"},
            "request_timing_ms": 500,
            "js_challenge_result": None,
            "accept_language": "en-US,en;q=0.9",
        }
        response = client.post("/v1/bot-score", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["is_bot"] is True
        assert data["bot_type"] == "known-good"
        assert data["bot_score"] == 0.0

    def test_bot_score_known_bad(self):
        payload = {
            "user_agent": "sqlmap/1.7.2 (http://sqlmap.org)",
            "headers": {"User-Agent": "sqlmap", "Accept": "*/*"},
            "request_timing_ms": 10,
            "js_challenge_result": None,
            "accept_language": "en-US,en;q=0.9",
        }
        response = client.post("/v1/bot-score", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["is_bot"] is True
        assert data["bot_type"] == "known-bad"
        assert data["bot_score"] >= 0.7

    def test_bot_score_human(self):
        payload = {
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "headers": {
                "User-Agent": "Mozilla/5.0...",
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
            },
            "request_timing_ms": 2500,
            "js_challenge_result": True,
            "accept_language": "en-US,en;q=0.9",
        }
        response = client.post("/v1/bot-score", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["bot_type"] == "unknown"

    def test_bot_score_missing_fields(self):
        response = client.post("/v1/bot-score", json={})
        assert response.status_code == 422

    def test_bot_score_fast_request(self):
        payload = {
            "user_agent": "Mozilla/5.0",
            "headers": {},
            "request_timing_ms": 5,
            "js_challenge_result": None,
            "accept_language": "en",
        }
        response = client.post("/v1/bot-score", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["is_bot"] is True
        assert data["bot_type"] == "known-bad"


class TestModelStatusEndpoint:
    def test_model_status(self):
        response = client.get("/v1/model/status")
        assert response.status_code == 200
        data = response.json()
        assert "model_version" in data
        assert "last_trained" in data
        assert "anomaly_model_loaded" in data
        assert "classifier_model_loaded" in data
        assert "bot_model_loaded" in data
        assert "risk_model_loaded" in data
        assert "total_samples_trained" in data

    def test_model_status_types(self):
        response = client.get("/v1/model/status")
        data = response.json()
        assert isinstance(data["anomaly_model_loaded"], bool)
        assert isinstance(data["classifier_model_loaded"], bool)
        assert isinstance(data["bot_model_loaded"], bool)
        assert isinstance(data["risk_model_loaded"], bool)
        assert isinstance(data["total_samples_trained"], int)


class TestRetrainEndpoint:
    # Retraining now runs against the on-disk corpus and only adopts a model
    # that scores at least as well as the incumbent. On a corpus too small to
    # judge, it refuses (422) rather than risk a worse model. The random-data
    # placeholder moved to /v1/model/retrain-legacy-placeholder.

    def test_retrain_refuses_on_small_corpus(self, tmp_path, monkeypatch):
        # Point the loader at an empty dir: too few samples to train.
        import api.app as appmod
        monkeypatch.setattr(appmod, "CORPUS_DIR", str(tmp_path / "empty"), raising=False)
        response = client.post("/v1/model/retrain")
        assert response.status_code == 422
        assert "samples" in response.json()["error"]

    def test_training_status_reports_corpus(self):
        response = client.get("/v1/model/training-status")
        assert response.status_code == 200
        data = response.json()
        assert "total_samples" in data
        assert "ready_to_train" in data
        assert "min_required" in data

    def test_retrain_invalid_config(self):
        payload = {"learning_rate": -1}
        response = client.post("/v1/model/retrain", json=payload)
        assert response.status_code == 422

    def test_placeholder_retrain_refused_by_default(self):
        response = client.post("/v1/model/retrain-legacy-placeholder")
        assert response.status_code == 501

    def test_body_size_limit_rejects_oversized(self):
        # Content-Length past the cap is refused before FastAPI parses it.
        response = client.post(
            "/v1/classify",
            content=b"{}",
            headers={"Content-Length": str(20 * 1024 * 1024)},
        )
        assert response.status_code == 413


class TestErrorHandling:
    def test_404(self):
        response = client.get("/nonexistent")
        assert response.status_code == 404

    def test_malformed_json(self):
        response = client.post(
            "/v1/inspect",
            data="not json",
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 422

    def test_cors_headers(self):
        response = client.options(
            "/v1/inspect",
            headers={
                "Origin": "http://example.com",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers


ATTACK_TYPES = [
    "sql-injection", "xss", "rce", "path-traversal", "ssrf", "lfi",
    "command-injection", "ssti", "ldap-injection", "xxe", "deserialization",
    "csrf", "open-redirect", "webshell", "crypto-failure", "no-attack",
]


class TestModelsDirectly:
    def test_anomaly_detector_score_range(self):
        request_data = {
            "method": "GET",
            "path": "/",
            "headers": {"Host": "example.com"},
            "body": None,
            "query_params": {},
        }
        score = anomaly_detector.score(request_data)
        assert 0 <= score <= 1

    def test_classifier_returns_valid_type(self):
        for attack in ["sql-injection", "xss", "rce", "normal"]:
            payloads = {
                "sql-injection": "' OR '1'='1",
                "xss": "<script>alert(1)</script>",
                "rce": "| cat /etc/passwd",
                "normal": "Hello, this is normal",
            }
            attack_type, confidence = attack_classifier.predict(payloads[attack])
            assert attack_type in ATTACK_TYPES
            assert 0 <= confidence <= 1

    def test_bot_detector_classify(self):
        score, is_bot, bot_type = bot_detector.classify(
            user_agent="Googlebot/2.1",
            headers={},
            request_timing_ms=500,
            accept_language="en",
        )
        assert is_bot is True
        assert bot_type == "known-good"
        assert score == 0.0

    def test_bot_detector_bad_bot(self):
        score, is_bot, bot_type = bot_detector.classify(
            user_agent="sqlmap/1.7",
            headers={},
            request_timing_ms=1,
            accept_language="en",
        )
        assert is_bot is True
        assert bot_type == "known-bad"
        assert score >= 0.7

    def test_risk_scorer_range(self):
        score, details = risk_scorer.score("test_session")
        assert 0 <= score <= 100
        assert isinstance(details, dict)
        assert "impossible_travel" in details
        assert "ato_detected" in details

    def test_risk_scorer_at_high_failures(self):
        for i in range(15):
            risk_scorer.record_request(
                session_id="ato_test",
                endpoint="/login",
                method="POST",
                status_code=401 if i < 10 else 200,
                anomaly_score=0.5,
                is_auth=True,
                success=False,
            )
        score, details = risk_scorer.score("ato_test")
        assert score > 20

    def test_fingerprint_uniqueness(self):
        from training.feature_engineering import compute_request_fingerprint
        fp1 = compute_request_fingerprint("GET", "/api/users", {"Host": "a.com"}, "Mozilla/5.0")
        fp2 = compute_request_fingerprint("POST", "/api/users", {"Host": "a.com"}, "Mozilla/5.0")
        assert fp1 != fp2

    def test_feature_extraction(self):
        from training.feature_engineering import extract_http_features
        features = extract_http_features("GET", "/etc/passwd", {}, None, {})
        assert len(features) > 0
        assert isinstance(features, np.ndarray)
        assert features.dtype == np.float64

    def test_entropy_computation(self):
        from training.feature_engineering import compute_entropy
        e1 = compute_entropy("aaaa")
        e2 = compute_entropy("abcdefgh")
        assert e2 > e1

    def test_tokenize_payload(self):
        from training.feature_engineering import tokenize_payload
        tokens = tokenize_payload("SELECT * FROM users WHERE id=1")
        assert len(tokens) > 0
        assert any("select" in t.lower() for t in tokens)


if __name__ == "__main__":
    pytest.main(["-v", __file__])
