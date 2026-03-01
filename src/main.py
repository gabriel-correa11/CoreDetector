import os
import joblib
import json
import logging
import csv
from collections import defaultdict
from time import perf_counter

from fastapi import FastAPI, Header, HTTPException, Form, Response, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from src.models import DetectionRequest
from src.analyzer import FraudAnalyzer
from src.utils import DataMasker
from src.dashboard import get_dashboard
from src.whatsapp import (
    build_whatsapp_response,
    build_feedback_ack,
    build_unauthorized_response,
    is_authorized,
)

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_PATH = os.path.join(PROJECT_ROOT, "models", "registry.json")

_last_hash: dict = {}


def load_production_model():
    with open(REGISTRY_PATH, "r") as f:
        registry = json.load(f)
    prod_model = next(m for m in registry if m["status"] == "production")
    return joblib.load(os.path.join(PROJECT_ROOT, prod_model["path"]))


pipeline = load_production_model()
analyzer = FraudAnalyzer(pipeline)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename=os.path.join(PROJECT_ROOT, "logs", "api_audit.log"),
)


@app.post("/api/v1/detect")
@limiter.limit(os.getenv("RATE_LIMIT_DETECT", "10/minute"))
async def detect(request: Request, body: DetectionRequest):
    t0 = perf_counter()
    result = analyzer.analyze(body.text)
    ms = (perf_counter() - t0) * 1000
    logging.info(
        f"Hash: {result['text_hash']} | Score: {result['final_risk_score']} | "
        f"Fraud: {result['is_fraud']} | Lookalikes: {result['look_alike_domains']} | Latency: {ms:.2f}ms"
    )
    return result


@app.post("/webhook/whatsapp")
async def whatsapp_webhook(Body: str = Form(default=""), From: str = Form(default="")):
    body_clean = Body.strip()

    if body_clean.upper() == "SEGURO":
        if not is_authorized(From):
            return Response(content=build_unauthorized_response(), media_type="application/xml")
        last_hash = _last_hash.get(From, "unknown")
        logging.warning(f"False positive reported | Hash: {last_hash}")
        return Response(content=build_feedback_ack(), media_type="application/xml")

    t0 = perf_counter()
    result = analyzer.analyze(body_clean)
    ms = (perf_counter() - t0) * 1000
    _last_hash[From] = result["text_hash"]
    logging.info(
        f"WhatsApp | Hash: {result['text_hash']} | Score: {result['final_risk_score']} | "
        f"Fraud: {result['is_fraud']} | Lookalikes: {result['look_alike_domains']} | Latency: {ms:.2f}ms"
    )
    twiml = build_whatsapp_response(
        result["risk_level"], result["is_fraud"], result["signals"], result["suspicious_domains"]
    )
    return Response(content=twiml, media_type="application/xml")


@app.get("/api/v1/health/dashboard")
async def dashboard():
    return get_dashboard()


@app.post("/api/v1/feedback")
@limiter.limit(os.getenv("RATE_LIMIT_FEEDBACK", "10/minute"))
async def collect_feedback(
    request: Request, text: str, is_fraud: bool, x_admin_key: str = Header(None)
):
    if x_admin_key != os.getenv("ADMIN_API_KEY"):
        raise HTTPException(status_code=403, detail="Unauthorized")

    masked_text = DataMasker.mask_pii(text)
    file_path = os.path.join(PROJECT_ROOT, "data", "feedback.csv")

    with open(file_path, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([masked_text, 1 if is_fraud else 0])

    return {"status": "Feedback recorded"}
