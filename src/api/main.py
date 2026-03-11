import os
import joblib
import json
import logging
import csv
from time import perf_counter

from fastapi import FastAPI, Header, HTTPException, Request, UploadFile, File
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from src.api.models import DetectionRequest
from src.core.image_processor import extract_text
from src.core.analyzer import FraudAnalyzer
from src.core.utils import DataMasker
from src.core.dashboard import get_dashboard
from src.bot.whatsapp import WPPConnectClient, WhatsAppHandler

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REGISTRY_PATH = os.path.join(PROJECT_ROOT, "models", "registry.json")

_ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp"}
_IMAGE_MAX_BYTES = 5 * 1024 * 1024


def _telegram_user_key(request: Request) -> str:
    uid = request.headers.get("X-Telegram-User-Id")
    return f"tg:{uid}" if uid else get_remote_address(request)


def _whatsapp_user_key(request: Request) -> str:
    uid = request.headers.get("X-Whatsapp-User-Id")
    return f"wa:{uid}" if uid else get_remote_address(request)


def load_production_model():
    with open(REGISTRY_PATH, "r") as f:
        registry = json.load(f)
    prod_model = next(m for m in registry if m["status"] == "production")
    return joblib.load(os.path.join(PROJECT_ROOT, prod_model["path"]))


pipeline = load_production_model()
analyzer = FraudAnalyzer(pipeline)
wpp_client = WPPConnectClient()
wa_handler = WhatsAppHandler(wpp_client, analyzer)

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
async def whatsapp_webhook(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    await wa_handler.handle_webhook(payload)
    return {"status": "ok"}


@app.post("/api/v1/detect/image")
@limiter.limit(os.getenv("RATE_LIMIT_IMAGE", "3/minute"), key_func=_telegram_user_key)
def detect_image(request: Request, file: UploadFile = File(...)):
    if file.content_type not in _ALLOWED_IMAGE_TYPES:
        raise HTTPException(status_code=415, detail=f"Unsupported media type: {file.content_type}")

    image_bytes = file.file.read()
    if len(image_bytes) > _IMAGE_MAX_BYTES:
        raise HTTPException(status_code=413, detail="Image exceeds 5MB limit")

    t_ocr = perf_counter()
    text = extract_text(image_bytes)
    ocr_ms = (perf_counter() - t_ocr) * 1000

    if not text:
        raise HTTPException(status_code=422, detail="No text could be extracted from the image")

    t_ml = perf_counter()
    result = analyzer.analyze(text)
    ml_ms = (perf_counter() - t_ml) * 1000

    logging.info(
        f"Image | Hash: {result['text_hash']} | Score: {result['final_risk_score']} | "
        f"Fraud: {result['is_fraud']} | Lookalikes: {result['look_alike_domains']} | "
        f"OCR: {ocr_ms:.2f}ms | ML: {ml_ms:.2f}ms | Latency: {ocr_ms + ml_ms:.2f}ms"
    )
    return {**result, "extracted_text": text}


@app.get("/api/v1/health/dashboard")
async def dashboard():
    return get_dashboard()


@app.post("/api/v1/feedback")
@limiter.limit(os.getenv("RATE_LIMIT_FEEDBACK", "10/minute"))
async def collect_feedback(
    request: Request, text: str, is_fraud: bool, x_admin_key: str = Header(None)
):
    if not x_admin_key or x_admin_key != os.getenv("ADMIN_API_KEY"):
        raise HTTPException(status_code=403, detail="Unauthorized")

    masked_text = DataMasker.mask_pii(text)
    file_path = os.path.join(PROJECT_ROOT, "data", "feedback.csv")

    with open(file_path, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([masked_text, 1 if is_fraud else 0])

    return {"status": "Feedback recorded"}
