from fastapi import FastAPI
import joblib
import os
from .models import DetectionRequest, DetectionResponse
from .analyzer import FraudAnalyzer

app = FastAPI()

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)

model_path = os.path.join(PROJECT_ROOT, "models", "phishing_model_pt.joblib")

if not os.path.exists(model_path):
    raise FileNotFoundError(f"Modelo nao encontrado em: {model_path}")

pipeline = joblib.load(model_path)
analyzer = FraudAnalyzer(pipeline)

@app.post("/api/v1/detect", response_model=DetectionResponse)
async def detect(request: DetectionRequest):
    return analyzer.analyze(request.text)