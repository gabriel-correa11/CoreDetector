from pydantic import BaseModel
from typing import List


class DetectionRequest(BaseModel):
    text: str
    source: str


class DetectionResponse(BaseModel):
    text: str
    risk_level: str
    fraud_probability: float
    is_fraud: bool
    signals: List[str]
    analysis_version: str
