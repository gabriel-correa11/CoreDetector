import re
import unicodedata
from typing import List, Dict

class FraudAnalyzer:
    def __init__(self, pipeline):
        self.pipeline = pipeline

    def normalize(self, text: str) -> str:
        text = unicodedata.normalize("NFKC", text)
        text = "".join(ch for ch in text if unicodedata.category(ch)[0] != "C")
        return text.lower().strip()

    def get_risk(self, prob: float) -> str:
        if prob < 0.35: return "BAIXO"
        if prob < 0.75: return "MODERADO"
        return "ALTO"

    def extract_signals(self, text: str) -> List[str]:
        signals = []
        patterns = {
            r"bit\.ly|t\.co|wa\.me|cutt\.ly|tinyurl": "Link encurtado suspeito",
            r"urgente|bloqueio|imediatamente|expira|atencao": "Gatilho de urgencia",
            r"cpf|senha|token|chave|pix": "Solicitacao de dados sensiveis",
            r"parabens|ganhou|venceu|premio|sorteio": "Promessa de ganho",
            r"receita federal|gov\.br|banco|correios": "Uso de entidade oficial"
        }
        for pattern, description in patterns.items():
            if re.search(pattern, text):
                signals.append(description)
        return signals

    def analyze(self, raw_text: str) -> Dict:
        clean_text = self.normalize(raw_text)

        prob = self.pipeline.predict_proba([clean_text])[0][1]

        return {
            "text": clean_text,
            "risk_level": self.get_risk(prob),
            "fraud_probability": round(prob, 4),
            "is_fraud": prob > 0.5,
            "signals": self.extract_signals(clean_text),
            "analysis_version": "1.2.0"
        }