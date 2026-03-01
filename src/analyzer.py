import re
import unicodedata
import hashlib
import tldextract
from typing import List, Dict
from langdetect import detect as _langdetect, DetectorFactory
from langdetect.lang_detect_exception import LangDetectException

DetectorFactory.seed = 0

WHITELISTED_DOMAINS = {
    "apple.com",
    "google.com",
    "microsoft.com",
}

_LOOK_ALIKE_THRESHOLD = 0.80

_LEET_TABLE = str.maketrans({
    '0': 'o', '1': 'i', '3': 'e', '4': 'a',
    '5': 's', '6': 'b', '7': 't', '9': 'g',
    '@': 'a', '$': 's', '!': 'i', '+': 't',
})

_URL_PATTERN = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')

_DOMAIN_PATTERN = re.compile(
    r'(?:https?://)?(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,6}(?:/[^\s<>"{}|\\^`\[\]]*)?'
)


def _detect_language(text: str) -> str:
    try:
        return _langdetect(text)
    except LangDetectException:
        return "pt"


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    prev = list(range(len(s2) + 1))
    for c1 in s1:
        curr = [prev[0] + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[-1] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def _levenshtein_similarity(s1: str, s2: str) -> float:
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    return 1.0 - _levenshtein(s1, s2) / max_len


class FraudAnalyzer:
    def __init__(self, pipeline):
        self.pipeline = pipeline

    @staticmethod
    def normalize(text: str) -> str:
        text = unicodedata.normalize("NFKC", text)
        text = "".join(ch for ch in text if unicodedata.category(ch)[0] != "C")
        return text.lower().strip()

    @staticmethod
    def deobfuscate(text: str) -> str:
        return text.translate(_LEET_TABLE)

    @staticmethod
    def extract_signals(text: str) -> List[str]:
        signals = []
        patterns = {
            r"jadiog|cutt\.ly|bit\.ly|rastreiosimediato\.com": "Suspicious link or brand spoofing",
            r"suspenso|irregular|bloqueio|bloquead|imediatamente|suspended|urgent|unauthorized|unusual\s+activity|account\s+locked|expire": "Hard urgency or threat tone",
            r"pix|transferencia|token|senha|wire\s+transfer|zelle|routing\s+number|ssn|social\s+security": "Direct financial request",
            r"ajuizamento|audiencia|protocolado|processo|coren|irs|lawsuit|subpoena": "Legal pressure or fake subpoena bait",
        }
        for pattern, description in patterns.items():
            if re.search(pattern, text):
                signals.append(description)
        return signals

    @staticmethod
    def _extract_suspicious_domains(text: str) -> List[str]:
        seen = set()
        domains = []
        for match in _DOMAIN_PATTERN.findall(text):
            ext = tldextract.extract(match)
            if ext.domain and ext.suffix:
                registered = f"{ext.domain}.{ext.suffix}"
                if registered not in WHITELISTED_DOMAINS and registered not in seen:
                    seen.add(registered)
                    domains.append(registered)
        return domains

    @staticmethod
    def _find_lookalike_domains(text: str) -> List[str]:
        lookalikes = []
        seen = set()
        for match in _DOMAIN_PATTERN.findall(text):
            ext = tldextract.extract(match)
            if not ext.domain or not ext.suffix:
                continue
            registered = f"{ext.domain}.{ext.suffix}"
            if registered in WHITELISTED_DOMAINS or registered in seen:
                continue
            deobfuscated_part = ext.domain.translate(_LEET_TABLE)
            for whitelisted in WHITELISTED_DOMAINS:
                wl_domain = whitelisted.split(".")[0]
                if deobfuscated_part == wl_domain:
                    seen.add(registered)
                    lookalikes.append(registered)
                    break
                if _levenshtein_similarity(ext.domain, wl_domain) >= _LOOK_ALIKE_THRESHOLD:
                    seen.add(registered)
                    lookalikes.append(registered)
                    break
        return lookalikes

    @staticmethod
    def _is_whitelisted_domain(text: str) -> bool:
        for url in _URL_PATTERN.findall(text):
            ext = tldextract.extract(url)
            if ext.domain and ext.suffix:
                registered = f"{ext.domain}.{ext.suffix}"
                if registered in WHITELISTED_DOMAINS:
                    return True
        return False

    def analyze(self, raw_text: str) -> Dict:
        clean_text = self.normalize(raw_text)
        deobfuscated = self.deobfuscate(clean_text)

        prob = self.pipeline.predict_proba([deobfuscated])[0][1]
        signals = self.extract_signals(deobfuscated)

        look_alike_domains = self._find_lookalike_domains(clean_text)
        if look_alike_domains:
            signals.append("Brand impersonation via look-alike domain")

        is_official_domain = self._is_whitelisted_domain(clean_text)
        is_fraud_decision = (
            prob > 0.4 or len(signals) >= 2 or bool(look_alike_domains)
        ) and not is_official_domain

        if is_fraud_decision:
            final_score = max(prob, 0.91)
        elif is_official_domain and prob < 0.5:
            final_score = min(prob, 0.20)
        else:
            final_score = prob

        if final_score < 0.3:
            risk = "LOW"
        elif final_score < 0.6:
            risk = "MEDIUM"
        else:
            risk = "HIGH"

        return {
            "text_hash": hashlib.sha256(clean_text.encode()).hexdigest(),
            "risk_level": risk,
            "statistical_probability": round(prob, 4),
            "final_risk_score": round(final_score, 4),
            "is_fraud": is_fraud_decision,
            "signals": signals,
            "suspicious_domains": self._extract_suspicious_domains(clean_text),
            "look_alike_domains": look_alike_domains,
            "language": _detect_language(clean_text),
            "analysis_version": "2.0.0",
        }
