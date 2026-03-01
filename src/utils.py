import re

class DataMasker:
    @staticmethod
    def mask_pii(text: str) -> str:
        text = re.sub(r'\d{3}\.\d{3}\.\d{3}-\d{2}|\d{11}', '[CPF]', text)
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]', text)
        text = re.sub(r'\(?\d{2}\)?\s?\d{4,5}-?\d{4}', '[PHONE]', text)
        return text