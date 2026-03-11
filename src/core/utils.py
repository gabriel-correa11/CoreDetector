import re


class DataMasker:
    _CPF = re.compile(r'\d{3}\.\d{3}\.\d{3}-\d{2}|\b\d{11}\b')
    _EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
    _PHONE = re.compile(r'\(?\d{2}\)?\s?\d{4,5}-?\d{4}')
    _CEP = re.compile(r'\b\d{5}-\d{3}\b')
    _DATE = re.compile(r'\b\d{2}/\d{2}/\d{4}\b')
    _RG = re.compile(r'\b\d{1,2}\.?\d{3}\.?\d{3}-?\d{1}\b')
    _NAME = re.compile(
        r'\b[A-ZÁÉÍÓÚÀÂÊÔÃÕÇ][a-záéíóúàâêôãõç]{1,}'
        r'(?:\s+(?:d[aeo]s?\s+)?[A-ZÁÉÍÓÚÀÂÊÔÃÕÇ][a-záéíóúàâêôãõç]{1,}){1,3}\b'
    )

    @staticmethod
    def mask_pii(text: str) -> str:
        text = DataMasker._CPF.sub('[CPF]', text)
        text = DataMasker._EMAIL.sub('[EMAIL]', text)
        text = DataMasker._PHONE.sub('[PHONE]', text)
        text = DataMasker._CEP.sub('[CEP]', text)
        text = DataMasker._DATE.sub('[DATA]', text)
        text = DataMasker._RG.sub('[RG]', text)
        text = DataMasker._NAME.sub('[NOME]', text)
        return text
