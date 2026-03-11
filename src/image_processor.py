import io
import re
import unicodedata

import pytesseract
from PIL import Image, UnidentifiedImageError

_MAX_PIXELS = 4096 * 4096
Image.MAX_IMAGE_PIXELS = _MAX_PIXELS

_CONTROL_CHARS_RE = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f"
    r"\u200b\u200c\u200d\u200e\u200f"
    r"\u202a\u202b\u202c\u202d\u202e"
    r"\ufeff]"
)


def _sanitize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = _CONTROL_CHARS_RE.sub("", text)
    return " ".join(text.split())


def extract_text(image_bytes: bytes) -> str:
    try:
        image = Image.open(io.BytesIO(image_bytes))
    except (Image.DecompressionBombError, UnidentifiedImageError, Exception):
        return ""

    try:
        raw = pytesseract.image_to_string(
            image, lang="por+eng", config="--psm 6", timeout=15
        )
    except (RuntimeError, pytesseract.TesseractError):
        return ""

    return _sanitize(raw)
