import io
import logging
import os
import time
from collections import defaultdict, deque

import httpx
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

from .i18n import build_reply

logger = logging.getLogger(__name__)

API_URL = os.getenv("API_URL", "http://api:8000")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")

AUTHORIZED_USERS: set[int] = set(
    int(uid.strip())
    for uid in os.getenv("TELEGRAM_AUTHORIZED_USERS", "").split(",")
    if uid.strip().isdigit()
)

_RATE_LIMIT = int(os.getenv("RATE_LIMIT_TELEGRAM_USER", "10"))
_IMAGE_RATE_LIMIT = int(os.getenv("RATE_LIMIT_TELEGRAM_IMAGE", "3"))

_last_text: dict[int, str] = {}
_user_timestamps: dict[int, deque] = defaultdict(deque)
_image_timestamps: dict[int, deque] = defaultdict(deque)

_http_client = httpx.AsyncClient()


def _is_authorized(user_id: int) -> bool:
    return not AUTHORIZED_USERS or user_id in AUTHORIZED_USERS


def _is_rate_limited(user_id: int) -> bool:
    now = time.monotonic()
    dq = _user_timestamps[user_id]
    while dq and now - dq[0] > 60:
        dq.popleft()
    if len(dq) >= _RATE_LIMIT:
        return True
    dq.append(now)
    return False


def _is_image_rate_limited(user_id: int) -> bool:
    now = time.monotonic()
    dq = _image_timestamps[user_id]
    while dq and now - dq[0] > 60:
        dq.popleft()
    if len(dq) >= _IMAGE_RATE_LIMIT:
        return True
    dq.append(now)
    return False


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Encaminhe uma mensagem suspeita para análise.\n"
        "Forward a suspicious message for analysis."
    )


async def cmd_feedback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id

    if not _is_authorized(user_id):
        await update.message.reply_text("Acesso não autorizado. / Unauthorized.")
        return

    if _is_rate_limited(user_id):
        await update.message.reply_text(
            "Limite atingido. Tente novamente em 1 minuto. / Rate limit exceeded. Try again in 1 minute."
        )
        return

    text = _last_text.get(user_id)
    if not text:
        await update.message.reply_text(
            "Nenhuma mensagem analisada recentemente. / No recent message analyzed."
        )
        return

    try:
        resp = await _http_client.post(
            f"{API_URL}/api/v1/feedback",
            json={"text": text, "is_fraud": False},
            headers={"X-Admin-Key": ADMIN_API_KEY},
            timeout=10,
        )
    except httpx.HTTPError as exc:
        logger.error("Feedback request failed: %s", exc)
        await update.message.reply_text("Erro ao registrar feedback. / Feedback error.")
        return

    if resp.status_code == 200:
        await update.message.reply_text(
            "Falso positivo registrado. Obrigado! / False positive recorded. Thank you!"
        )
    else:
        logger.warning("Feedback API returned %d", resp.status_code)
        await update.message.reply_text("Erro ao registrar feedback. / Feedback error.")


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id

    if not _is_authorized(user_id):
        await update.message.reply_text("Acesso não autorizado. / Unauthorized.")
        return

    if _is_rate_limited(user_id):
        await update.message.reply_text(
            "Limite atingido. Tente novamente em 1 minuto. / Rate limit exceeded. Try again in 1 minute."
        )
        return

    text = " ".join(update.message.text.split())

    try:
        resp = await _http_client.post(
            f"{API_URL}/api/v1/detect",
            json={"text": text, "source": "telegram"},
            timeout=15,
        )
    except httpx.HTTPError as exc:
        logger.error("Detect request failed: %s", exc)
        await update.message.reply_text("Erro ao analisar mensagem. / Analysis error.")
        return

    if resp.status_code != 200:
        logger.warning("Detect API returned %d", resp.status_code)
        await update.message.reply_text("Erro ao analisar mensagem. / Analysis error.")
        return

    result = resp.json()
    _last_text[user_id] = text
    lang = result.get("language", "pt")
    await update.message.reply_text(build_reply(result, lang), parse_mode="HTML")


async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id

    if not _is_authorized(user_id):
        await update.message.reply_text("Acesso não autorizado. / Unauthorized.")
        return

    if _is_rate_limited(user_id):
        await update.message.reply_text(
            "Limite atingido. Tente novamente em 1 minuto. / Rate limit exceeded. Try again in 1 minute."
        )
        return

    if _is_image_rate_limited(user_id):
        await update.message.reply_text(
            "Limite de imagens atingido (máx. 3/min). / Image rate limit reached (max 3/min)."
        )
        return

    processing_msg = await update.message.reply_text(
        "Processando imagem... / Processing image..."
    )

    photo = update.message.photo[-1]
    buf = io.BytesIO()

    try:
        tg_file = await context.bot.get_file(photo.file_id)
        await tg_file.download_to_memory(buf)
    except Exception as exc:
        logger.error("Photo download failed: %s", exc)
        await processing_msg.edit_text(
            "Erro ao baixar a imagem. / Failed to download image."
        )
        return

    image_bytes = buf.getvalue()

    try:
        resp = await _http_client.post(
            f"{API_URL}/api/v1/detect/image",
            files={"file": ("photo.jpg", image_bytes, "image/jpeg")},
            headers={"X-Telegram-User-Id": str(user_id)},
            timeout=30,
        )
    except httpx.HTTPError as exc:
        logger.error("Image detect request failed: %s", exc)
        await processing_msg.edit_text(
            "Erro ao analisar imagem. / Image analysis error."
        )
        return

    if resp.status_code == 422:
        await processing_msg.edit_text(
            "Nenhum texto encontrado na imagem. / No text found in the image."
        )
        return

    if resp.status_code == 413:
        await processing_msg.edit_text(
            "Imagem muito grande (máx. 5MB). / Image too large (max 5MB)."
        )
        return

    if resp.status_code != 200:
        logger.warning("Image detect API returned %d", resp.status_code)
        await processing_msg.edit_text(
            "Erro ao analisar imagem. / Image analysis error."
        )
        return

    result = resp.json()
    lang = result.get("language", "pt")
    _last_text[user_id] = result.get("extracted_text", "")
    await processing_msg.edit_text(build_reply(result, lang), parse_mode="HTML")


def main() -> None:
    if not TELEGRAM_BOT_TOKEN:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not set")
    if not ADMIN_API_KEY:
        raise RuntimeError("ADMIN_API_KEY is not set")

    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("feedback", cmd_feedback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_handler(MessageHandler(filters.PHOTO, handle_photo))
    app.run_polling()
