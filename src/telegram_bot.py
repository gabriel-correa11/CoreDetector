from .telegram.bot import (  # noqa: F401
    ADMIN_API_KEY,
    AUTHORIZED_USERS,
    TELEGRAM_BOT_TOKEN,
    _IMAGE_RATE_LIMIT,
    _http_client,
    _image_timestamps,
    _is_authorized,
    _is_image_rate_limited,
    _is_rate_limited,
    _last_text,
    _user_timestamps,
    cmd_feedback,
    cmd_start,
    handle_message,
    handle_photo,
    main,
)
from .telegram.i18n import build_reply as _build_reply  # noqa: F401


def _build_pt(result: dict) -> str:
    return _build_reply(result, "pt")


def _build_en(result: dict) -> str:
    return _build_reply(result, "en")
