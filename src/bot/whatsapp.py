import asyncio
import base64
import logging
import os
from collections import defaultdict, deque
from time import monotonic
from typing import Optional

import httpx

from src.core.analyzer import FraudAnalyzer
from src.core.image_processor import extract_text

logger = logging.getLogger(__name__)

_WPP_BASE_URL = os.getenv("WPP_BASE_URL", "http://wppconnect:21465")
_WPP_SESSION = os.getenv("WPP_SESSION", "default")
_WPP_AUTH_TOKEN = os.getenv("WPP_AUTH_TOKEN", "")

_RATE_LIMIT = int(os.getenv("RATE_LIMIT_WHATSAPP_USER", "10"))
_IMAGE_RATE_LIMIT = int(os.getenv("RATE_LIMIT_WHATSAPP_IMAGE", "3"))
_IMAGE_MAX_BYTES = 5 * 1024 * 1024
_RETRY_ATTEMPTS = 3
_RETRY_BACKOFF = (0.5, 1.0)

AUTHORIZED_USERS: set[str] = set(
    n.strip()
    for n in os.getenv("WA_AUTHORIZED_USERS", "").split(",")
    if n.strip()
)

_user_timestamps: dict[str, deque] = defaultdict(deque)
_image_timestamps: dict[str, deque] = defaultdict(deque)
_last_hash: dict[str, str] = {}

_SIGNAL_LABELS = {
    "Suspicious link or brand spoofing": "Link suspeito ou imitação de marca conhecida",
    "Hard urgency or threat tone": "Linguagem de urgência ou ameaça",
    "Direct financial request": "Solicitação de dados financeiros (Pix, senha, token)",
    "Legal pressure or fake subpoena bait": "Pressão jurídica falsa (processo, intimação)",
    "Brand impersonation via look-alike domain": "Domínio imitando uma marca oficial (possível golpe visual)",
}

_FOOTER_HIGH = (
    "Não clique em nenhum link e não forneça dados pessoais, senhas ou códigos.\n\n"
    "Se você conhece quem enviou e tem certeza de que a mensagem é legítima, responda: SEGURO"
)
_FOOTER_MEDIUM = (
    "Não aja por impulso. Confirme com a instituição pelo telefone oficial "
    "antes de clicar em qualquer link ou fornecer dados."
)
_FOOTER_LOW = "Mesmo assim, nunca forneça senhas ou códigos por mensagem."


def is_authorized(phone_id: str) -> bool:
    return not AUTHORIZED_USERS or phone_id in AUTHORIZED_USERS


def _is_rate_limited(phone_id: str) -> bool:
    now = monotonic()
    dq = _user_timestamps[phone_id]
    while dq and now - dq[0] > 60:
        dq.popleft()
    if len(dq) >= _RATE_LIMIT:
        return True
    dq.append(now)
    return False


def _is_image_rate_limited(phone_id: str) -> bool:
    now = monotonic()
    dq = _image_timestamps[phone_id]
    while dq and now - dq[0] > 60:
        dq.popleft()
    if len(dq) >= _IMAGE_RATE_LIMIT:
        return True
    dq.append(now)
    return False


def _build_reply(result: dict) -> str:
    key = "HIGH" if result["is_fraud"] else result["risk_level"]
    signals = result.get("signals", [])
    domains = list(
        dict.fromkeys(
            result.get("suspicious_domains", []) + result.get("look_alike_domains", [])
        )
    )

    signal_section = (
        "\n\nMotivos identificados:\n" + "\n".join(f"- {_SIGNAL_LABELS.get(s, s)}" for s in signals)
        if signals
        else ""
    )
    domain_section = (
        "\n\nDomínios suspeitos:\n" + "\n".join(f"- {d}" for d in domains)
        if domains
        else ""
    )

    if key == "HIGH":
        return f"ATENCAO: MENSAGEM PERIGOSA{signal_section}{domain_section}\n\n{_FOOTER_HIGH}"
    if key == "MEDIUM":
        return f"Atenção: Mensagem Suspeita{signal_section}{domain_section}\n\n{_FOOTER_MEDIUM}"
    return f"Mensagem parece segura.{signal_section}{domain_section}\n\n{_FOOTER_LOW}"


class WPPConnectClient:
    def __init__(self) -> None:
        self._base = _WPP_BASE_URL.rstrip("/")
        self._session = _WPP_SESSION
        self._headers = {
            "Authorization": f"Bearer {_WPP_AUTH_TOKEN}",
            "Content-Type": "application/json",
        }
        self._client = httpx.AsyncClient(timeout=15.0)

    async def _request_with_retry(
        self, method: str, url: str, **kwargs
    ) -> Optional[httpx.Response]:
        for attempt in range(_RETRY_ATTEMPTS):
            try:
                resp = await self._client.request(
                    method, url, headers=self._headers, **kwargs
                )
                if resp.status_code < 500:
                    return resp
                logger.warning(
                    "WPPConnect %s %s attempt %d/%d returned %d",
                    method, url, attempt + 1, _RETRY_ATTEMPTS, resp.status_code,
                )
            except httpx.HTTPError as exc:
                logger.warning(
                    "WPPConnect %s %s attempt %d/%d failed: %s",
                    method, url, attempt + 1, _RETRY_ATTEMPTS, exc,
                )
            if attempt < _RETRY_ATTEMPTS - 1:
                await asyncio.sleep(_RETRY_BACKOFF[attempt])
        logger.error(
            "WPPConnect %s %s exhausted %d retries", method, url, _RETRY_ATTEMPTS
        )
        return None

    async def send_message(self, to: str, text: str) -> None:
        url = f"{self._base}/api/{self._session}/send-message"
        resp = await self._request_with_retry(
            "POST", url, json={"phone": to, "message": text, "isGroup": False}
        )
        if resp is not None and resp.status_code >= 400:
            logger.error(
                "WPPConnect send-message %d for %s: %s",
                resp.status_code, to, resp.text[:200],
            )

    async def get_media_bytes(self, message_id: str) -> Optional[bytes]:
        url = f"{self._base}/api/{self._session}/get-media-by-message/{message_id}"
        resp = await self._request_with_retry("GET", url)
        if resp is None:
            return None
        if resp.status_code == 404:
            logger.warning("WPPConnect media not found: %s", message_id)
            return None
        if resp.status_code != 200:
            logger.error("WPPConnect get-media %d for %s", resp.status_code, message_id)
            return None

        data = resp.json()
        raw = (
            data.get("base64")
            or data.get("data", {}).get("base64", "")
            or data.get("response", {}).get("base64", "")
        )
        if not raw:
            return None
        if "," in raw:
            raw = raw.split(",", 1)[1]
        try:
            return base64.b64decode(raw)
        except Exception as exc:
            logger.error("WPPConnect base64 decode failed for %s: %s", message_id, exc)
            return None


class WhatsAppHandler:
    def __init__(self, client: WPPConnectClient, analyzer: FraudAnalyzer) -> None:
        self._client = client
        self._analyzer = analyzer

    async def handle_webhook(self, payload: dict) -> None:
        if payload.get("event") != "onmessage":
            return

        data = payload.get("data", {})
        sender: str = data.get("from", "")
        if not sender:
            return

        if not is_authorized(sender):
            await self._client.send_message(sender, "Acesso não autorizado.")
            return

        msg_type: str = data.get("type", "chat")
        has_media: bool = data.get("hasMedia", False)
        message_id: str = (data.get("id") or {}).get("id", "")

        if has_media and msg_type in {"image", "document"}:
            await self._handle_media(sender, message_id)
        elif msg_type == "chat":
            body: str = data.get("body", "").strip()
            if not body:
                return
            if body.upper() == "SEGURO":
                await self._handle_false_positive(sender)
            else:
                await self._handle_text(sender, body)
        else:
            logger.debug(
                "Ignoring WPPConnect message type=%s from X-Whatsapp-User-Id=%s",
                msg_type, sender,
            )

    async def _handle_text(self, sender: str, text: str) -> None:
        if _is_rate_limited(sender):
            await self._client.send_message(
                sender, "Limite atingido. Tente novamente em 1 minuto."
            )
            return

        result = self._analyzer.analyze(text)
        _last_hash[sender] = result["text_hash"]
        logger.info(
            "WhatsApp | X-Whatsapp-User-Id: %s | Hash: %s | Score: %s | Fraud: %s | Lookalikes: %s",
            sender, result["text_hash"], result["final_risk_score"],
            result["is_fraud"], result["look_alike_domains"],
        )
        await self._client.send_message(sender, _build_reply(result))

    async def _handle_media(self, sender: str, message_id: str) -> None:
        if _is_rate_limited(sender):
            await self._client.send_message(
                sender, "Limite atingido. Tente novamente em 1 minuto."
            )
            return

        if _is_image_rate_limited(sender):
            await self._client.send_message(
                sender, "Limite de imagens atingido (máx. 3/min)."
            )
            return

        image_bytes = await self._client.get_media_bytes(message_id)
        if not image_bytes:
            await self._client.send_message(
                sender, "Não foi possível processar a mídia."
            )
            return

        if len(image_bytes) > _IMAGE_MAX_BYTES:
            await self._client.send_message(sender, "Imagem muito grande (máx. 5MB).")
            return

        text = extract_text(image_bytes)
        if not text:
            await self._client.send_message(
                sender, "Nenhum texto encontrado na imagem."
            )
            return

        result = self._analyzer.analyze(text)
        _last_hash[sender] = result["text_hash"]
        logger.info(
            "WhatsApp Image | X-Whatsapp-User-Id: %s | Hash: %s | Score: %s | Fraud: %s | Lookalikes: %s",
            sender, result["text_hash"], result["final_risk_score"],
            result["is_fraud"], result["look_alike_domains"],
        )
        await self._client.send_message(sender, _build_reply(result))

    async def _handle_false_positive(self, sender: str) -> None:
        last = _last_hash.get(sender, "unknown")
        logger.warning(
            "False positive reported | Hash: %s | X-Whatsapp-User-Id: %s", last, sender
        )
        await self._client.send_message(sender, "Registrado. Obrigado pelo aviso.")
