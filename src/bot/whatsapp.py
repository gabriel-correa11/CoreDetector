import os
from twilio.twiml.messaging_response import MessagingResponse

AUTHORIZED_USERS = set(
    n.strip() for n in os.getenv("AUTHORIZED_USERS", "").split(",") if n.strip()
)

_SIGNAL_LABELS = {
    "Suspicious link or brand spoofing": "Link suspeito ou imitação de marca conhecida",
    "Hard urgency or threat tone": "Linguagem de urgência ou ameaça",
    "Direct financial request": "Solicitação de dados financeiros (Pix, senha, token)",
    "Legal pressure or fake subpoena bait": "Pressão jurídica falsa (processo, intimação)",
    "Brand impersonation via look-alike domain": "Domínio imitando uma marca oficial (possível golpe visual)",
}

_SEGURO_PROMPT = (
    "Se você conhece quem enviou e tem certeza de que a mensagem é legítima, "
    "responda: SEGURO"
)

_FOOTER_HIGH = (
    "Não clique em nenhum link e não forneça dados pessoais, senhas ou códigos.\n\n"
    + _SEGURO_PROMPT
)
_FOOTER_MEDIUM = (
    "Não aja por impulso. Confirme com a instituição pelo telefone oficial "
    "antes de clicar em qualquer link ou fornecer dados."
)
_FOOTER_LOW = "Mesmo assim, nunca forneça senhas ou códigos por mensagem."


def _format_signals(signals: list) -> str:
    if not signals:
        return ""
    lines = "\n".join(f"- {_SIGNAL_LABELS.get(s, s)}" for s in signals)
    return f"\n\nMotivos identificados:\n{lines}"


def _format_domains(suspicious_domains: list) -> str:
    if not suspicious_domains:
        return ""
    lines = "\n".join(f"- {d}" for d in suspicious_domains)
    return f"\n\nDomínios suspeitos encontrados:\n{lines}"


def build_whatsapp_response(risk_level: str, is_fraud: bool, signals: list, suspicious_domains: list) -> str:
    key = "HIGH" if is_fraud else risk_level
    signals_section = _format_signals(signals)
    domains_section = _format_domains(suspicious_domains)

    if key == "HIGH":
        body = f"ATENCAO: MENSAGEM PERIGOSA{signals_section}{domains_section}\n\n{_FOOTER_HIGH}"
    elif key == "MEDIUM":
        body = f"Atenção: Mensagem Suspeita{signals_section}{domains_section}\n\n{_FOOTER_MEDIUM}"
    else:
        body = f"Mensagem parece segura.\n\n{_FOOTER_LOW}"

    response = MessagingResponse()
    response.message(body)
    return str(response)


def build_feedback_ack() -> str:
    response = MessagingResponse()
    response.message("Registrado. Obrigado pelo aviso.")
    return str(response)


def build_unauthorized_response() -> str:
    response = MessagingResponse()
    response.message("Essa opção não está disponível para este número.")
    return str(response)


def is_authorized(phone_number: str) -> bool:
    return phone_number in AUTHORIZED_USERS
