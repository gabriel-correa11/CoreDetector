import html

_SIGNAL_LABELS_PT = {
    "Suspicious link or brand spoofing": "Link suspeito ou imitação de marca conhecida",
    "Hard urgency or threat tone": "Linguagem de urgência ou ameaça",
    "Direct financial request": "Solicitação de dados financeiros (Pix, senha, token)",
    "Legal pressure or fake subpoena bait": "Pressão jurídica falsa (processo, intimação)",
    "Brand impersonation via look-alike domain": "Domínio imitando uma marca oficial",
}

_RISK_PT = {"LOW": "BAIXO", "MEDIUM": "MÉDIO", "HIGH": "ALTO"}

_STRINGS = {
    "pt": {
        "title": "Análise de Segurança",
        "verdict_label": "Veredito",
        "verdict_fraud": "FRAUDE DETECTADA",
        "verdict_safe": "MENSAGEM SEGURA",
        "risk_label": "Nível de Risco",
        "signals_label": "Motivos Identificados",
        "domains_label": "Domínios Suspeitos",
        "feedback_hint": "Use /feedback se esta análise estiver incorreta.",
    },
    "en": {
        "title": "Security Analysis",
        "verdict_label": "Verdict",
        "verdict_fraud": "FRAUD DETECTED",
        "verdict_safe": "SAFE MESSAGE",
        "risk_label": "Risk Level",
        "signals_label": "Detected Signals",
        "domains_label": "Suspicious Domains",
        "feedback_hint": "Use /feedback to report an incorrect analysis.",
    },
}


def build_reply(result: dict, lang: str) -> str:
    s = _STRINGS.get(lang, _STRINGS["en"])
    risk = _RISK_PT.get(result["risk_level"], result["risk_level"]) if lang == "pt" else result["risk_level"]
    score = int(result["final_risk_score"] * 100)
    verdict = s["verdict_fraud"] if result["is_fraud"] else s["verdict_safe"]
    domains = list(dict.fromkeys(result["suspicious_domains"] + result["look_alike_domains"]))

    lines = [
        f"<b>{s['title']}</b>",
        "",
        f"{s['verdict_label']}: <b>{verdict}</b>",
        f"{s['risk_label']}: <b>{risk}</b> ({score}%)",
    ]

    if result["signals"]:
        lines += ["", f"<b>{s['signals_label']}:</b>"]
        for sig in result["signals"]:
            label = _SIGNAL_LABELS_PT.get(sig, sig) if lang == "pt" else sig
            lines.append(f"- {html.escape(label)}")

    if domains:
        lines += ["", f"<b>{s['domains_label']}:</b>"]
        for d in domains:
            lines.append(f"- {html.escape(d)}")

    lines += ["", s["feedback_hint"]]
    return "\n".join(lines)
