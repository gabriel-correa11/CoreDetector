<div align="center">

# CoreDetector

**Real-time phishing detection engine — hybrid ML + heuristics, production-ready**

[![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-green?logo=fastapi)](https://fastapi.tiangolo.com)
[![LightGBM](https://img.shields.io/badge/LightGBM-ML_Engine-orange)](https://lightgbm.readthedocs.io)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue?logo=docker)](https://docker.com)
[![Tests](https://img.shields.io/badge/Tests-131_passing-brightgreen)]()
[![License](https://img.shields.io/badge/License-MIT-lightgrey)]()

[English](#english) · [Português](#português)

</div>

---

<a name="english"></a>
# English

## What is CoreDetector?

CoreDetector is a production-grade REST API that detects phishing messages in real time. It combines a **LightGBM machine learning model** with a **deterministic heuristics engine** to deliver fast, explainable fraud verdicts — not just a "yes or no", but a full breakdown of *why* a message is suspicious.

Built to protect real people from WhatsApp scams, fake government notices, look-alike banking domains, and social engineering attacks in both Brazilian Portuguese and English.

---

## How it works

Every message goes through a 4-stage pipeline:

```
Raw text
   │
   ├── 1. Unicode Normalization (NFKC)
   ├── 2. De-obfuscation   (leet table: 0→o, 1→i, 3→e, @→a ...)
   ├── 3. Signal Extraction (regex heuristics — PT-BR + EN-US)
   │       ├── Suspicious links / brand spoofing
   │       ├── Hard urgency or threat tone
   │       ├── Direct financial request (CPF, PIX, password)
   │       └── Legal pressure / fake subpoena
   └── 4. LightGBM (TF-IDF ngram 1–2 → probability score)

Decision:
   is_fraud = (prob > 0.4 OR signals >= 2 OR look-alike domain) AND NOT official domain

   fraud      → final_score = max(prob, 0.91)
   official   → final_score = min(prob, 0.20)
   default    → final_score = prob

   LOW < 0.30 · MEDIUM < 0.60 · HIGH ≥ 0.60
```

### Look-alike Domain Detection (Levenshtein)

Attackers often register domains like `g00gle.net` or `micros0ft-secure.com` to impersonate trusted brands. CoreDetector:

1. **De-obfuscates** the domain (`g00gle` → `google`)
2. Computes **Levenshtein similarity** against a whitelist of official domains
3. Flags any domain with similarity **≥ 0.80** as `Brand impersonation via look-alike domain`

This catches evasion attempts that defeat pure ML models.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/detect` | Analyze a message for phishing |
| `POST` | `/api/v1/feedback` | Report a false positive (requires `X-Admin-Key`) |
| `GET` | `/api/v1/health/dashboard` | 24h aggregated stats |

### Example Request

```bash
curl -X POST http://localhost:8000/api/v1/detect \
  -H "Content-Type: application/json" \
  -d '{"text": "URGENT: Your CPF was flagged. Regularize now: gov-regulariza.online/cpf", "source": "api"}'
```

### Example Response

```json
{
  "risk_level": "HIGH",
  "final_risk_score": 0.9998,
  "is_fraud": true,
  "signals": [
    "Hard urgency or threat tone",
    "Direct financial request"
  ],
  "suspicious_domains": ["gov-regulariza.online"],
  "look_alike_domains": [],
  "language": "pt",
  "analysis_version": "2.0.0"
}
```

---

## MLOps — Gatekeeper Pipeline

Model promotion is protected by an automated **Gatekeeper** that enforces quality thresholds before any new model reaches production:

- `recall ≥ threshold` — never sacrifice fraud detection rate
- `precision drop ≤ tolerance` — control false positives
- Automatic registry versioning (`v_YYYYMMDD_HHMM`)
- Current production model: **recall = 0.984 · precision = 0.996**

---

## Interfaces

### Telegram Bot
- Forward any suspicious message to the bot for instant analysis
- Bilingual responses (PT-BR / EN-US) based on detected language
- `/feedback` command to report false positives
- Per-user rate limiting (sliding window, 60s)
- Access control via `TELEGRAM_AUTHORIZED_USERS`

### WhatsApp (Twilio)
- Webhook integration with TwiML responses
- Educational risk cards in PT-BR
- Phone number-based access control

---

## Observability

Every request is logged with:
```
2026-03-01 16:00:00,123 - INFO - Hash: <sha256> | Score: 0.91 | Fraud: True | Lookalikes: [] | Latency: 12.34ms
```

The dashboard endpoint aggregates:
- Total requests, fraud rate, avg/P95/max latency
- False positives reported in the last 24h
- Active production model metadata

---

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/gabriel-correa11/dataset_builder
cd dataset_builder
cp .env.example .env
# Fill in your values in .env
```

### 2. Run with Docker

```bash
docker compose up --build -d
```

The API will be available at `http://localhost:8000`
Interactive docs: `http://localhost:8000/docs`

### 3. Run locally

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn src.main:app --reload
```

---

## Project Structure

```
src/
├── main.py          # FastAPI app — routes, rate limiting, middleware
├── analyzer.py      # Hybrid engine — normalization, heuristics, LightGBM
├── dashboard.py     # Log parser and 24h stats aggregator
├── telegram_bot.py  # Telegram polling bot
├── whatsapp.py      # Twilio TwiML builder
└── utils.py         # PII masking (CPF, email, phone)
```

---

## Environment Variables

Copy `.env.example` to `.env` and set your values:

| Variable | Description | Default |
|----------|-------------|---------|
| `TELEGRAM_BOT_TOKEN` | Token from @BotFather | required |
| `ADMIN_API_KEY` | Key for protected endpoints | required |
| `TWILIO_ACCOUNT_SID` | Twilio account SID | optional |
| `TWILIO_AUTH_TOKEN` | Twilio auth token | optional |
| `TELEGRAM_AUTHORIZED_USERS` | Comma-separated Telegram user IDs | empty = allow all |
| `RATE_LIMIT_DETECT` | Requests/min for /detect | 10 |
| `RATE_LIMIT_FEEDBACK` | Requests/min for /feedback | 10 |
| `RATE_LIMIT_TELEGRAM_USER` | Messages/min per Telegram user | 10 |

---

## Test Suite

```bash
python -m pytest tests/ -v
# 131 passed
```

| File | Tests | Coverage |
|------|-------|----------|
| `test_logic.py` | 29 | Normalization, signals, whitelist, analyze |
| `test_gatekeeper.py` | 8 | LightGBM pipeline, recall/precision gates |
| `test_whatsapp.py` | 22 | TwiML builder, webhook, access control |
| `test_robustness.py` | 23 | De-obfuscation, Levenshtein, rate limiting |
| `test_dashboard.py` | 18 | Log parsing, feedback, dashboard aggregation |
| `test_telegram.py` | 31 | Bot handlers, auth, per-user rate limiting |

---

<a name="português"></a>
# Português

## O que é o CoreDetector?

O CoreDetector é uma API REST de nível produção que detecta mensagens de phishing em tempo real. Ele combina um **modelo de Machine Learning LightGBM** com um **motor de heurísticas determinístico** para entregar vereditos de fraude rápidos e explicáveis — não apenas "sim ou não", mas uma análise completa de *por que* uma mensagem é suspeita.

Desenvolvido para proteger pessoas reais contra golpes de WhatsApp, avisos falsos do governo, domínios bancários look-alike e ataques de engenharia social — em Português do Brasil e em Inglês.

---

## Como funciona

Cada mensagem passa por um pipeline de 4 etapas:

```
Texto bruto
   │
   ├── 1. Normalização Unicode (NFKC)
   ├── 2. De-ofuscação   (tabela leet: 0→o, 1→i, 3→e, @→a ...)
   ├── 3. Extração de Sinais (heurísticas regex — PT-BR + EN-US)
   │       ├── Links suspeitos / imitação de marca
   │       ├── Linguagem de urgência ou ameaça
   │       ├── Solicitação financeira direta (CPF, PIX, senha)
   │       └── Pressão jurídica / intimação falsa
   └── 4. LightGBM (TF-IDF ngram 1–2 → score de probabilidade)

Decisão:
   is_fraud = (prob > 0.4 OU sinais >= 2 OU domínio look-alike) E NÃO domínio oficial

   fraude     → score_final = max(prob, 0.91)
   oficial    → score_final = min(prob, 0.20)
   padrão     → score_final = prob

   BAIXO < 0.30 · MÉDIO < 0.60 · ALTO ≥ 0.60
```

### Detecção de Domínios Look-alike (Levenshtein)

Golpistas costumam registrar domínios como `g00gle.net` ou `banc0brasil.com` para imitar marcas confiáveis. O CoreDetector:

1. **De-ofusca** o domínio (`g00gle` → `google`)
2. Calcula a **similaridade de Levenshtein** contra uma whitelist de domínios oficiais
3. Sinaliza qualquer domínio com similaridade **≥ 0.80** como `Brand impersonation via look-alike domain`

Isso captura tentativas de evasão que enganam modelos puramente estatísticos.

---

## Endpoints da API

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `POST` | `/api/v1/detect` | Analisa uma mensagem para phishing |
| `POST` | `/api/v1/feedback` | Reporta falso positivo (requer `X-Admin-Key`) |
| `GET` | `/api/v1/health/dashboard` | Estatísticas agregadas das últimas 24h |

### Exemplo de Requisição

```bash
curl -X POST http://localhost:8000/api/v1/detect \
  -H "Content-Type: application/json" \
  -d '{"text": "URGENTE: Seu CPF foi bloqueado. Regularize agora: gov-regulariza.online/cpf", "source": "api"}'
```

### Exemplo de Resposta

```json
{
  "risk_level": "HIGH",
  "final_risk_score": 0.9998,
  "is_fraud": true,
  "signals": [
    "Hard urgency or threat tone",
    "Direct financial request"
  ],
  "suspicious_domains": ["gov-regulariza.online"],
  "look_alike_domains": [],
  "language": "pt",
  "analysis_version": "2.0.0"
}
```

---

## MLOps — Pipeline Gatekeeper

A promoção de modelos é protegida por um **Gatekeeper** automático que exige a aprovação de métricas antes de qualquer modelo chegar à produção:

- `recall ≥ threshold` — nunca sacrificar a taxa de detecção de fraudes
- `queda de precision ≤ tolerância` — controlar falsos positivos
- Versionamento automático no registry (`v_YYYYMMDD_HHMM`)
- Modelo em produção atual: **recall = 0.984 · precision = 0.996**

---

## Interfaces

### Bot do Telegram
- Encaminhe qualquer mensagem suspeita para análise instantânea
- Respostas bilíngues (PT-BR / EN-US) baseadas no idioma detectado
- Comando `/feedback` para reportar falsos positivos
- Rate limiting por usuário (sliding window de 60s)
- Controle de acesso via `TELEGRAM_AUTHORIZED_USERS`

### WhatsApp (Twilio)
- Integração via webhook com respostas TwiML
- Cards educativos de risco em PT-BR
- Controle de acesso por número de telefone

---

## Observabilidade

Cada requisição é registrada com:
```
2026-03-01 16:00:00,123 - INFO - Hash: <sha256> | Score: 0.91 | Fraud: True | Lookalikes: [] | Latency: 12.34ms
```

O endpoint de dashboard agrega:
- Total de requisições, taxa de fraude, latência média/P95/máxima
- Falsos positivos reportados nas últimas 24h
- Metadados do modelo em produção ativo

---

## Início Rápido

### 1. Clone e configure

```bash
git clone https://github.com/gabriel-correa11/dataset_builder
cd dataset_builder
cp .env.example .env
# Preencha os valores no .env
```

### 2. Executar com Docker

```bash
docker compose up --build -d
```

A API estará disponível em `http://localhost:8000`
Documentação interativa: `http://localhost:8000/docs`

### 3. Executar localmente

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn src.main:app --reload
```

---

## Estrutura do Projeto

```
src/
├── main.py          # App FastAPI — rotas, rate limiting, middleware
├── analyzer.py      # Motor híbrido — normalização, heurísticas, LightGBM
├── dashboard.py     # Parser de logs e agregador de estatísticas 24h
├── telegram_bot.py  # Bot Telegram com polling assíncrono
├── whatsapp.py      # Builder TwiML para Twilio
└── utils.py         # Mascaramento de PII (CPF, email, telefone)
```

---

## Variáveis de Ambiente

Copie `.env.example` para `.env` e preencha os valores:

| Variável | Descrição | Padrão |
|----------|-----------|--------|
| `TELEGRAM_BOT_TOKEN` | Token do @BotFather | obrigatório |
| `ADMIN_API_KEY` | Chave para endpoints protegidos | obrigatório |
| `TWILIO_ACCOUNT_SID` | SID da conta Twilio | opcional |
| `TWILIO_AUTH_TOKEN` | Token de autenticação Twilio | opcional |
| `TELEGRAM_AUTHORIZED_USERS` | IDs Telegram separados por vírgula | vazio = libera todos |
| `RATE_LIMIT_DETECT` | Requisições/min no /detect | 10 |
| `RATE_LIMIT_FEEDBACK` | Requisições/min no /feedback | 10 |
| `RATE_LIMIT_TELEGRAM_USER` | Mensagens/min por usuário Telegram | 10 |

---

## Suíte de Testes

```bash
python -m pytest tests/ -v
# 131 passed
```

| Arquivo | Testes | Cobertura |
|---------|--------|-----------|
| `test_logic.py` | 29 | Normalização, sinais, whitelist, analyze |
| `test_gatekeeper.py` | 8 | Pipeline LightGBM, gates de recall/precision |
| `test_whatsapp.py` | 22 | Builder TwiML, webhook, controle de acesso |
| `test_robustness.py` | 23 | De-ofuscação, Levenshtein, rate limiting |
| `test_dashboard.py` | 18 | Parser de logs, feedback, agregação |
| `test_telegram.py` | 31 | Handlers do bot, auth, rate limit por usuário |

---

<div align="center">

Developed by **Gabriel Correa**

</div>
