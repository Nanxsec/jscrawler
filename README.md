# jscrawl

**JavaScript Endpoint & Secrets Extractor** — zero dependências externas, Python puro.

Ferramenta de reconhecimento ofensivo focada em arquivos JavaScript. Faz crawl de páginas, fuzzing de paths comuns e análise de bundles locais em busca de endpoints, segredos vazados, tokens, credenciais e artefatos de desenvolvimento.

---

## Funcionalidades

- **Crawl de HTML** — extrai todos os `<script src="">` linkados na página alvo e analisa blocos `<script>` inline automaticamente
- **Fuzzing de paths JS** — sonda 80+ caminhos comuns de bundlers (Webpack, Next.js, Nuxt, Vite, Angular, React, Vue…)
- **Análise local** — processa arquivos `.js` e `.map` individuais ou diretórios inteiros recursivamente
- **Detecção de segredos** — 40+ categorias de padrões cobrindo:
  - Chaves AWS, Google, Firebase, Azure
  - JWTs e secrets de assinatura
  - Tokens OAuth (GitHub, Slack, Discord, Telegram, Stripe, SendGrid, Mailgun…)
  - Strings de conexão com bancos de dados (MongoDB, MySQL, PostgreSQL, Redis…)
  - Chaves privadas RSA/EC/SSH
  - Credenciais em texto claro (usuário, senha, e-mail)
  - IPs internos e URLs de ambiente local
  - Source maps, flags de debug, comentários TODO/FIXME
- **Deduplicação** — mesmo achado não aparece duas vezes por arquivo
- **Filtro de falsos positivos** — elimina valores genéricos, placeholders e nomes de variáveis comuns
- **Exportação** — salva resultados em `.txt` legível ou `.json` para integração com pipelines
- **Controle de concorrência** — workers assíncronos configuráveis com semáforo

---

## Requisitos

- Python 3.8+
- Nenhuma dependência de terceiros

---

## Instalação

```bash
git clone https://github.com/nanxsec/jscrawler
cd jscrawl
chmod +x jscrawl.py
```

Ou use diretamente:

```bash
python3 jscrawl.py --help
```

---

## Uso

### Crawl + Fuzzing em alvo remoto

```bash
python3 jscrawl.py --url https://alvo.com
```

### Apenas crawl (sem fuzzing de paths)

```bash
python3 jscrawl.py --url https://alvo.com --no-fuzz
```

### Apenas fuzzing (sem crawl do HTML)

```bash
python3 jscrawl.py --url https://alvo.com --no-crawl
```

### Análise de arquivo local

```bash
python3 jscrawl.py --local ./bundle.js
```

### Análise de diretório completo

```bash
python3 jscrawl.py --local ./dist/
```

### Filtrar por severidade mínima

```bash
python3 jscrawl.py --url https://alvo.com --min-severity HIGH
```

### Salvar resultados

```bash
# Formato texto
python3 jscrawl.py --url https://alvo.com -o relatorio.txt

# Formato JSON
python3 jscrawl.py --url https://alvo.com -o relatorio.json --format json
```

### Ajustar concorrência e timeout

```bash
python3 jscrawl.py --url https://alvo.com -t 50 --timeout 12
```

---

## Opções

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--url URL` | — | URL alvo para crawl e fuzzing |
| `--local PATH` | — | Arquivo `.js` ou diretório local |
| `-t`, `--threads N` | `30` | Workers HTTP concorrentes |
| `--timeout N` | `8` | Timeout por requisição (segundos) |
| `--no-crawl` | `false` | Pula o crawl do HTML |
| `--no-fuzz` | `false` | Pula o fuzzing de paths |
| `--min-severity` | `INFO` | Severidade mínima: `CRITICAL` `HIGH` `MEDIUM` `LOW` `INFO` |
| `-o`, `--output FILE` | — | Arquivo de saída |
| `--format` | `txt` | Formato: `txt` ou `json` |

---

## Severidades

| Nível | Exemplos |
|-------|----------|
| `CRITICAL` | AWS keys, JWTs, senhas, tokens de bot, chaves privadas, bearer tokens |
| `HIGH` | API keys genéricas, Firebase, Azure, OAuth client IDs, buckets S3 |
| `MEDIUM` | IPs internos, URLs locais, tenant IDs, source maps, variáveis de ambiente |
| `LOW` | Flags de debug, `console.log`, comentários TODO/FIXME |
| `INFO` | Endpoints e rotas extraídos do código |

---

## Saída JSON

Cada achado no JSON contém:

```json
{
  "source": "https://alvo.com/static/js/main.js",
  "js_type": "crawled",
  "category": "aws_key",
  "severity": "CRITICAL",
  "line": 142,
  "value": "AKIAIOSFODNN7EXAMPLE",
  "context": "...awsKey = 'AKIAIOSFODNN7EXAMPLE', region..."
}
```

---

## Categorias detectadas

`aws_key` · `aws_secret` · `aws_bucket` · `google_api_key` · `google_oauth` · `firebase_url` · `firebase_key` · `azure_storage` · `azure_tenant` · `jwt_token` · `jwt_secret` · `api_key` · `secret_key` · `bearer_token` · `auth_header` · `password` · `username` · `email_cred` · `db_connection` · `db_password` · `private_key` · `ssh_key` · `github_token` · `slack_token` · `stripe_key` · `twilio_sid` · `sendgrid_key` · `mailgun_key` · `heroku_key` · `npm_token` · `discord_token` · `telegram_token` · `env_variable` · `hardcoded_ip` · `internal_url` · `crypto_key` · `hash_secret` · `debug_flag` · `console_log` · `todo_comment` · `source_map` · `endpoint` · `route`

---

## Aviso Legal

Esta ferramenta é destinada a uso em **ambientes autorizados** — pentest, bug bounty, análise do próprio código. O uso não autorizado contra sistemas de terceiros é ilegal. O autor não se responsabiliza por uso indevido.
