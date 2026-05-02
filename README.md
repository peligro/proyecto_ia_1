# 🔒 AI Audit Security Scanner

[![Release](https://img.shields.io/github/v/release/peligro/proyecto_ia_1?label=version&color=blue)](https://github.com/peligro/proyecto_ia_1/releases)
[![License](https://img.shields.io/github/license/peligro/proyecto_ia_1)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go)](https://go.dev)
[![GitHub Actions](https://github.com/peligro/proyecto_ia_1/actions/workflows/release.yml/badge.svg)](https://github.com/peligro/proyecto_ia_1/actions)

> **AI-powered security scanner** for dependencies, web applications, and APIs — with intelligent vulnerability explanations in multiple languages.

[🌐 Translations](#-translations) • [🚀 Quick Start](#-quick-start) • [✨ Features](#-features) • [📦 Installation](#-installation) • [🔧 Usage](#-usage) • [🤖 AI Providers](#-ai-providers) • [🌍 i18n](#-internationalization) • [🔐 Security](#-security-considerations) • [🤝 Contributing](#-contributing)

---

## 🌐 Translations

[🇺 English](README.md) • [🇪🇸 Español](README.es.md) • [🇫🇷 Français](README.fr.md) • [🇵🇹 Português](README.pt.md) • [🇩 Deutsch](README.de.md)

---

## 🚀 Quick Start

### One-liner installation (Linux/macOS)
```bash
curl -fsSL https://raw.githubusercontent.com/peligro/proyecto_ia_1/main/install.sh | bash
```

### Scan a website with AI explanations (Spanish)


```bash
./ai-audit scan \
  --type web \
  --url https://tusitio.com \
  --ai \
  --provider mistral \
  --lang es \
  --output pdf
```

### Scan dependencies for vulnerabilities

```bash
./ai-audit scan --type deps --dir ./mi-proyecto --output markdown
```

### Gray-box auth testing (BOLA/BFLA detection)

```bash
./ai-audit scan \
  --type auth \
  --url https://api.tusitio.com \
  --graybox \
  --admin-token "$ADMIN_TOKEN" \
  --user-token "$USER_TOKEN" \
  --endpoints "/api/users,/api/admin" \
  --output json
```

### 🌍 Internationalization (i18n)

- **5 languages**: English, Spanish, French, Portuguese, German
- **AI responses in your language**: Prompts are localized, not just UI labels
- **PDF reports with proper encoding**: Professional output for any audience

### 📊 Professional Reporting

| Format | Best For | Features |
|--------|----------|----------|
| `json` | Automation, CI/CD | Machine-readable, easy to parse |
| `markdown` | Documentation, wikis | Human-readable, GitHub-friendly |
| `pdf` | Client reports, executives | Styled layout, visual severity badges, print-ready |

### 🔐 Security-First Design

- **Zero hardcoded secrets**: All API keys via env vars or `--key` flag
- **No telemetry**: Your scans stay on your machine
- **Open source**: Audit the code yourself

---

## 📦 Installation

### Option 1: Pre-built binaries (Recommended)

Download from [Releases](https://github.com/peligro/proyecto_ia_1/releases):

```bash
# Linux (AMD64)
curl -L https://github.com/peligro/proyecto_ia_1/releases/latest/download/ai-audit_Linux_x86_64.tar.gz | tar xz

# macOS (Apple Silicon)
curl -L https://github.com/peligro/proyecto_ia_1/releases/latest/download/ai-audit_Darwin_arm64.tar.gz | tar xz

# Windows (PowerShell)
Invoke-WebRequest -Uri https://github.com/peligro/proyecto_ia_1/releases/latest/download/ai-audit_Windows_x86_64.zip -OutFile ai-audit.zip
Expand-Archive ai-audit.zip -DestinationPath .
```

### Option 2: Build from source

Requires Go 1.25+:

```bash
git clone https://github.com/peligro/proyecto_ia_1.git
cd proyecto_ia_1/golang
go build -o ai-audit -ldflags="-s -w" .
```

### Option 3: Install script (Linux/macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/peligro/proyecto_ia_1/main/install.sh | bash
```

## 🔧 Usage

### Basic scan

```bash
./ai-audit scan --type web --url https://example.com
```
### With AI explanations (Mistral, Spanish output)

```bash
export MISTRAL_API_KEY=your_key_here
./ai-audit scan \
  --type web \
  --url https://example.com \
  --ai \
  --provider mistral \
  --lang es \
  --output pdf
```

### Gray-box auth testing

```bash
./ai-audit scan \
  --type auth \
  --url https://api.example.com \
  --graybox \
  --admin-token "admin_jwt_here" \
  --user-token "user_jwt_here" \
  --endpoints "/api/users,/api/admin/settings" \
  --ai \
  --output markdown
```

### Full options reference

```bash
./ai-audit scan --help

# Scan type
-t, --type string          deps, web, api, auth (default: deps)
-u, --url string           Target URL (required for web/auth)
-d, --dir string           Directory to scan (for deps)

# AI integration
--ai                       Enable AI-powered explanations
--provider string          gemini, mistral, deepseek, openai (default: gemini)
--key string               API key (or use *_API_KEY env var)
--model string             Specific model (optional)
--cache-ai                 Enable response caching (default: true)
--cache-ttl duration       Cache TTL (default: 24h)

# Output
-o, --output string        json, markdown, pdf (default: json)
-l, --lang string          en, es, fr, pt, de (default: en)

# Auth testing
--graybox                  Enable gray-box auth testing
--admin-token string       Admin API token
--user-token string        User API token
--endpoints strings        Endpoints to test (comma-separated)
```

---

## 🤖 AI Providers Configuration

Configure via environment variables or flags:

```bash
# Gemini (Google)
export GEMINI_API_KEY=your_key
export GEMINI_BASE_URL=https://generativelanguage.googleapis.com/v1beta/
export GEMINI_MODEL=gemini-2.0-flash

# Mistral
export MISTRAL_API_KEY=your_key
export MISTRAL_BASE_URL=https://api.mistral.ai/v1/
export MISTRAL_MODEL=mistral-small-latest

# DeepSeek
export DEEPSEEK_API_KEY=your_key
export DEEPSEEK_API_URL=https://api.deepseek.com/v1/
export DEEPSEEK_MODEL=deepseek-chat

# OpenAI
export OPENAI_API_KEY=your_key
export OPENAI_BASE_URL=https://api.openai.com/v1/
export OPENAI_MODEL=gpt-4o-mini
```

### 💡 Tip: Use --cache-ai to avoid redundant API calls. Cached responses are stored in ~/.ai-audit/cache/.


## 🌍 Internationalization (i18n)

| Code | Language | Example |
|------|----------|---------|
| `en` | English | `--lang en` |
| `es` | Spanish | `--lang es` |
| `fr` | French | `--lang fr` |
| `pt` | Portuguese | `--lang pt` |
| `de` | German | `--lang de` |

### 🔐 Security Considerations

#### Your keys stay safe

- ✅ API keys are **never hardcoded** — use env vars or `--key` flag
- ✅ Binaries **do not embed secrets** — keys are read at runtime only
- ✅ No telemetry or external calls beyond configured AI providers

#### Verify integrity

```bash
# Download checksums for latest release
curl -L https://github.com/peligro/proyecto_ia_1/releases/latest/download/checksums.txt

# Verify binary
sha256sum -c checksums.txt
```
 

### Responsible disclosure

Found a security issue in ai-audit itself? Please email [your-email@example.com] instead of opening a public issue.


---

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/your-idea`
3. Make your changes + add tests
4. Run linting: `go fmt ./... && go vet ./...`
5. Submit a PR

### Development setup

```bash
# Clone and enter project
git clone https://github.com/peligro/proyecto_ia_1.git
cd proyecto_ia_1/golang

# Create .env for local testing (never commit this!)
cp .env.example .env
# Edit .env with your API keys

# Run tests
go test ./...

# Build and run
go build -o ai-audit .
./ai-audit --help
```

### Adding a new language

- Create pkg/i18n/xx.go with xxDict() function
- Add the language constant in pkg/i18n/i18n.go
- Update this README's translation table

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

## 🙏 Acknowledgments

- [OSV.dev](https://osv.dev) for vulnerability data
- [OWASP](https://owasp.org) for security guidelines
- [chromedp](https://github.com/chromedp/chromedp) for PDF generation
- [gofpdf](https://github.com/jung-kurt/gofpdf) for fallback PDF rendering
- All AI providers for making intelligent explanations accessible

## 🚀 Quick Verification

After installation, verify everything works:

```bash
# Check version
./ai-audit version
# Output: ai-audit version v0.2.6

# Run a quick scan
./ai-audit scan --type web --url https://httpbin.org --output json | head -20
```

## 📬 Support & Feedback

- 🐛 Report bugs: [Issues](https://github.com/peligro/proyecto_ia_1/issues)
- 💡 Request features: [Discussions](https://github.com/peligro/proyecto_ia_1/discussions)
- 📧 Contact: [yo@cesarcancino.com](mailto:yo@cesarcancino.com)

---

> **Built with ❤️ by [@peligro](https://github.com/peligro)**  
> *Scan smarter, fix faster, sleep better.* 🔒✨