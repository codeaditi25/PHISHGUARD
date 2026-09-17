[README.md](https://github.com/user-attachments/files/32351866/README.md)
# PHISHGUARD 🛡️ LinkShield (PhishGuard)

**Check before you click.**

LinkShield is a lightweight URL security scanner that analyzes a submitted link using a set of heuristic checks and returns a risk score (0–100) along with a plain-language verdict — **Safe**, **Suspicious**, or **Potentially Dangerous**. It's built as a two-part project: a FastAPI backend that performs the analysis and a static HTML/CSS/JS frontend that provides the scanning interface.

> ⚠️ LinkShield is a heuristic, educational tool. A score is an *indicator*, not proof that a site is malicious or safe. It does not visit or render the target website — it only inspects the URL's structure.

---

## Features

- 🎯 **Risk Score** — a normalized 0–100 score for any submitted URL
- 🔍 **Detailed Breakdown** — see exactly which checks passed, warned, or failed, and why
- ⚡ **Fast, No-Frills Scanning** — paste a URL and get an instant result
- 🗂️ **Scan History** — recent scans are stored and retrievable via the API
- 🌐 **Simple Web UI** — clean, responsive scanner interface with no build step required

### Security checks performed

LinkShield inspects the *structure* of a URL (not the live website) across 11 heuristics:

| Check | What it looks for |
|---|---|
| URL Length | Unusually long URLs |
| HTTPS | Whether the link uses `https` |
| IP Address as Domain | A raw IP address instead of a domain name |
| Suspicious Keywords | Words like `login`, `verify`, `secure`, `account`, `password`, etc. |
| Subdomain Count | Excessive subdomain nesting |
| `@` Symbol | Use of `@` to mask the real destination |
| Domain Hyphens | An unusually high number of hyphens in the domain |
| Unicode / Homoglyph | Non-ASCII characters or Punycode (`xn--`) that can impersonate real domains |
| Brand Typosquatting | Known brand names combined with suspicious surrounding text |
| URL Shortener | Use of common link-shortening services |
| Random Domain Pattern | Domains that look auto-generated (digit-heavy, odd consonant runs) |

Each check contributes points to a total risk score:

- **0–29** → `Safe`
- **30–69** → `Suspicious`
- **70–100** → `Potentially Dangerous`

---

## Tech Stack

**Backend**
- [FastAPI](https://fastapi.tiangolo.com/) — web framework / REST API
- [SQLAlchemy](https://www.sqlalchemy.org/) — ORM
- SQLite — storage for scan history
- [Pydantic](https://docs.pydantic.dev/) — request/response validation
- [Uvicorn](https://www.uvicorn.org/) — ASGI server

**Frontend**
- Plain HTML, CSS, and JavaScript (no framework, no build step)

---

## Project Structure

```
PHISHGUARD/
├── Backend/
│   ├── analysis/
│   │   ├── url_parser.py        # Normalizes and parses submitted URLs
│   │   ├── security_checks.py   # Runs the individual heuristic checks
│   │   └── scoring.py           # Aggregates checks into a score + verdict
│   ├── main.py                  # FastAPI app & routes
│   ├── config.py                # App settings (DB URL, CORS, app name/version)
│   ├── database.py              # SQLAlchemy engine/session setup
│   ├── models.py                # `Scan` database model
│   └── schemas.py                # Pydantic request/response schemas
├── Frontend/
│   ├── index.html               # Scanner UI
│   ├── script.js                # Handles form submission & API calls
│   ├── results.js               # Renders the analysis results
│   ├── style.css                # Styling
│   └── assets/                  # Logo/static assets
└── README.md
```

---

## Getting Started

### Prerequisites

- Python 3.9+
- A modern web browser
- (Optional) A simple local server for the frontend, e.g. the VS Code "Live Server" extension

### 1. Clone the repository

```bash
git clone https://github.com/codeaditi25/PHISHGUARD.git
cd PHISHGUARD
```

### 2. Set up the backend

```bash
cd Backend
pip install fastapi uvicorn sqlalchemy pydantic
```

Run the API server:

```bash
python main.py
```

Or with `uvicorn` directly:

```bash
uvicorn main:app --reload --port 8000
```

The API will be available at `http://127.0.0.1:8000`, and interactive docs at `http://127.0.0.1:8000/docs`. A SQLite database (`linkshield.db`) is created automatically on first run.

### 3. Run the frontend

The frontend is static, so you can open `Frontend/index.html` directly in a browser, or serve it locally (recommended, to avoid CORS/file-path quirks):

```bash
cd Frontend
python -m http.server 5500
```

Then visit `http://127.0.0.1:5500`.

> The frontend calls the API at `http://127.0.0.1:8000/analyze` (see `API_URL` in `script.js`). Update this if your backend runs elsewhere.

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Returns app name, version, and status |
| `GET` | `/health` | Basic health check |
| `POST` | `/analyze` | Analyzes a submitted URL and returns a score, verdict, and check breakdown |
| `GET` | `/scans` | Returns the 50 most recent scans |

### Example: `POST /analyze`

**Request**

```json
{
  "url": "http://paypal-secure-login.example-verify.com"
}
```

**Response**

```json
{
  "url": "http://paypal-secure-login.example-verify.com",
  "score": 63,
  "verdict": "Suspicious",
  "checks": [
    {
      "name": "HTTPS",
      "status": "warning",
      "score": 5,
      "reason": "The URL does not use HTTPS."
    },
    {
      "name": "Brand Typosquatting",
      "status": "danger",
      "score": 18,
      "reason": "The domain contains the brand name 'paypal' with additional suspicious domain text."
    }
  ]
}
```

---

## Roadmap Ideas

- [ ] Move CORS origins and secrets out of source and into environment variables for production
- [ ] Swap the demo brand/keyword lists for a maintained, external data source
- [ ] Add a "Recent Scans" view in the frontend using `GET /scans`
- [ ] Containerize the backend (Dockerfile / docker-compose)
- [ ] Add automated tests for the analysis and scoring modules

---

## Disclaimer

LinkShield performs static analysis of URL structure only. It does not fetch, render, or execute the destination page, and it is not a substitute for a full anti-phishing or threat-intelligence solution. Always exercise caution with unfamiliar links.

## License

No license has been specified for this project yet. Consider adding one (e.g. MIT) if you intend for others to use or contribute to it.
