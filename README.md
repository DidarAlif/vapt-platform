# ReconScience 🛡️

**Advanced Security Reconnaissance & Vulnerability Assessment Platform**

A modern, full-stack VAPT (Vulnerability Assessment and Penetration Testing) platform that leverages Nuclei's 9000+ security templates for comprehensive web application security scanning.

![Next.js](https://img.shields.io/badge/Next.js-black?style=flat-square&logo=next.js&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=flat-square&logo=postgresql&logoColor=white)

## ✨ Features

### Security Scanning
- **Multi-Mode Scanning**: Quick, Full, Network, and Custom scan profiles
- **Nuclei Integration**: Leverages 9000+ security templates for CVEs, misconfigurations, and exposures
- **Python Fallback**: Built-in security checks when Nuclei isn't available
- **Header Analysis**: Comprehensive security header validation
- **Technology Detection**: Automatic fingerprinting of web technologies

### Platform Features
- **User Authentication**: Secure JWT-based authentication system
- **Scan History**: Track and review previous security assessments
- **Report Generation**: Export detailed HTML and JSON reports
- **OWASP Mapping**: Findings mapped to OWASP Top 10 2021 categories
- **Risk Scoring**: Automated risk score calculation based on findings

## 🏗️ Architecture

```
vapt-platform/
├── apps/
│   └── web/          # Next.js frontend
├── appsapi/          # FastAPI backend
│   ├── main.py       # API routes & endpoints
│   ├── scanner.py    # Nuclei scanner integration
│   ├── auth.py       # Authentication system
│   ├── database.py   # Database configuration
│   ├── models.py     # SQLAlchemy models
│   ├── report.py     # Report generation
│   └── owasp.py      # OWASP mapping
└── docker-compose.yml
```

## 🚀 Getting Started

### Prerequisites
- Node.js 18+
- Python 3.10+
- PostgreSQL
- Nuclei (optional, for full scanning capability)

### Frontend Setup
```bash
cd apps/web
npm install
npm run dev
```

### Backend Setup
```bash
cd appsapi
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

### Environment Variables

## 📡 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/register` | POST | Register new user |
| `/auth/login` | POST | User login |
| `/auth/me` | GET | Get current user |
| `/scan` | POST | Start security scan |
| `/scans` | GET | Get scan history |
| `/scans/{id}` | GET | Get scan details |
| `/scans/{id}/report/html` | GET | Export HTML report |
| `/scans/{id}/report/json` | GET | Export JSON report |

## 🔍 Scan Modes

| Mode | Description | Duration |
|------|-------------|----------|
| **Quick** | Technology detection & basic exposures | ~2 min |
| **Full** | Comprehensive CVE & vulnerability scan | ~10 min |
| **Network** | SSL, DNS, and cloud service analysis | ~5 min |
| **Custom** | User-selected vulnerability categories | Variable |

## 🛡️ Security Categories

- CVEs & Known Vulnerabilities
- Misconfigurations
- Exposed Files & Directories
- Subdomain Takeovers
- SSL/TLS Issues
- XSS, SQLi, LFI, RCE
- Authentication Bypass
- Admin Panels & Dashboards

## 📄 License

MIT License - feel free to use this for your own security assessments.

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only**. Always obtain proper authorization before scanning any target. Unauthorized scanning may be illegal.

---

Built with ❤️ by [Didar Alif](https://github.com/DidarAlif)
