# 🛡️ Security Copilot — AI-Powered Threat Intelligence Assistant

A conversational AI security assistant that investigates IPs, URLs, file hashes, and MITRE ATT&CK techniques by querying multiple real-world threat intelligence APIs. Built with Python, OpenAI GPT-4o, and Streamlit.

---

## 🚀 Live Demo

> https://security-copilot.streamlit.app/

---

## 📌 What It Does

Security Copilot lets you ask natural language questions about security indicators and automatically:

- Queries multiple threat intelligence sources simultaneously
- Correlates findings across tools to produce a unified risk assessment
- Calculates a **Threat Score (0–100)** with a verdict (CLEAN / LOW / MEDIUM / HIGH / CRITICAL)
- Maps findings to **MITRE ATT&CK techniques**
- Generates a downloadable **PDF Threat Intelligence Report**

---

## 🧰 Integrated Tools

| Tool | Purpose |
|---|---|
| **VirusTotal** | Malware detection for IPs, URLs, and file hashes |
| **AbuseIPDB** | IP abuse reports and confidence scoring |
| **GreyNoise** | Internet noise vs targeted threat classification |
| **Shodan** | Open ports, services, and vulnerability exposure |
| **MITRE ATT&CK** | Live attack technique lookup and tactic mapping |

---

## 🏗️ Architecture
```
User (Streamlit UI)
        ↓
   Rate Limiter
        ↓
  GPT-4o Agent (Function Calling)
        ↓
   Tool Router
        ↓
┌──────────────────────────────────┐
│  VirusTotal  │  AbuseIPDB        │
│  GreyNoise   │  Shodan           │
│  MITRE ATT&CK (live JSON feed)   │
└──────────────────────────────────┘
        ↓
  Threat Scoring Engine
        ↓
  PDF Report Generator
```

---

## ✨ Key Features

- **Natural language interface** — ask questions like a real analyst
- **Multi-source correlation** — combines results from 5 intelligence sources
- **Threat scoring engine** — numeric score with evidence from each tool
- **MITRE ATT&CK integration** — live data from official MITRE GitHub feed
- **PDF report generation** — professional downloadable investigation report
- **IOC file upload** — upload `.txt`, `.csv`, or `.json` files with indicators
- **Rate limiting** — prevents API abuse (5 req/min, 30 req/session)
- **Dark mode UI** — professional SOC dashboard aesthetic
- **Session management** — clear chat and reset state cleanly

---

## 📋 Example Queries
```
Check IP 45.155.205.233
Is 104.16.249.249 a VPN or proxy?
Scan this URL: http://example.com/malware.exe
Check hash: 44d88612fea8a8f36de82e1278abb02f
What is MITRE technique T1059?
Show me persistence techniques
Search MITRE for credential dumping
Generate report
```

---

## ⚙️ Setup & Installation

### 1. Clone the repository
```bash
git clone https://github.com/Turbantech/Security-Copilot.git
cd security-copilot
```

### 2. Create a virtual environment
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Mac/Linux
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure API keys

Create a `.env` file in the project root:
```env
OPENAI_API_KEY=sk-your-key-here
VIRUSTOTAL_API_KEY=your-key-here
ABUSEIPDB_API_KEY=your-key-here
GREYNOISE_API_KEY=your-key-here
SHODAN_API_KEY=your-key-here
```

### Where to get API keys

| Service | Link | Free Tier |
|---|---|---|
| OpenAI | https://platform.openai.com/api-keys | Pay per use |
| VirusTotal | https://www.virustotal.com/gui/my-apikey | ✅ Free |
| AbuseIPDB | https://www.abuseipdb.com/account/api | ✅ Free |
| GreyNoise | https://viz.greynoise.io/account | ✅ Free |
| Shodan | https://account.shodan.io | ✅ Free (limited) |

### 5. Run the app
```bash

streamlit run app.py
```

Open your browser at `http://localhost:8501`

---

## 📁 Project Structure
```
security-copilot/
│
├── app.py                  # Streamlit UI
├── orchestrator.py         # GPT-4o agent + tool routing
├── system_prompt.py        # AI system prompt
├── threat_scorer.py        # Threat scoring engine
├── report_generator.py     # PDF report generation
├── rate_limiter.py         # Request rate limiting
├── config.py               # API key management
│
├── tools/
│   ├── virustotal_tool.py  # VirusTotal integration
│   ├── abuseipdb_tool.py   # AbuseIPDB integration
│   ├── greynoise_tool.py   # GreyNoise integration
│   ├── shodan_tool.py      # Shodan integration
│   └── mitre_tool.py       # MITRE ATT&CK integration
│
├── .streamlit/
│   └── config.toml         # Dark theme config
│
└── requirements.txt
```

---

## 🔒 Security Controls

- API keys stored in environment variables only — never hardcoded
- Rate limiting per session (5 req/min, 30 req/session max)
- Input passed to APIs only — never executed
- No user data stored or logged beyond session

---

## 🚀 Deployment

### Streamlit Community Cloud (Free)

1. Push to GitHub (make sure `.env` is in `.gitignore`)
2. Go to [share.streamlit.io](https://share.streamlit.io)
3. Connect your repo and set `app.py` as the main file
4. Add API keys under **Settings → Secrets**
5. Deploy

---

## 🛠️ Troubleshooting

| Problem | Fix |
|---|---|
| MITRE data slow on first load | Normal — downloads ~15MB, cached after first run |
| VirusTotal rate limit errors | Free tier = 4 req/min, wait and retry |
| Shodan 403 error | Free API key has limited access, upgrade for full data |
| OpenAI quota error | Check credits at platform.openai.com |
| Missing API keys warning | Add missing keys to your `.env` file |

---

## 📄 License

MIT License — free to use and modify.