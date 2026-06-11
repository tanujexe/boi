# 🛡️ BOI — SentinelAI Malware Analysis Platform

**SentinelAI** is a multi-agent automated Android malware investigation and risk assessment platform. It accepts Android APK files, runs them through a 6-stage AI agent pipeline powered by **Groq (Llama 3.1 70B)**, and produces a full forensic report — including MITRE ATT&CK mappings, risk scores, attack narratives, and remediation guidance.

---

## 🧠 How It Works

When you upload an APK, it flows through 6 AI agents in sequence:

```
APK Upload
    │
    ▼
[Agent 1] Reverse Engineering  →  Decompiles APK, extracts permissions, APIs, URLs
    │
    ▼
[Agent 2] Code Analysis        →  Classifies findings by severity (Critical/High/Medium)
    │
    ▼
[Agent 3] Threat Intelligence  →  Maps to MITRE ATT&CK & OWASP Mobile Top 10
    │
    ▼
[Agent 4] Investigation        →  Groq (Llama 3.1 70B) synthesizes attack narrative
    │
    ▼
[Agent 5] Risk Assessment      →  Deterministic scoring engine (0–100 risk score)
    │
    ▼
[Agent 6] Report Generation    →  Groq writes full Executive + Technical + Remediation report
```

---

## 📁 Project Structure

```
boi/
│
├── backend/                        # Python FastAPI backend
│   │
│   ├── main.py                     # 🚀 App entry point — starts FastAPI server, loads .env, registers routes
│   ├── database.py                 # 🗄️ SQLite database setup using SQLAlchemy (tables: jobs, campaigns)
│   ├── schemas.py                  # 📐 Pydantic models for request/response validation
│   ├── requirements.txt            # 📦 All Python dependencies
│   ├── .env                        # 🔑 Your secret API keys (NEVER committed to git)
│   ├── .env.example                # 📋 Template showing what keys are needed
│   ├── .gitignore                  # 🚫 Tells git what NOT to track (node_modules, .env, db, etc.)
│   │
│   ├── routes/                     # API route handlers (URL endpoints)
│   │   ├── __init__.py             # Makes routes a Python package
│   │   ├── jobs.py                 # /api/jobs — upload APK, start analysis, get job status
│   │   ├── campaigns.py            # /api/campaigns — group multiple jobs into campaigns
│   │   └── keys.py                 # /api/keys — manage API key storage
│   │
│   ├── services/                   # Core business logic
│   │   ├── __init__.py             # Makes services a Python package
│   │   ├── agents.py               # 🤖 The 6 AI agents + LangGraph workflow orchestration
│   │   ├── parser.py               # 🔍 Static APK parser — extracts manifest, DEX, permissions
│   │   ├── db_service.py           # 💾 Database CRUD operations (create/read jobs & campaigns)
│   │   └── websocket_manager.py    # 📡 Real-time WebSocket log streaming to the frontend
│   │
│   ├── uploads/                    # Temporary storage for uploaded APK files (gitignored)
│   ├── test_apks/                  # Sample APKs for testing (gitignored)
│   └── sentinel_ai.db              # SQLite database file — auto-created on first run (gitignored)
│
└── frontend/                       # React + Vite frontend
    │
    ├── index.html                  # HTML entry point
    ├── vite.config.js              # Vite bundler configuration
    ├── tailwind.config.js          # Tailwind CSS configuration
    ├── postcss.config.js           # PostCSS configuration
    ├── package.json                # Node.js dependencies and scripts
    │
    └── src/                        # React source code
        ├── main.jsx                # React app bootstrap
        ├── App.jsx                 # Root component — handles routing between views
        ├── App.css                 # Global app styles
        ├── index.css               # Base CSS / Tailwind directives
        │
        └── components/             # Individual page components
            ├── Sidebar.jsx         # 🗂️ Navigation sidebar with all page links
            ├── DashboardView.jsx   # 📊 Main dashboard — job stats, recent activity
            ├── UploadPage.jsx      # 📤 APK upload form + real-time agent log streaming
            ├── EvidenceExplorer.jsx # 🔬 Browse extracted permissions, APIs, URLs per job
            ├── InvestigationReport.jsx # 📄 View full AI-generated forensic report
            ├── ThreatIntel.jsx     # 🗺️ MITRE ATT&CK & OWASP mapping viewer
            ├── CampaignTriage.jsx  # 📁 Group and manage analysis campaigns
            └── ApiPlayground.jsx   # 🧪 Test API endpoints directly from the browser
```

---

## 🧰 Prerequisites

Make sure these are installed before you begin:

| Tool | Min Version | Download |
|---|---|---|
| **Node.js** | v18+ | https://nodejs.org |
| **Python** | 3.10+ | https://python.org |
| **Git** | Any | https://git-scm.com |

---

## 🚀 Setup & Run on a New Device

### Step 1 — Clone the repository

```bash
git clone https://github.com/tanujexe/boi.git
cd boi
```

---

### Step 2 — Backend Setup

```bash
cd backend
```

**Create a virtual environment** (keeps dependencies isolated):

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python -m venv venv
source venv/bin/activate
```

**Install all dependencies:**

```bash
pip install -r requirements.txt
```

**Set up your environment variables:**

```bash
# Windows
copy .env.example .env

# macOS / Linux
cp .env.example .env
```

Now open the `.env` file and add your Groq API key:

```
GROQ_API_KEY=your_groq_api_key_here
```

> 🔑 Get a free Groq API key at **https://console.groq.com** → Sign up → API Keys → Create New Key

**Start the backend server:**

```bash
python main.py
```

✅ Backend is live at: **http://localhost:8000**  
📖 Interactive API docs: **http://localhost:8000/docs**

---

### Step 3 — Frontend Setup

Open a **new terminal window**, then:

```bash
cd frontend
```

**Install dependencies:**

```bash
npm install
```

**Start the frontend dev server:**

```bash
npm run dev
```

✅ App is live at: **http://localhost:5173**

---

## ⚙️ Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GROQ_API_KEY` | ✅ Yes | Powers the AI agents (Llama 3.1 70B via Groq LPU) |

> The `.env` file lives in the `backend/` folder and is **never committed to git**.

---

## 🔌 Key API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Check if the server is running |
| `POST` | `/api/jobs/upload` | Upload an APK for analysis |
| `GET` | `/api/jobs` | List all analysis jobs |
| `GET` | `/api/jobs/{id}` | Get full results for a job |
| `WS` | `/api/ws/{job_id}` | Real-time agent log stream |
| `GET` | `/api/campaigns` | List all campaigns |
| `POST` | `/api/campaigns` | Create a new campaign |

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | React 18, Vite, Tailwind CSS, Recharts, Lucide Icons |
| **Backend** | FastAPI, Uvicorn, SQLAlchemy, SQLite |
| **AI Agents** | LangGraph, Groq SDK (Llama 3.1 70B) |
| **Real-time** | WebSockets |

---

## ⚠️ Important Notes

- Both **backend** and **frontend** must be running simultaneously for the app to work
- The **SQLite database** (`sentinel_ai.db`) is created automatically on first run — no setup needed
- The **Groq API** is used for AI reasoning — without a valid key, the system falls back to built-in templates for known malware families (Anubis, SharkBot, Cerberus)
- Never commit your `.env` file — it's protected by `.gitignore`
