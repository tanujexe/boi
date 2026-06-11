# 🛡️ BOI — SentinelAI Malware Analysis Platform

A multi-agent automated Android malware investigation & risk assessment platform built with **FastAPI** (backend) and **React + Vite** (frontend).

---

## 🧰 Prerequisites

Make sure you have these installed before cloning:

| Tool | Version | Download |
|---|---|---|
| Node.js | v18+ | https://nodejs.org |
| Python | 3.10+ | https://python.org |
| Git | any | https://git-scm.com |

---

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/tanujexe/boi.git
cd boi
```

---

### 2. Backend Setup

```bash
cd backend
```

**Create a virtual environment (recommended):**

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python -m venv venv
source venv/bin/activate
```

**Install dependencies:**

```bash
pip install -r requirements.txt
```

**Set up environment variables:**

```bash
# Copy the example file
cp .env.example .env
```

Then open `.env` and add your actual API key:

```
GROQ_API_KEY=your_groq_api_key_here
```

> 🔑 Get your free Groq API key at https://console.groq.com

**Run the backend:**

```bash
python main.py
```

The API will be live at: **http://localhost:8000**  
Interactive API docs: **http://localhost:8000/docs**

---

### 3. Frontend Setup

Open a **new terminal**, then:

```bash
cd frontend
```

**Install dependencies:**

```bash
npm install
```

**Run the frontend:**

```bash
npm run dev
```

The app will be live at: **http://localhost:5173**

---

## 📁 Project Structure

```
boi/
├── backend/
│   ├── main.py              # FastAPI entry point
│   ├── database.py          # Database setup (SQLite)
│   ├── schemas.py           # Pydantic models
│   ├── requirements.txt     # Python dependencies
│   ├── .env.example         # Environment variable template
│   ├── routes/              # API route handlers
│   └── services/            # Business logic & AI agents
│
└── frontend/
    ├── src/                 # React source code
    ├── public/              # Static assets
    ├── package.json         # Node dependencies
    └── vite.config.js       # Vite configuration
```

---

## ⚠️ Important Notes

- Never commit your `.env` file — it's already in `.gitignore`
- The backend uses **SQLite** by default, so no database installation is needed
- Both backend and frontend must be running simultaneously for the app to work
