# Aegis Vanguard

> **Aegis** (Greek): The shield or breastplate of Athena/Zeus, signifying protection and backing.  
> **Vanguard**: The foremost part of an advancing army, leading the charge.

Aegis Vanguard is a full-stack Offensive Security Assessment platform built for the ArchScale Guild Hackathon (Problem AS-09).

This project goes beyond theoretical vulnerability lists by combining a powerful parallelized Python scanner with a modern, real-time Next.js command dashboard. It not only breaches the target to expose critical flaws but simultaneously generates the exact middleware (Express/Nginx/Next.js) code patches required to forge an impenetrable defense.

## Features

- **Live Offensive Scanner**: 14 concurrent Python modules designed to exploit, enumerate, and expose misconfigurations (CORS, Missing Headers, Rate Limiting, Open Redirects, etc.).
- **SPA Fingerprinting**: An advanced Error Analyzer that automatically fingerprints catch-all Next.js/React routes to eliminate false positives.
- **Server-Sent Events (SSE)**: Real-time execution streaming from the Python subprocess directly to the React frontend.
- **The "Hire Me" Patch Generator**: Auto-generates exact code snippets (e.g. `helmet`, `express-rate-limit`, `nginx.conf`) for every vulnerability found.
- **Executive Dashboard**: A dark-mode, premium UI visualizing the entire attack surface and hardening plan.

---

## 🚀 Quick Start (Local Development)

### 1. Python Scanner Setup
```bash
cd scanner
python -m venv venv
# Windows
venv\Scripts\activate
# Mac/Linux
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Next.js Dashboard Setup
Open a new terminal:
```bash
cd dashboard
npm install
npm run dev
```
Visit `http://localhost:3000` to access the Aegis Vanguard dashboard.

---

## ☁️ Deployment (Free on Render)

Because Aegis Vanguard requires both a Node.js frontend and a Python backend subprocess to execute live scans, serverless platforms like Vercel will not work (due to lack of Python binaries and 10-second API timeouts). 

We use **Docker** on **Render.com** for free, full-stack hosting.

1. Create a GitHub repository and push this entire directory.
2. Go to [Render.com](https://render.com/) and click **New > Web Service**.
3. Connect your GitHub repository.
4. Render will automatically detect the `Dockerfile` at the root of the project.
5. Select the **Free** instance type.
6. Click **Deploy Web Service**.

Render will build the Docker container (installing Python, Node, running `pip install` and `npm build`) and expose port 3000. Your live scanner will now work flawlessly on the public internet.

---

## Architecture

```text
aegis-vanguard/
│
├── Dockerfile                  # Multi-environment config for Render deployment
├── scanner/                    # The Offensive Python Engine
│   ├── main.py                 # Core parallel execution thread pool
│   ├── report_generator.py     # HTML report compiler
│   ├── patches/                # Generated defense code snippets
│   └── *.py                    # The 14 attack modules
│
└── dashboard/                  # The Defensive Next.js Command Center
    ├── src/app/api/scan/       # Server-Sent Events (SSE) bridge to Python
    ├── src/app/scan/           # Live execution UI
    └── src/app/hardening/      # Code patch viewer
```

## Hackathon Submission Notice
*This platform was explicitly developed under authorization for the ArchScale Guild Internship Hackathon to assess `app.archscale.in`. Do not point this scanner at unauthorized targets.*
