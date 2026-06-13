# 🛡️ Email Protection Gateway — How To Run

> بالعربي: الملف ده بيشرح إزاي تشغل الـ pipeline بتاعنا خطوة بخطوة من الأول.

---

## ✅ Step 1 — Install Docker Desktop

1. Go to: **https://www.docker.com/products/docker-desktop**
2. Download the **Windows** version and install it
3. After installing, open **Docker Desktop** and wait for it to say **"Engine running"**

> ⚠️ Make sure Docker Desktop is **open and running** before doing anything below.

---

## ✅ Step 2 — Get the Project Files

Download the project folder from the shared link and extract it somewhere easy, for example:

```
D:\EPG\
```

The folder should look like this after extracting:

```
EPG/
├── docker-compose.yml
├── test_pipeline.py
├── orchestrator/
├── malware-scanner/
├── spam-filter/
├── phishing-filter/
└── shared/
```

---

## ✅ Step 3 — Build & Start Everything

Open **PowerShell** (or Windows Terminal), navigate to the EPG folder, and run:

```powershell
cd D:\EPG
docker compose up --build
```

> This will:
> - Build all 3 scanner images (spam, phishing, malware)
> - Start all containers automatically
> - **First time will take ~5-10 minutes** (downloading Python, installing packages)
> - Next time will be fast (cached)

Wait until you see lines like:
```
epg-spam      | INFO:     Application startup complete.
epg-phishing  | INFO:     Application startup complete.
epg-malware   | INFO:     Uvicorn running on http://0.0.0.0:8003
```

---

## ✅ Step 4 — Verify Everything is Running

Open a **new** PowerShell window (keep the first one running) and run:

```powershell
curl.exe http://localhost:8001/health
curl.exe http://localhost:8002/health
curl.exe http://localhost:8003/health
```

You should get:
```json
{"status":"healthy","service":"spam-filter"}
{"status":"healthy","service":"phishing-filter"}
{"status":"healthy","service":"malware-scanner","models_loaded":true}
```

If all 3 say healthy — you're good to go ✅

---

## ✅ Step 5 — Test the Pipeline

### Get a test email file (.eml)

To test, you need a `.eml` file (a saved email). You can get one by:

**In Gmail:**
1. Open any email
2. Click the 3 dots (⋮) → **Download message**
3. It saves as a `.eml` file

**To test the Malware Scanner specifically:**
- Download an email that has a **PDF or Word attachment**
- The malware scanner analyzes email attachments

### Run the test

```powershell
cd D:\EPG
python test_pipeline.py "C:\Users\YourName\Desktop\your_email.eml"
```

### Example output:

```
============================================================
  EPG Health Check
============================================================
  [OK]  Spam Filter      ->  healthy
  [OK]  Phishing Filter  ->  healthy
  [OK]  Malware Scanner  ->  healthy

============================================================
  File : your_email.eml
============================================================

  [1/3]  Spam Filter
         Verdict : HAM  |  Score: 21
         Time    : 1.2s

  [2/3]  Phishing Filter
         Verdict : CLEAN  |  Score: 12
         Time    : 0.1s

  [3/3]  Malware Scanner
         Verdict : CLEAN  |  Score: 5
         Time    : 0.4s

  ✅  CLEAN — passed all 3 stages.
  Total time: 1.7s
```

---

## 🛑 How to Stop

In the PowerShell window where `docker compose up` is running, press:

```
Ctrl + C
```

Or from any terminal:

```powershell
cd D:\EPG
docker compose down
```

---

## ❓ Troubleshooting

### "docker is not recognized"
→ Docker Desktop isn't open. Open it from the Start menu and wait for it to fully start.

### "port is already allocated"
→ Another app is using port 8001/8002/8003. Stop the old containers:
```powershell
docker compose down
docker compose up --build
```

### Container keeps restarting
→ Check the logs:
```powershell
docker logs epg-spam
docker logs epg-phishing
docker logs epg-malware
```

### Need Python for test_pipeline.py?
→ Install Python from **https://www.python.org/downloads/** (3.10 or higher)
→ Then install the only dependency needed:
```powershell
pip install requests
```

---

## 📋 Summary — 4 Commands Total

```powershell
# 1. Go to the project folder
cd D:\EPG

# 2. Build and start everything (first time only, takes ~10 min)
docker compose up --build

# 3. In a new terminal — test it's running
curl.exe http://localhost:8001/health

# 4. Scan an email
python test_pipeline.py "C:\path\to\email.eml"
```

---

*Built by the EPG team — Spam · Phishing · Malware Static Analysis*
