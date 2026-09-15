## Quickest Option: Upload to GitHub Directly in Browser (Takes 60 Seconds - No Git Installation Needed!)

If you do not have Git installed on your computer, you can push the project in 1 minute directly from your browser:

1. Open your browser and go to [https://github.com/new](https://github.com/new).
2. Repository Name: `AI-Phishing-URL-Detector` (or `phishing-url-detection-system`).
3. Description: `AI-Powered Phishing URL Detection System using 22 cybersecurity features, Random Forest, Flask Web Dashboard, and REST API.`
4. Set to **Public**.
5. Click **Create repository**.
6. On the new repository page, click the link: **"uploading an existing file"** (or "upload files").
7. Open Windows File Explorer and navigate to:
   `c:\Users\HAIDER HASHMI\Documents\ali haider 391 sec\AI-Phishing-URL-Detector`
8. Drag and drop all the files and folders (`src`, `tests`, `saved_models`, `docs`, `README.md`, `requirements.txt`, etc.) into the GitHub upload page.
9. Click **Commit changes**. Done! Your GitHub repo is 100% live!

---

## Option 2: Using Git CLI

If you prefer using the command line:

### Step 1: Install Git (via PowerShell)
Run this command in PowerShell:
```powershell
winget install --id Git.Git -e --source winget
```
*(After installation finishes, restart your PowerShell terminal.)*

### Step 2: Initialize & Push
```powershell
cd "c:\Users\HAIDER HASHMI\Documents\ali haider 391 sec\AI-Phishing-URL-Detector"
git init
git add .
git commit -m "feat: initial commit - AI-powered phishing URL detection system with ML pipeline, Web UI, and REST API"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/AI-Phishing-URL-Detector.git
git push -u origin main
```

---

### Step 6: Add GitHub Link to Your CV!
Now copy the link `https://github.com/YOUR_USERNAME/AI-Phishing-URL-Detector` and put it right next to your project title in your resume!
