"""
Secret Scanning GitHub App - FastAPI Service
Scans repos for secrets, values them via RevenueEngine, reports to owners.
"""
import os, re, json, hmac, hashlib, logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from pydantic import BaseModel
import subprocess
import tempfile
import shutil

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secret-scanner")

app = FastAPI(title="Secret Scanner GitHub App")

# Secret patterns (from your credential_vault + whale_scraper)
SECRET_PATTERNS = {
    "AWS_ACCESS_KEY_ID": (r"AKIA[0-9A-Z]{16}", 5000.0),
    "AWS_SECRET_ACCESS_KEY": (r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s:=]+[A-Za-z0-9/+=]{40}", 5000.0),
    "RSA_PRIVATE_KEY": (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", 10000.0),
    "STRIPE_KEY": (r"(sk_live|rk_live)_[a-zA-Z0-9]{24,}", 7500.0),
    "OPENAI_KEY": (r"sk-[a-zA-Z0-9]{48}", 2000.0),
    "ANTHROPIC_KEY": (r"sk-ant-[a-zA-Z0-9\-_]{95,}", 2000.0),
    "GITHUB_PAT": (r"gh[pousr]_[a-zA-Z0-9]{36,255}", 3000.0),
    "GITHUB_TOKEN": (r"gho_[a-zA-Z0-9]{36}", 3000.0),
    "DATABASE_URI": (r"(postgres|mysql|mongodb)://[^:\s]+:[^@\s]+@[^\s]+", 4000.0),
    "SLACK_TOKEN": (r"xox[baprs]-[a-zA-Z0-9\-]{10,}", 1500.0),
    "DISCORD_TOKEN": (r"[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}", 1000.0),
    "SENDGRID_KEY": (r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}", 2000.0),
    "TWILIO_SID": (r"AC[a-f0-9]{32}", 1500.0),
    "HIGH_ENTROPY_TOKEN": (r"(?i)(api[_\-]?key|secret|token|password)[\s:=]+[A-Za-z0-9_\-]{32,}", 1000.0),
}

# Value map from your revenue_engine
SECRET_VALUE_MAP = {
    "AWS_ACCESS_KEY_ID": 5000.0, "AWS_SECRET_ACCESS_KEY": 5000.0,
    "RSA_PRIVATE_KEY": 10000.0, "STRIPE_KEY": 7500.0,
    "OPENAI_KEY": 2000.0, "ANTHROPIC_KEY": 2000.0,
    "GITHUB_PAT": 3000.0, "GITHUB_TOKEN": 3000.0,
    "DATABASE_URI": 4000.0, "SLACK_TOKEN": 1500.0,
    "DISCORD_TOKEN": 1000.0, "SENDGRID_KEY": 2000.0,
    "TWILIO_SID": 1500.0, "HIGH_ENTROPY_TOKEN": 1000.0,
}

class ScanRequest(BaseModel):
    repo_url: str
    branch: str = "main"
    deep_scan: bool = False

class Finding(BaseModel):
    type: str
    file: str
    line: int
    match: str
    value_usd: float
    severity: str

class ScanResult(BaseModel):
    repo: str
    scanned_at: str
    findings: List[Finding]
    total_value: float
    risk_level: str

def scan_file(content: str, filepath: str) -> List[Finding]:
    findings = []
    lines = content.split("\n")
    for i, line in enumerate(lines, 1):
        for stype, (pattern, value) in SECRET_PATTERNS.items():
            matches = re.finditer(pattern, line)
            for m in matches:
                # Mask the secret in output
                masked = m.group()[:4] + "*" * (len(m.group()) - 8) + m.group()[-4:] if len(m.group()) > 8 else "****"
                severity = "Critical" if value >= 5000 else "High" if value >= 2000 else "Medium"
                findings.append(Finding(
                    type=stype,
                    file=filepath,
                    line=i,
                    match=masked,
                    value_usd=value,
                    severity=severity
                ))
    return findings

def scan_repo(repo_url: str, branch: str = "main") -> ScanResult:
    """Clone repo (shallow) and scan for secrets."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = os.path.join(tmpdir, "repo")
        # Shallow clone
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", branch, repo_url, repo_dir],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            raise HTTPException(400, f"Clone failed: {result.stderr}")
        
        all_findings = []
        total_value = 0.0
        for root, dirs, files in os.walk(repo_dir):
            # Skip .git, node_modules, vendor, etc.
            dirs[:] = [d for d in dirs if d not in [".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", "dist", "build"]]
            for f in files:
                if f.endswith((".py", ".js", ".ts", ".json", ".yaml", ".yml", ".env", ".config", ".ini", ".toml", ".sh", ".bash", ".zsh", ".tf", ".tfvars", ".pem", ".key", ".crt", ".crt", ".csr")):
                    fpath = os.path.join(root, f)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        rel_path = os.path.relpath(fpath, repo_dir)
                        findings = scan_file(content, rel_path)
                        all_findings.extend(findings)
                        total_value += sum(f.value_usd for f in findings)
                    except Exception as e:
                        logger.debug(f"Failed to scan {fpath}: {e}")
        
        risk = "Critical" if total_value >= 10000 else "High" if total_value >= 5000 else "Medium" if total_value >= 1000 else "Low"
        repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        
        return ScanResult(
            repo=repo_name,
            scanned_at=datetime.utcnow().isoformat(),
            findings=all_findings,
            total_value=round(total_value, 2),
            risk_level=risk
        )

@app.post("/scan", response_model=ScanResult)
async def scan_endpoint(req: ScanRequest, background_tasks: BackgroundTasks):
    """Scan a repository for secrets."""
    try:
        result = scan_repo(req.repo_url, req.branch)
        return result
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise HTTPException(500, str(e))

@app.post("/webhook")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """GitHub App webhook - triggers on push/PR."""
    payload = await request.json()
    event = request.headers.get("X-GitHub-Event")
    
    if event in ["push", "pull_request"]:
        repo = payload.get("repository", {})
        repo_url = repo.get("clone_url") or repo.get("ssh_url")
        branch = payload.get("ref", "refs/heads/main").replace("refs/heads/", "")
        
        if repo_url:
            background_tasks.add_task(scan_and_report, repo_url, branch, repo.get("full_name"))
            return {"status": "queued", "repo": repo.get("full_name")}
    
    return {"status": "ignored", "event": event}

async def scan_and_report(repo_url: str, branch: str, full_name: str):
    """Background task: scan repo and send report."""
    try:
        result = scan_repo(repo_url, branch)
        # Here you'd send email/Slack/webhook to repo owner
        logger.info(f"Scan complete for {full_name}: {len(result.findings)} findings, ${result.total_value}")
        # TODO: Send email/webhook to owner with report + upsell
    except Exception as e:
        logger.error(f"Background scan failed for {full_name}: {e}")

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "secret-scanner"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
