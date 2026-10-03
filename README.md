# Sovereign Secret Scanner - GitHub App

Automated secret scanning with business impact valuation.

## Features
- Scans repos for 13 secret types (AWS, Stripe, GitHub, RSA keys, etc.)
- Values findings via RevenueEngine ($1K-$10K per secret)
- GitHub App webhook on push/PR
- REST API for manual scans

## Deployment to Railway

1. Connect this repo to Railway
2. Set environment variables:
   - `GITHUB_TOKEN` - GitHub PAT with repo:read, issues:write, checks:write
   - `BOUNTY_OPERATOR_SECRET` - HMAC secret for approval tokens (optional)
3. Deploy - Railway auto-detects Python + uvicorn

## Endpoints
- `GET /health` - Health check
- `POST /scan` - Manual scan (body: `{repo_url, branch}`)
- `POST /webhook` - GitHub App webhook (push, pull_request)

## Local Development
```bash
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8080
```
