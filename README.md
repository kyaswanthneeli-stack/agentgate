# AgentGate

**Inspect agent tool requests before execution.** An independent Python engineering project by Neeli Yaswanth Kumar.

[Interactive demonstration](https://kyaswanthneeli-stack.github.io/projects/agentgate.html) · [Portfolio](https://kyaswanthneeli-stack.github.io/)

## What this release implements

A FastAPI service with a fixed tool allowlist, argument validation, recursive email/key-pattern redaction, selected instruction-override detection, atomic per-session call limits, and request-bound one-use approvals. Client and administrator credentials are separate. The two tool adapters are intentionally local demonstrations: document search returns a fixture; notification execution returns a simulated result without sending anything.

This is a policy gateway prototype, **not a complete prompt-injection firewall or MCP proxy**. It has no trained local classifier, monetary budget accounting, arbitrary tool forwarding or production compliance certification.

## Run locally

```bash
git clone https://github.com/kyaswanthneeli-stack/agentgate.git
cd agentgate
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export AGENTGATE_CLIENT_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export AGENTGATE_ADMIN_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
uvicorn app:app --host 127.0.0.1 --port 8000 --workers 1
```

Open `http://127.0.0.1:8000/docs`. The interactive API documentation explains each input. Keep administrator credentials away from agents. Missing credentials fail closed.

In a second terminal with the same client environment variable:

```bash
curl http://127.0.0.1:8000/tools/call \
  -H "X-API-Key: $AGENTGATE_CLIENT_KEY" -H 'Content-Type: application/json' \
  -d '{"session":"demo","tool":"search_docs","arguments":{"query":"onboarding"}}'
```

### Approval walkthrough

1. Submit `send_notification` with `arguments: {"message":"Release ready"}` to `/tools/call`. It returns 403 without approval.
2. An administrator sends the **same session, tool and arguments** to `/approvals` with `X-Admin-Key`.
3. Copy the returned `approval` into the original tool request. Submit with the client key within 60 seconds.
4. Changing any bound field, reusing the approval or waiting past expiry causes rejection. Approval cannot override an unknown tool or blocked pattern.
5. `/audit` requires the administrator key. It returns successful execution metadata and request digests rather than raw arguments. Denied requests are not currently recorded.

## Architecture

```mermaid
flowchart TD
 A[Authenticated request] --> B[Allowlist and argument policy]
 B --> C[Atomic call limit and approval check]
 C --> D[Recursive redaction]
 D --> E[Fixed demonstration adapter]
 E --> F[Redacted result and bounded audit]
```

A process-local lock protects counters and approval consumption. Approval tokens contain a random nonce and HMAC and are stored against a canonical request digest. An approval is valid only while present in this process's registry. Restarting invalidates tokens and resets counters.

## Verify

```bash
python -m unittest -v
```

19 tests cover authentication, policy denial, nested redaction, output redaction, concurrent limit enforcement, approval binding, replay, expiry and administrator separation. These are correctness checks for implemented controls, not evidence of comprehensive attack resistance.

## Deployment and limits

`docs/index.html` calls the deployed Python API for policy inspection and lexical search. It does not issue administrator approvals or execute privileged tools. A Dockerfile is included for a backend host; set both credentials at runtime and use a TLS reverse proxy. Do not publish these credentials in GitHub or frontend code.

Run **one worker only**: state is in memory, not shared or durable. Session identifiers are caller-selected, so a caller can evade a per-session cap by creating another session; this is not a tenant billing control. There are at most 1,000 active sessions/approvals and 1,000 retained audit events. Counts reset on restart. HTTP ingress size/rate limits and authenticated principal-to-session binding are deployment responsibilities. Regex checks miss obfuscated, multilingual and indirect attacks; PII redaction is incomplete. Request digests can still permit guessing of predictable input. No external tool execution is secured by this prototype.

Next steps: durable principal-bound quotas, an actual MCP adapter, security evaluation corpus, classifier comparison, denied-event auditing, approval UI and adversarial testing.

## Engineering verification and deployment

[![CI](https://github.com/kyaswanthneeli-stack/agentgate/actions/workflows/ci.yml/badge.svg)](https://github.com/kyaswanthneeli-stack/agentgate/actions/workflows/ci.yml)

- [Architecture diagram, five-minute walkthrough and hosting checklist](docs/ARCHITECTURE_AND_DEMO.md)
- [GitHub Actions test and Docker build results](https://github.com/kyaswanthneeli-stack/agentgate/actions/workflows/ci.yml)
- [Railway deployment configuration](railway.json) using the existing Dockerfile and `/health` endpoint.

**Hosting status:** deployed on Railway at https://agentgate-production-00036f18.up.railway.app/docs. The portfolio now calls the public, bounded backend endpoints described below. Privileged endpoints remain authenticated; no credentials are shipped to the browser.

## Captioned architecture video

[Download the 20-second MP4 architecture explainer from the latest successful Actions run](https://github.com/kyaswanthneeli-stack/agentgate/actions/workflows/walkthrough.yml). The source-of-truth render script is [docs/build_walkthrough.py](docs/build_walkthrough.py). The video is **captioned and silent** and explains the code architecture; it is **not** a recording of a live external API or paid model. Use the demo instructions above to show real backend behavior.

## Live hosted API — verified

**Public API documentation:** https://agentgate-production-00036f18.up.railway.app/docs

**Unauthenticated health endpoint:** https://agentgate-production-00036f18.up.railway.app/health

[![Live public API smoke test](https://github.com/kyaswanthneeli-stack/agentgate/actions/workflows/deployment-smoke.yml/badge.svg)](https://github.com/kyaswanthneeli-stack/agentgate/actions/workflows/deployment-smoke.yml)

This is a live Railway-hosted Python backend, built from the public GitHub repository. GitHub-hosted smoke tests verify that `/health` returns a valid healthy JSON response, `/docs` serves Swagger UI, and the protected endpoint rejects requests without authentication (HTTP 401). **Secrets are stored as Railway backend environment variables, never in this repository.** The publicly viewable API documentation doesn't grant access to privileged operations. Tool adapters are deliberately simulated; notifications are not actually sent. For architecture and setup details, see [the engineering walkthrough](docs/ARCHITECTURE_AND_DEMO.md).

## Live browser workflow

1. Open the linked portfolio page and choose a request example.
2. Click **Inspect on server**. The browser posts to `/public/inspect`; the real Python policy engine returns the decision and sanitized arguments. Inspection does not execute a tool or grant approval.
3. Paste non-sensitive text into the document search panel, separating documents with a blank line. Click **Search on server** to call `/public/search`. It ranks the submitted documents using lexical word counts.
4. Inspect the JSON response, including its operation mode, processed-document count and matching excerpts.

The page shows connection errors explicitly and never silently substitutes a local result. `/public/status` checks availability. Only the portfolio origin is allowed by CORS. Public operations are bounded and perform no external notifications, paid calls or privileged execution. Avoid submitting confidential documents: this is a public portfolio service. No visitor text is deliberately persisted by these handlers. Public endpoint payload validation is not an ingress rate limiter; deploy platform-level rate controls before broader use.
