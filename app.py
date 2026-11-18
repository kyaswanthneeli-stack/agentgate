"""AgentGate: local tool policy gateway; never executes arbitrary tools or SQL."""
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

EMAIL = re.compile(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}')
SECRET = re.compile(r'\b(?:sk-[A-Za-z0-9_-]{8,}|AKIA[A-Z0-9]{16})\b')
INJECTION = re.compile(r'ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|reveal\s+(?:the\s+)?system\s+prompt', re.I)

def redact(value):
    if isinstance(value, str):
        return SECRET.sub('[REDACTED_KEY]', EMAIL.sub('[REDACTED_EMAIL]', value))
    if isinstance(value, dict):
        return {k: '[REDACTED_SECRET]' if k.lower() in {'password','token','api_key','authorization','secret'} else redact(v) for k,v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value

class Call(BaseModel):
    session: str = Field(min_length=1, max_length=80, pattern=r'^[a-zA-Z0-9_-]+$')
    tool: str = Field(min_length=1, max_length=80)
    arguments: dict = Field(default_factory=dict)
    approval: str | None = None

def fingerprint(call):
    raw=json.dumps([call.session,call.tool,call.arguments],sort_keys=True,separators=(',',':'))
    return hashlib.sha256(raw.encode()).hexdigest()

def create_app(client_key=None, admin_key=None, limit=10, clock=time.time):
    client_key=client_key or os.getenv('AGENTGATE_CLIENT_KEY')
    admin_key=admin_key or os.getenv('AGENTGATE_ADMIN_KEY')
    signing=secrets.token_bytes(32)
    lock=threading.Lock(); counts={}; approvals={}; audit=[]
    app=FastAPI(title='AgentGate',version='0.1.0')
    def auth(provided,expected):
        if not expected or not provided or not hmac.compare_digest(provided,expected):
            raise HTTPException(401,'Valid API key required; set server environment keys first')
    def policy(call):
        text=json.dumps(call.arguments)
        if len(text)>16000: return 'payload_too_large'
        if call.tool not in {'search_docs','send_notification'}: return 'tool_not_allowed'
        if INJECTION.search(text): return 'instruction_override_pattern'
        if call.tool=='search_docs' and (set(call.arguments)!={'query'} or not isinstance(call.arguments.get('query'),str)): return 'invalid_tool_arguments'
        if call.tool=='send_notification' and (set(call.arguments)!={'message'} or not isinstance(call.arguments.get('message'),str)): return 'invalid_tool_arguments'
        return None
    @app.get('/health')
    def health(): return {'status':'ok','mode':'local demonstration tools'}
    @app.post('/approvals')
    def approve(call:Call,x_admin_key:str|None=Header(default=None)):
        auth(x_admin_key,admin_key)
        reason=policy(call)
        if reason: raise HTTPException(403,reason)
        if call.tool!='send_notification': raise HTTPException(400,'Tool does not require approval')
        with lock:
            now=clock()
            for key in list(approvals):
                if approvals[key][1]<now: del approvals[key]
            if len(approvals)>=1000: raise HTTPException(429,'Approval capacity reached')
            nonce=secrets.token_hex(16); digest=fingerprint(call)
            token=nonce+'.'+hmac.new(signing,(nonce+digest).encode(),hashlib.sha256).hexdigest()
            approvals[token]=(digest,now+60)
        return {'approval':token,'expires_in_seconds':60}
    @app.post('/tools/call')
    def execute(call:Call,x_api_key:str|None=Header(default=None)):
        auth(x_api_key,client_key)
        reason=policy(call)
        if reason: raise HTTPException(403,reason)
        with lock:
            if call.session not in counts and len(counts)>=1000: raise HTTPException(429,'Session capacity reached')
            if counts.get(call.session,0)>=limit: raise HTTPException(429,'Session call limit reached')
            if call.tool=='send_notification':
                approved=approvals.get(call.approval)
                if not approved or approved[0]!=fingerprint(call) or approved[1]<clock():
                    raise HTTPException(403,'Valid request-bound approval required')
                del approvals[call.approval]
            counts[call.session]=counts.get(call.session,0)+1
            safe=redact(call.arguments)
            # Fixed demo adapters only. No SQL, shell, external email or arbitrary network execution.
            result={'matches':[{'title':'Operations handbook','excerpt':'Use reviewed, allowlisted tools.'}],'query':safe['query']} if call.tool=='search_docs' else {'queued':False,'simulation':True,'message':safe['message']}
            audit.append({'session':call.session,'tool':call.tool,'decision':'allowed','arguments_digest':fingerprint(call)})
            del audit[:-1000]
        return {'decision':'allow','sanitized_arguments':safe,'result':redact(result),'calls_used':counts[call.session]}
    @app.get('/audit')
    def events(x_admin_key:str|None=Header(default=None)):
        auth(x_admin_key,admin_key)
        with lock: return list(audit)
    return app
app=create_app()
