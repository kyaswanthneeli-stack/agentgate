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
from fastapi.middleware.cors import CORSMiddleware
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
    app=FastAPI(title='AgentGate',version='0.2.0')
    app.add_middleware(CORSMiddleware,
        allow_origins=['https://kyaswanthneeli-stack.github.io'],
        allow_methods=['GET','POST'],
        allow_headers=['content-type'])
    class PublicSearch(BaseModel):
        query: str = Field(min_length=1,max_length=200)
        documents: list[str] = Field(min_length=1,max_length=12)
    @app.get('/public/status')
    def public_status():
        return {'status':'ok','policy':'operational','text_search':'operational',
                'external_notifications':False}
    @app.post('/public/inspect')
    def public_inspect(call:Call):
        # Evaluate the real policy engine. This does not authorize or execute tools.
        if len(json.dumps(call.arguments,ensure_ascii=True))>4000:
            raise HTTPException(413,'Payload exceeds public inspection limit')
        reason=policy(call)
        decision=('block' if reason else
                  'approval_required' if call.tool=='send_notification' else 'allow')
        return {'decision':decision,'reason':reason or
                ('Request-bound administrator approval is required'
                 if decision=='approval_required' else 'Tool request passes policy checks'),
                'sanitized_arguments':redact(call.arguments),
                'executed':False,'approval_issued':False,
                'mode':'live_server_policy_inspection'}
    @app.post('/public/search')
    def public_search(payload:PublicSearch):
        # Search text that a visitor submits now; no stored or fabricated results.
        if any(len(doc)>2000 for doc in payload.documents):
            raise HTTPException(413,'Each document must contain at most 2000 characters')
        check=Call(session='public',tool='search_docs',arguments={'query':payload.query})
        denial=policy(check)
        if denial: raise HTTPException(403,denial)
        terms=set(re.findall(r'[a-z0-9]{2,}',payload.query.lower()))
        results=[]
        for i,doc in enumerate(payload.documents):
            words=re.findall(r'[a-z0-9]{2,}',doc.lower())
            hits=sum(words.count(term) for term in terms)
            if hits:
                results.append({'document_index':i,'score':hits,
                                'excerpt':redact(doc[:500])})
        results.sort(key=lambda item:(-item['score'],item['document_index']))
        return {'query':redact(payload.query),'matches':results[:8],
                'total_matches':len(results),'processed_documents':len(payload.documents),
                'mode':'real_lexical_document_search',
                'note':'Deterministic search of caller-supplied text; no LLM or external messaging.'}

    def auth(provided,expected):
        if not expected or not provided or not hmac.compare_digest(provided.encode('utf-8'),expected.encode('utf-8')):
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
                if approvals[key][1]<=now: del approvals[key]
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
                if not approved or approved[0]!=fingerprint(call) or approved[1]<=clock():
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
