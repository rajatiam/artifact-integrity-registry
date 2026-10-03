import csv, hashlib, io, json, math, re
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from .validation import validate_input, http_url, unique

def now(): return datetime.now(timezone.utc).isoformat()
def validate(data,records): return initialize(validate_input(data,CONFIG['example']),records)

def initialize(row,records):
    if not re.fullmatch(r'[a-zA-Z0-9._-]{1,60}',row['name']) or not re.fullmatch(r'[a-zA-Z0-9._-]{1,60}',row['artifact_version']): raise ValueError('Use safe artifact name and version identifiers')
    unique(records,row,['name','artifact_version']); payload=row['content'].encode()
    return dict(row,sha256=hashlib.sha256(payload).hexdigest(),bytes=len(payload),verified=False)
def summary(rows): return {'artifacts':len(rows),'stored_bytes':sum(r['bytes'] for r in rows),'verified':sum(r['verified'] for r in rows)}
def transition(row,action):
    if action!='verify': raise ValueError('Unsupported action')
    if hashlib.sha256(row['content'].encode()).hexdigest()!=row['sha256']: raise ValueError('Artifact integrity mismatch')
    return dict(row,verified=True)
