"""Server-owned API identity; caller headers cannot grant access."""
import json
import os
import secrets
from urllib.parse import parse_qs
from starlette.responses import JSONResponse
from backend.db.session import request_workspace

class AuthenticationMiddleware:
    def __init__(self, app): self.app = app
    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope['method'] == 'OPTIONS' or scope['path'] in ('/health', '/health/live', '/health/ready', '/api/health', '/docs', '/redoc', '/openapi.json'):
            return await self.app(scope, receive, send)
        # Explicit development demo is isolated from normal credentialed operation.
        demo = os.getenv('CYBERGUARD_DEMO_MODE', 'false').lower() == 'true'
        required = os.getenv('CYBERGUARD_REQUIRE_AUTH', 'true').lower() != 'false'
        if demo and not required and all(os.getenv(key, 'development').lower() not in ('production','staging') for key in ('ENVIRONMENT','CYBERGUARD_ENV')):
            return await self.app(scope, receive, send)
        headers = dict(scope.get('headers', []))
        authorization = headers.get(b'authorization', b'').decode()
        token = authorization[7:] if authorization.startswith('Bearer ') else ''
        actor = None
        try:
            configured = json.loads(os.getenv('CYBERGUARD_SERVER_CREDENTIALS', '{}'))
            for candidate, value in configured.items():
                if token and secrets.compare_digest(token, candidate): actor = value; break
            valid = (isinstance(actor, dict) and isinstance(actor.get('actor_id'), str) and actor['actor_id'].strip()
                and actor.get('role') in ('analyst','admin','platform_admin','security_admin','tenant_admin','security_lead','viewer')
                and isinstance(actor.get('workspaces'), list) and actor['workspaces']
                and all(isinstance(item,str) and item.strip() for item in actor['workspaces']))
        except (ValueError, TypeError, AttributeError): valid = False
        if not valid:
            return await JSONResponse({'detail':'A valid server-issued access token is required.'},401)(scope,receive,send)
        query = parse_qs(scope.get('query_string', b'').decode())
        selected = headers.get(b'x-workspace-id', headers.get(b'x-tenant-id', b'')).decode()
        requested = query.get('workspace_id', query.get('tenant_id', []))
        if not selected: selected = requested[0] if requested else next((w for w in actor['workspaces'] if w != '*'), 'default')
        if any(value != selected for value in requested) or (b'x-tenant-id' in headers and headers[b'x-tenant-id'].decode() != selected):
            return await JSONResponse({'detail':'Conflicting workspace selection.'},403)(scope,receive,send)
        privileged = actor['role'] in ('admin','platform_admin')
        if selected not in actor['workspaces'] and not (privileged and '*' in actor['workspaces']):
            return await JSONResponse({'detail':'Workspace access denied.'},403)(scope,receive,send)
        if '*' in actor['workspaces'] and not privileged:
            return await JSONResponse({'detail':'Invalid server membership configuration.'},403)(scope,receive,send)
        if actor['role'] == 'viewer' and scope['method'] not in ('GET','HEAD'):
            return await JSONResponse({'detail':'Read-only identity.'},403)(scope,receive,send)
        for key in (b'x-role',b'x-user-role'):
            if key in headers and headers[key].decode().lower() != actor['role']:
                return await JSONResponse({'detail':'Role headers cannot change server privileges.'},403)(scope,receive,send)
        role = 'platform_admin' if actor['role']=='admin' and scope['path'].startswith('/api/admin') else actor['role']
        for key in (b'x-user',b'x-actor-id',b'x-user-id',b'x-user-name'): headers[key] = actor['actor_id'].encode()
        headers[b'x-role'] = headers[b'x-user-role'] = role.encode()
        headers[b'x-workspace-id'] = headers[b'x-tenant-id'] = selected.encode()
        scope['headers'] = list(headers.items())
        scope.setdefault('state',{})['actor'] = actor
        scope['state']['workspace_id'] = selected
        context = request_workspace.set(selected)
        try: return await self.app(scope,receive,send)
        finally: request_workspace.reset(context)
