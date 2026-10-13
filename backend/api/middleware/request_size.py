"""Bound body consumption before multipart parsing."""
from starlette.responses import JSONResponse
from fastapi import HTTPException
class RequestSizeMiddleware:
    def __init__(self,app): self.app=app
    async def __call__(self,scope,receive,send):
        if scope['type']!='http': return await self.app(scope,receive,send)
        headers=dict(scope.get('headers',[]));limit=64*1024*1024 if b'multipart/form-data' in headers.get(b'content-type',b'') else 10*1024*1024
        try: length=int(headers.get(b'content-length',b'0'))
        except ValueError: length=0
        if length>limit: return await JSONResponse({'detail':'Request exceeds size limit.'},413)(scope,receive,send)
        count=0;exceeded=False;responded=False
        async def bounded_receive():
            nonlocal count,exceeded
            message=await receive();count+=len(message.get('body',b''))
            if count>limit: exceeded=True;raise HTTPException(413,'Request exceeds size limit.')
            return message
        async def bounded_send(message):
            nonlocal responded
            if exceeded:
                if not responded:
                    responded=True
                    await JSONResponse({'detail':'Request exceeds size limit.'},413)(scope,receive,send)
                return
            await send(message)
        await self.app(scope,bounded_receive,bounded_send)
