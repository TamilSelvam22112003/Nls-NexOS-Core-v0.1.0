import logging,os
from fastapi import FastAPI,Header,HTTPException,Request
from fastapi.responses import JSONResponse
from . import __version__
from .ca import CertificateAuthority,EnrollmentDenied
from .config import Settings,token_from_environment_or_file
from .database import Registry
from .models import EnrollmentRequest,EnrollmentResponse,HealthResponse

def create_app(settings=None):
 if settings is None:settings=Settings.load(os.environ.get('NLS_CA_CONFIG','/etc/nls-nexos-core/router-ca.yaml'))
 registry=Registry(settings.database_path); token=token_from_environment_or_file(settings); ca=CertificateAuthority(settings,registry,token); app=FastAPI(title='NLS Router-CA',version=__version__)
 @app.middleware('http')
 async def request_size_limit(request:Request,call_next):
  size=request.headers.get('content-length','')
  if size.isdigit() and int(size)>settings.max_request_bytes:return JSONResponse(status_code=413,content={'detail':'request too large'})
  return await call_next(request)
 @app.get('/health',response_model=HealthResponse)
 async def health():return HealthResponse()
 @app.post('/api/v1/enroll',response_model=EnrollmentResponse)
 async def enroll(req:EnrollmentRequest,x_nls_bootstrap_token:str=Header(default=''),x_nls_router_token:str=Header(default='')):
  try:return ca.enroll(req,x_nls_bootstrap_token,x_nls_router_token)
  except EnrollmentDenied as exc:raise HTTPException(status_code=403,detail='enrollment denied') from exc
  except Exception as exc:logging.exception('enrollment internal error');raise HTTPException(status_code=500,detail='internal error') from exc
 @app.get('/api/v1/policy')
 async def policy():raise HTTPException(status_code=501,detail='NLS policy channel not implemented')
 @app.get('/api/v1/revocation')
 async def revocation():raise HTTPException(status_code=501,detail='revocation endpoint not implemented')
 return app