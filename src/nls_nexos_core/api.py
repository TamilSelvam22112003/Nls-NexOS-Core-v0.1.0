from contextlib import asynccontextmanager
import hashlib
import logging
import time

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from . import __version__
from .ca import CertificateAuthority, EnrollmentDenied
from .config import Settings, token_from_environment_or_file
from .database import Registry
from .models import EnrollmentRequest, EnrollmentResponse, HealthResponse


def create_app(settings: Settings | None = None) -> FastAPI:
    if settings is None:
        from os import environ
        settings_path = environ.get("NLS_CA_CONFIG", "/etc/nls-nexos-core/router-ca.yaml")
        settings = Settings.load(settings_path)
    registry = Registry(settings.database_path)
    token = token_from_environment_or_file(settings)
    ca = CertificateAuthority(settings, registry, token)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.registry = registry
        app.state.ca = ca
        yield

    app = FastAPI(title="NLS Router-CA", version=__version__, lifespan=lifespan)

    @app.middleware("http")
    async def request_size_limit(request: Request, call_next):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > settings.max_request_bytes:
            return JSONResponse(status_code=413, content={"detail":"request too large"})
        return await call_next(request)

    @app.get("/health", response_model=HealthResponse)
    async def health():
        return HealthResponse()

    @app.post("/api/v1/enroll", response_model=EnrollmentResponse)
    async def enroll(req: EnrollmentRequest, x_nls_enrollment_token: str = Header(default="")):
        try:
            return ca.enroll(req, x_nls_enrollment_token)
        except EnrollmentDenied:
            raise HTTPException(status_code=403, detail="enrollment denied")
        except Exception as exc:
            logging.exception("enrollment internal error")
            raise HTTPException(status_code=500, detail="internal error") from exc

    @app.get("/api/v1/policy")
    async def policy():
        # TODO: require verified mTLS client certificate at the TLS terminator and map
        # the authenticated certificate SAN to an active router registry entry.
        raise HTTPException(status_code=501, detail="mTLS policy endpoint not enabled yet")

    @app.get("/api/v1/revocation")
    async def revocation():
        # TODO: publish signed CRL / status endpoint. Do not imply revocation is ready.
        raise HTTPException(status_code=501, detail="revocation endpoint not enabled yet")

    return app
