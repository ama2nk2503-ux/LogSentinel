from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from api.routes_auth import router as auth_router
from api.routes_alerts import router as alerts_router
from api.routes_detections import router as detections_router
from api.routes_dashboard import router as dashboard_router
from api.routes_events import router as events_router
from api.routes_export import router as export_router
from api.routes_graph import router as graph_router
from api.routes_intel import router as intel_router
from api.routes_ioc import router as ioc_router
from api.routes_jobs import router as jobs_router
from api.routes_benchmark import router as benchmark_router
from api.routes_policy import router as policy_router
from api.routes_query import router as query_router
from api.routes_samples import router as samples_router
from api.routes_stream import router as stream_router
from api.routes_threats import router as threats_router
from api.routes_upload import router as upload_router
from api.routes_geo import router as geo_router
from api.routes_audit import router as audit_router
from api.routes_assets import router as assets_router
from api.routes_ml import router as ml_router
from core.auth import decode_token, seed_admin
from core.alerts import seed_alert_rules
from core.config import settings
from core.intel import seed_intel_reference
from core.storage import init_db

app = FastAPI(title="LogSentinel", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

AUTH_EXEMPT_PREFIXES = ("/api/auth/login", "/api/auth/register", "/api/health")


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    if any(path.startswith(p) for p in AUTH_EXEMPT_PREFIXES):
        return await call_next(request)
    if not path.startswith("/api/"):
        return await call_next(request)
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or not decode_token(auth[7:]):
        return Response('{"detail":"Unauthorized"}', status_code=401, media_type="application/json")
    return await call_next(request)


app.include_router(auth_router, prefix="/api")
app.include_router(upload_router, prefix="/api")
app.include_router(jobs_router, prefix="/api")
app.include_router(events_router, prefix="/api")
app.include_router(ioc_router, prefix="/api")
app.include_router(detections_router, prefix="/api")
app.include_router(threats_router, prefix="/api")
app.include_router(policy_router, prefix="/api")
app.include_router(intel_router, prefix="/api")
app.include_router(export_router, prefix="/api")
app.include_router(stream_router, prefix="/api")
app.include_router(dashboard_router, prefix="/api")
app.include_router(samples_router, prefix="/api")
app.include_router(graph_router, prefix="/api")
app.include_router(query_router, prefix="/api")
app.include_router(benchmark_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(geo_router, prefix="/api")
app.include_router(audit_router, prefix="/api")
app.include_router(assets_router, prefix="/api")
app.include_router(ml_router, prefix="/api")


@app.on_event("startup")
def startup() -> None:
    init_db()
    seed_admin()
    seed_alert_rules()
    seed_intel_reference()


@app.get("/api/health")
def health():
    return {"status": "ok", "version": app.version}
