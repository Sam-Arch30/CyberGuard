from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from backend.api.routes.email import router as email_router
from backend.api.routes.cases import router as cases_router
from backend.api.routes.correlation import router as correlation_router
from backend.api.routes.reports import router as reports_router
from backend.api.routes.audit import router as audit_router, evidence_router
from backend.api.routes.dashboard import router as dashboard_router
from backend.api.routes.attribution import router as attribution_router
from backend.api.routes.confidence import router as confidence_router
from backend.api.routes.cross_investigation import router as cross_investigation_router
from backend.api.routes.copilot import router as copilot_router
from backend.api.routes.benchmark import router as benchmark_router
from backend.api.routes.intelligence import router as intelligence_router
from backend.api.routes.unified import router as unified_router
from backend.api.routes.ingest import router as ingest_router
from backend.api.routes.urls import router as urls_router
from backend.api.routes.files import router as files_router
from backend.api.routes.auth_security import router as auth_security_router
from backend.api.routes.network_security import router as network_security_router
from backend.api.routes.api_security import router as api_security_router
from backend.api.routes.impersonation import router as impersonation_router
from backend.api.routes.multimedia import router as multimedia_router
from backend.api.routes.knowledge_graph import router as knowledge_graph_router
from backend.api.routes.cross_incident import router as cross_incident_router
from backend.api.routes.temporal_correlation import router as temporal_correlation_router
from backend.api.routes.attack_reconstruction import router as attack_reconstruction_router
from backend.api.routes.attack_confidence import router as attack_confidence_router
from backend.api.routes.mitre_attack import router as mitre_attack_router
from backend.api.routes.infrastructure_attribution import router as infrastructure_attribution_router
from backend.api.routes.behavioral_baseline import router as behavioral_baseline_router
from backend.api.routes.novelty import router as novelty_router
from backend.api.routes.threat_memory import router as threat_memory_router
from backend.api.routes.continual_learning import router as continual_learning_router
from backend.api.routes.candidate_rules import router as candidate_rules_router
from backend.api.routes.risk_engine import router as risk_engine_router
from backend.api.routes.explainable_ai import router as explainable_ai_router
from backend.api.routes.response_recommendations import router as response_recommendations_router
from backend.api.routes.response_playbooks import router as response_playbooks_router
from backend.api.routes.soc_copilot import router as soc_copilot_router
from backend.api.routes.endpoint_agent import router as endpoint_agent_router
from backend.api.routes.device_incident_correlation import router as device_incident_correlation_router
from backend.api.routes.analysis_live import router as analysis_live_router
from backend.api.routes.investigations import router as investigations_router
from backend.api.routes.search import router as search_router
from backend.api.routes.jobs import router as jobs_router
from backend.api.routes.notifications import router as notifications_router
from backend.api.routes.alerts import router as alerts_router
from backend.api.routes.alert_clusters import router as alert_clusters_router, alert_correlate_router
from backend.api.routes.incidents import router as incidents_router
from backend.api.middleware.security_headers import SecurityHeadersMiddleware
import os
from backend.api.middleware.rate_limiter import RateLimiterMiddleware
from backend.services.log_sanitizer import configure_production_logging
from backend.db.session import engine, Base, init_db
import backend.db.models  # Register models

# Initialize production-safe logging with secret redaction
configure_production_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Handles startup table verification and in-process background worker initialization.
    """
    init_db(max_retries=15, retry_delay=2.0)
    worker_enabled = os.getenv("BACKGROUND_WORKER_ENABLED", "true").lower() in ("true", "1", "yes")
    if worker_enabled:
        from backend.services.background_job_worker import start_in_process_worker, stop_in_process_worker
        start_in_process_worker(max_concurrency=int(os.getenv("WORKER_CONCURRENCY", "2")))
    yield
    if worker_enabled:
        from backend.services.background_job_worker import stop_in_process_worker
        await stop_in_process_worker()



app = FastAPI(
    title="Cybersecurity Email Forensic Parser API",
    description="FastAPI service to ingest, parse, and analyze RFC-822 / .eml email files for cybersecurity threat investigation.",
    version="1.0.0",
    lifespan=lifespan
)

# Section 20: Register HTTP Security Hardening Middleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimiterMiddleware)

# CORS configuration: Allow only known origins, forbid wildcard with credentials
cors_origins_env = os.getenv("CORS_ORIGINS", "").strip()
if cors_origins_env:
    allowed_origins = [orig.strip() for orig in cors_origins_env.split(",") if orig.strip()]
else:
    allowed_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ]

has_wildcard = "*" in allowed_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=not has_wildcard,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(email_router)
app.include_router(cases_router)
app.include_router(incidents_router)
app.include_router(correlation_router)
app.include_router(reports_router)
app.include_router(audit_router)
app.include_router(evidence_router)
app.include_router(dashboard_router)
app.include_router(attribution_router)
app.include_router(confidence_router)
app.include_router(cross_investigation_router)
app.include_router(copilot_router)
app.include_router(benchmark_router)
app.include_router(intelligence_router)
app.include_router(unified_router)
app.include_router(ingest_router)
app.include_router(urls_router)
app.include_router(files_router)
app.include_router(auth_security_router)
app.include_router(network_security_router)
app.include_router(api_security_router)
app.include_router(impersonation_router)
app.include_router(multimedia_router)
app.include_router(knowledge_graph_router)
app.include_router(cross_incident_router)
app.include_router(temporal_correlation_router)
app.include_router(attack_reconstruction_router)
app.include_router(attack_confidence_router)
app.include_router(mitre_attack_router)
app.include_router(infrastructure_attribution_router)
app.include_router(behavioral_baseline_router)
app.include_router(novelty_router)
app.include_router(threat_memory_router)
app.include_router(continual_learning_router)
app.include_router(candidate_rules_router)
app.include_router(risk_engine_router)
app.include_router(explainable_ai_router)
app.include_router(response_recommendations_router)
app.include_router(response_playbooks_router)
app.include_router(soc_copilot_router)
app.include_router(endpoint_agent_router)
app.include_router(device_incident_correlation_router)
app.include_router(analysis_live_router)
app.include_router(investigations_router)
app.include_router(search_router)
app.include_router(jobs_router)
app.include_router(notifications_router)
app.include_router(alert_clusters_router)
app.include_router(alert_correlate_router)
app.include_router(alerts_router)

from backend.api.routes.benchmark import reset_workspace_state
app.add_api_route("/api/workspace/reset", reset_workspace_state, methods=["POST"], tags=["Workspace"])



@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": f"Internal Server Error: {str(exc)}", "error_code": "INTERNAL_SERVER_ERROR"}
    )


@app.get("/health", tags=["Health"])
@app.get("/api/health", tags=["Health"])
async def health_check():
    """
    Service health check endpoint.
    Performs active database connectivity check.
    """
    db_status = "ok"
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "degraded",
                "service": "cybersecurity-email-parser",
                "database": f"unhealthy: {str(exc)}"
            }
        )

    return {
        "status": "ok",
        "service": "cybersecurity-email-parser",
        "database": db_status
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
