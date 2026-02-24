"""FastAPI application factory for the governance dashboard."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from agent_safe import __version__
from dashboard.backend.config import DashboardConfig
from dashboard.backend.routers import actions, activity, audit, health, policies
from dashboard.backend.services.action_service import ActionService
from dashboard.backend.services.activity_service import ActivityService
from dashboard.backend.services.audit_service import AuditService
from dashboard.backend.services.policy_service import PolicyService


def create_app(config: DashboardConfig | None = None) -> FastAPI:
    """Build and return the FastAPI application.

    Services are initialised from *config* (or env defaults) and
    injected into each router via its ``init_router()`` function.
    """
    if config is None:
        config = DashboardConfig.from_env()

    app = FastAPI(
        title="Agent-Safe Dashboard",
        version=__version__,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )

    # --- CORS (dev mode only) ---
    if config.dev_mode:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["http://localhost:5173"],  # Vite dev server
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # --- Services ---
    audit_svc = AuditService(config)
    action_svc = ActionService(config)
    policy_svc = PolicyService(config)
    activity_svc = ActivityService(audit_svc)

    # --- Routers ---
    audit.init_router(audit_svc)
    actions.init_router(action_svc)
    policies.init_router(policy_svc)
    activity.init_router(activity_svc)
    health.init_router(audit_svc, action_svc, policy_svc)

    app.include_router(audit.router)
    app.include_router(actions.router)
    app.include_router(policies.router)
    app.include_router(activity.router)
    app.include_router(health.router)

    # --- Static files (built frontend) ---
    frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
    if frontend_dist.is_dir():
        app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")

    return app
