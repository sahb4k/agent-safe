"""FastAPI application factory for the governance dashboard."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from agent_safe import __version__
from dashboard.backend.auth.dependencies import init_auth
from dashboard.backend.auth.service import AuthService
from dashboard.backend.auth.tier import has_feature
from dashboard.backend.config import DashboardConfig
from dashboard.backend.db.connection import Database
from dashboard.backend.db.migrations import run_migrations
from dashboard.backend.routers import actions, activity, audit, health, policies
from dashboard.backend.routers import auth as auth_router
from dashboard.backend.routers import clusters as clusters_router
from dashboard.backend.routers import users as users_router
from dashboard.backend.services.action_service import ActionService
from dashboard.backend.services.activity_service import ActivityService
from dashboard.backend.services.audit_service import AuditService
from dashboard.backend.services.policy_service import PolicyService

logger = logging.getLogger(__name__)


def _bootstrap_admin(auth_svc: AuthService, config: DashboardConfig) -> None:
    """Create the admin user on first run if configured."""
    if not config.admin_password:
        return
    existing = auth_svc.get_user_by_username(config.admin_username)
    if existing is not None:
        return
    auth_svc.create_user(
        username=config.admin_username,
        password=config.admin_password,
        role="admin",
        display_name="Administrator",
    )
    logger.info("Created bootstrap admin user: %s", config.admin_username)


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

    # --- Database + Auth (paid tiers) ---
    is_paid = config.tier != "free"
    auth_svc: AuthService | None = None

    if is_paid and config.signing_key:
        db = Database(config.db_path)
        run_migrations(db)
        auth_svc = AuthService(db, config.signing_key)
        init_auth(auth_svc, config.tier)
        _bootstrap_admin(auth_svc, config)
    else:
        init_auth(None, "free")  # type: ignore[arg-type]

    # --- Managed Policy Service (paid tier, requires DB) ---
    managed_policy_svc = None
    if is_paid and has_feature(config.tier, "policies") and config.signing_key:
        from dashboard.backend.managed_policies.service import ManagedPolicyService

        managed_policy_svc = ManagedPolicyService(db)

    # --- Core Services ---
    audit_svc = AuditService(config)
    action_svc = ActionService(config)
    policy_svc = PolicyService(config)
    activity_svc = ActivityService(audit_svc)

    # --- Core Routers ---
    audit.init_router(audit_svc)
    actions.init_router(action_svc)
    policies.init_router(policy_svc, managed_service=managed_policy_svc, tier=config.tier)
    activity.init_router(activity_svc)
    health.init_router(audit_svc, action_svc, policy_svc)

    app.include_router(audit.router)
    app.include_router(actions.router)
    app.include_router(policies.router)
    app.include_router(activity.router)
    app.include_router(health.router)

    # --- Auth Routers (paid tier only) ---
    if auth_svc is not None:
        auth_router.init_router(auth_svc)
        users_router.init_router(auth_svc, config.tier)
        app.include_router(auth_router.router)
        if has_feature(config.tier, "users"):
            app.include_router(users_router.router)

    # --- Report Router (paid tier) ---
    if has_feature(config.tier, "reports"):
        from dashboard.backend.reports.service import ReportService
        from dashboard.backend.routers import reports as reports_router

        report_svc = ReportService(audit_svc)
        reports_router.init_router(report_svc)
        app.include_router(reports_router.router)

    # --- Cluster Router (paid tier) ---
    if has_feature(config.tier, "clusters") and is_paid:
        from dashboard.backend.clusters.service import ClusterService

        cluster_svc = ClusterService(db)
        clusters_router.init_router(
            cluster_svc, config.tier, managed_policy_svc=managed_policy_svc,
        )
        app.include_router(clusters_router.router)

    # --- Static files (built frontend) ---
    frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
    if frontend_dist.is_dir():
        app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")

    return app
