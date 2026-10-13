"""
Section 75: Authoritative Demo & Golden Path Scenario API Routes.
Provides endpoints to inspect, execute, and safely reset the 4 realistic CyberGuard demonstration scenarios:
- Scenario A: Targeted Phishing & Lookalike Brand
- Scenario B: Executive Impersonation & BEC
- Scenario C: Weaponized Executable Attachment
- Scenario D: Multi-Stage Coordinated Attack
Guarantees that all demo records are isolated (is_demo: true) and that production data is never touched or deleted.
"""
import logging
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Header, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.services.demo_scenario_service import DemoScenarioService

logger = logging.getLogger("cyberguard.api.demo")

router = APIRouter(prefix="/api/demo", tags=["Demo & Golden Path Scenarios"])


def get_demo_actor_and_role(
    x_user: Optional[str] = Header(None, alias="X-User"),
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
    x_role: Optional[str] = Header(None, alias="X-Role"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> tuple[str, str]:
    user = (x_user or x_actor_id or "").strip() or "Demo Analyst"
    role = (x_role or x_user_role or "").strip().lower()

    if not role and authorization:
        auth_clean = authorization.strip().lower()
        if "admin" in auth_clean or "lead" in auth_clean:
            role = "admin"
        elif "analyst" in auth_clean or "soc" in auth_clean:
            role = "analyst"
        elif "unauthorized" in auth_clean:
            role = "unauthorized"

    if role in ("guest", "unauthorized", "untrusted"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: insufficient permissions for demo operations.",
        )

    return user, role or "analyst"


class ExecuteScenarioRequest(BaseModel):
    workspace_id: str = Field(default="default", description="Target workspace / tenant ID")
    actor: Optional[str] = Field(default=None, description="Initiating analyst or actor identifier")


@router.get("/scenarios", summary="List available realistic demonstration scenarios")
def list_demo_scenarios() -> Dict[str, Any]:
    """
    Returns the 4 supported deterministic demonstration scenarios for CyberGuard.
    Each scenario exercises the authentic end-to-end detection and response pipeline.
    """
    scenarios = DemoScenarioService.list_scenarios()
    return {
        "status": "SUCCESS",
        "count": len(scenarios),
        "scenarios": scenarios,
        "environment": "DEMO_READY",
    }


@router.get("/scenarios/{scenario_id}", summary="Get scenario details")
def get_demo_scenario(scenario_id: str) -> Dict[str, Any]:
    """Returns definition and expected detection metadata for a specific scenario."""
    scenarios = DemoScenarioService.list_scenarios()
    matched = next((s for s in scenarios if s["id"] == scenario_id.lower().strip()), None)
    if not matched:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scenario '{scenario_id}' not found. Available: {[s['id'] for s in scenarios]}",
        )
    return {"status": "SUCCESS", "scenario": matched}


@router.post("/scenarios/{scenario_id}/execute", summary="Execute authentic scenario through real pipeline")
async def execute_demo_scenario(
    scenario_id: str,
    payload: Optional[ExecuteScenarioRequest] = None,
    user_info: tuple[str, str] = Depends(get_demo_actor_and_role),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Triggers end-to-end ingestion, parsing, IOC extraction, threat scoring,
    correlation, case creation, incident generation, attack path mapping,
    response recommendation, and evidence logging for the scenario.
    """
    actor_name = (payload.actor if payload and payload.actor else None) or user_info[0]
    workspace = (payload.workspace_id if payload and payload.workspace_id else "default")

    try:
        result = await DemoScenarioService.execute_scenario(
            db=db,
            scenario_id=scenario_id,
            workspace_id=workspace,
            actor=actor_name,
        )
        return result
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as exc:
        logger.error(f"Error executing demo scenario {scenario_id}: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Scenario execution failed.',
        )


@router.post("/reset", summary="Safe demo data reset (purges only is_demo: true)")
def reset_demo_data(
    user_info: tuple[str, str] = Depends(get_demo_actor_and_role),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Safely purges only records tagged with is_demo: true.
    Ensures production artifacts, cases, incidents, audit logs, and evidence remain completely intact.
    """
    try:
        result = DemoScenarioService.reset_demo_data(db)
        return result
    except Exception as exc:
        logger.error(f"Failed to execute demo reset: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Demo reset failed.',
        )


@router.get("/status", summary="Get active demo scenario metrics and environment state")
def get_demo_status(
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Returns statistics on active demo scenarios and demo isolation state."""
    try:
        return DemoScenarioService.get_demo_status(db)
    except Exception as exc:
        logger.error(f"Failed to fetch demo status: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Demo status check failed.',
        )
