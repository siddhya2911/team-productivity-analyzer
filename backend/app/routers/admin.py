from fastapi import APIRouter, Depends
from app.core.permissions import require_roles
from app.models.user import User, UserRole

router = APIRouter(prefix="/admin", tags=["admin"])

@router.get("/health")
def admin_health(_: User = Depends(require_roles(UserRole.admin))):
    return {"ok": True, "scope": "admin"}