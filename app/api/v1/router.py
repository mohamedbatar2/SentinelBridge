from fastapi import APIRouter
from app.api.v1.alerts import router as alerts_router
from app.api.v1.metrics import router as metrics_router

api_router = APIRouter()
api_router.include_router(alerts_router)
api_router.include_router(metrics_router)