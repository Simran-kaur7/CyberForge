from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.incidents import router as incidents_router
from app.api.approvals import router as approvals_router


PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"


app = FastAPI(
    title="CyberForge API",
    version="1.0.0",
    description="Local API bridge for CyberForge security investigations.",
)

app.include_router(incidents_router)
app.include_router(approvals_router)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "cyberforge-api",
    }


app.mount(
    "/",
    StaticFiles(directory=FRONTEND_DIR, html=True),
    name="frontend",
)