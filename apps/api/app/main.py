from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.database import engine
from app.models.scan import Base
from app.api.v1.scans import router as scans_router

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title='CloudSecAI Engine API',
    version='1.0.0',
    description='Autonomous IaC Security Scanner & AI Remediation Platform'
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

app.include_router(scans_router, prefix='/api/v1')

@app.get('/health', tags=['Health'])
def health_check():
    return {
        'status': 'online',
        'service': 'CloudSecAI Core Engine',
        'version': '1.0.0'
    }
