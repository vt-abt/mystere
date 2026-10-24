import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routes import credentials, deposit, retrieve, delete

app = FastAPI(title="Mystere Custodian")
app.add_middleware(CORSMiddleware, allow_origins=[os.getenv("CUSTODIAN_WEB_ORIGIN", "http://localhost:5173")], allow_methods=["*"], allow_headers=["*"])
app.include_router(credentials.router)
app.include_router(deposit.router)
app.include_router(retrieve.router)
app.include_router(delete.router)
