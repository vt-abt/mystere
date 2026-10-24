from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routes import keys, session, ws

app = FastAPI(title="Mystere Relay")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.include_router(keys.router, prefix="/keys")
app.include_router(session.router, prefix="/session")
app.include_router(ws.router)
