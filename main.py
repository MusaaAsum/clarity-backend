# main.py - Version ultra-minimal garantie
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os

# Application FastAPI
app = FastAPI()

# CORS pour permettre Vercel
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"message": "Clarity API", "status": "running"}

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": "working"}

# Point d'entrée Railway
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
