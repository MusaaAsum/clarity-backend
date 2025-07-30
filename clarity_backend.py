from fastapi import FastAPI, HTTPException, Form
from pydantic import BaseModel
import hashlib
import uvicorn

app = FastAPI()

# Simulation d'une base de données simple en mémoire
users_db = {}

# === Fonctions de hachage avec sha256 ===
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(input_password: str, stored_hash: str) -> bool:
    return hash_password(input_password) == stored_hash

# === Modèle de données ===
class User(BaseModel):
    username: str
    password: str

# === Endpoints ===

@app.post("/signup")
def signup(user: User):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Utilisateur déjà inscrit.")
    
    users_db[user.username] = hash_password(user.password)
    return {"message": "Inscription réussie !"}

@app.post("/login")
def login(user: User):
    if user.username not in users_db:
        raise HTTPException(status_code=404, detail="Utilisateur inconnu.")
    
    if not verify_password(user.password, users_db[user.username]):
        raise HTTPException(status_code=401, detail="Mot de passe incorrect.")
    
    return {"message": f"Bienvenue, {user.username} !"}

@app.get("/")
def read_root():
    return {"message": "API Clarity Backend — opérationnelle 🚀"}

# === Point d'entrée pour exécuter en local (inutile pour Render) ===
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
