# main.py - Backend FastAPI avec CORS corrigé
import os
import jwt
import bcrypt
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import uuid
import re

# Configuration
SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Base de données
SQLALCHEMY_DATABASE_URL = "sqlite:///./clarity.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Modèles de base de données
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

class CoachingSession(Base):
    __tablename__ = "sessions"
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String, unique=True, index=True)
    user_id = Column(Integer)
    problem_description = Column(Text)
    status = Column(String, default="in_progress")
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

class QuestionResponse(Base):
    __tablename__ = "question_responses"
    id = Column(Integer, primary_key=True, index=True)
    session_uuid = Column(String)
    question_key = Column(String)
    answer = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

class ActionPlan(Base):
    __tablename__ = "action_plans"
    id = Column(Integer, primary_key=True, index=True)
    session_uuid = Column(String)
    analysis = Column(Text)
    actions = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

# Créer les tables
Base.metadata.create_all(bind=engine)

# Modèles Pydantic
class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class SessionStart(BaseModel):
    problem_description: str

class QuestionAnswer(BaseModel):
    session_id: str
    question_key: str
    answer: str

# FastAPI app
app = FastAPI(title="Clarity API", version="1.0.0")

# CORS Configuration - CORRECTION CRITIQUE
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En production, remplacez par votre domaine Vercel
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# Dépendances
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Token invalide")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token invalide")
    
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Utilisateur non trouvé")
    return user

# Routes principales
@app.get("/")
async def root():
    return {"message": "Clarity API", "status": "running"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# Authentification
@app.post("/auth/register")
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    # Vérifier si l'utilisateur existe
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email déjà utilisé")
    
    # Hasher le mot de passe
    hashed_password = bcrypt.hashpw(user_data.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Créer l'utilisateur
    user = User(email=user_data.email, hashed_password=hashed_password)
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Créer le token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {"id": user.id, "email": user.email}
    }

@app.post("/auth/login")
async def login(form_data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.email).first()
    if not user or not bcrypt.checkpw(form_data.password.encode('utf-8'), user.hashed_password.encode('utf-8')):
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {"id": user.id, "email": user.email}
    }

@app.get("/auth/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    return {"id": current_user.id, "email": current_user.email}

# Moteur de questions
@dataclass
class Question:
    key: str
    text: str
    type: str = "text"

def generate_questions(problem_description: str) -> List[Question]:
    questions = [
        Question("duration", "Depuis combien de temps cette situation dure-t-elle ?"),
        Question("triggers", "Qu'est-ce qui déclenche généralement ce problème ?"),
        Question("attempts", "Qu'avez-vous déjà essayé pour résoudre cela ?"),
        Question("context", "Dans quel contexte ce problème se manifeste-t-il le plus ?"),
        Question("impact", "Comment cela affecte-t-il votre quotidien ?")
    ]
    
    # Adaptation selon le contenu
    if any(word in problem_description.lower() for word in ["travail", "job", "bureau", "collègue", "patron"]):
        questions.append(Question("work_specific", "Comment vos collègues/supérieurs réagissent-ils à cette situation ?"))
    
    if any(word in problem_description.lower() for word in ["relation", "copain", "copine", "famille", "ami"]):
        questions.append(Question("relationship_specific", "Comment cette situation affecte-t-elle vos relations proches ?"))
    
    return questions

def analyze_responses(problem: str, responses: List[Dict]) -> Dict[str, List[str]]:
    # Mots-clés pour la classification
    inherited_keywords = ["né", "famille", "parents", "enfance", "naturellement", "toujours été", "depuis petit"]
    changeable_keywords = ["réaction", "choix", "décision", "communication", "attitude", "comportement", "habitude"]
    
    analysis = {
        "inherited_fixed": [],
        "inherited_changeable": [],
        "created_fixed": [],
        "created_changeable": []
    }
    
    # Analyser le problème principal
    problem_lower = problem.lower()
    if any(keyword in problem_lower for keyword in inherited_keywords):
        if any(keyword in problem_lower for keyword in changeable_keywords):
            analysis["inherited_changeable"].append("Trait de personnalité à développer")
        else:
            analysis["inherited_fixed"].append("Caractéristique héritée à accepter")
    else:
        if any(keyword in problem_lower for keyword in changeable_keywords):
            analysis["created_changeable"].append("Comportement modifiable")
        else:
            analysis["created_fixed"].append("Situation passée à assumer")
    
    # Analyser les réponses
    for response in responses:
        answer_lower = response["answer"].lower()
        
        if "depuis toujours" in answer_lower or "enfance" in answer_lower:
            analysis["inherited_fixed"].append(f"Aspect ancien: {response['answer'][:50]}...")
        elif "communication" in answer_lower or "réaction" in answer_lower:
            analysis["created_changeable"].append(f"Point d'action: {response['answer'][:50]}...")
        elif "essayé" in answer_lower:
            analysis["created_fixed"].append(f"Tentative passée: {response['answer'][:50]}...")
    
    # Ajouter des éléments par défaut si vide
    if not analysis["created_changeable"]:
        analysis["created_changeable"].append("Votre façon de réagir à cette situation")
    
    return analysis

def generate_action_plan(analysis: Dict[str, List[str]]) -> List[str]:
    actions = []
    
    # Focus sur la zone "created_changeable"
    changeable_items = analysis.get("created_changeable", [])
    
    if changeable_items:
        actions.append("Cette semaine : Observez vos réactions automatiques dans cette situation")
        actions.append("Identifiez UN petit changement que vous pouvez faire dès aujourd'hui")
        actions.append("Partagez votre réflexion avec une personne de confiance")
    else:
        actions.append("Concentrez-vous sur l'acceptation de ce qui ne dépend pas de vous")
        actions.append("Identifiez vos forces pour mieux gérer cette situation")
        actions.append("Cherchez du soutien auprès de vos proches")
    
    return actions

# Routes de session
@app.post("/sessions/start")
async def start_session(session_data: SessionStart, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    session_uuid = str(uuid.uuid4())
    
    session = CoachingSession(
        uuid=session_uuid,
        user_id=current_user.id,
        problem_description=session_data.problem_description,
        status="in_progress"
    )
    
    db.add(session)
    db.commit()
    
    questions = generate_questions(session_data.problem_description)
    questions_dict = [{"key": q.key, "text": q.text, "type": q.type} for q in questions]
    
    return {
        "session_id": session_uuid,
        "questions": questions_dict
    }

@app.post("/sessions/respond")
async def respond_to_question(response_data: QuestionAnswer, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Vérifier que la session appartient à l'utilisateur
    session = db.query(CoachingSession).filter(
        CoachingSession.uuid == response_data.session_id,
        CoachingSession.user_id == current_user.id
    ).first()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session non trouvée")
    
    # Enregistrer la réponse
    question_response = QuestionResponse(
        session_uuid=response_data.session_id,
        question_key=response_data.question_key,
        answer=response_data.answer
    )
    
    db.add(question_response)
    db.commit()
    
    return {"status": "success"}

@app.post("/sessions/complete/{session_id}")
async def complete_session(session_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Vérifier la session
    session = db.query(CoachingSession).filter(
        CoachingSession.uuid == session_id,
        CoachingSession.user_id == current_user.id
    ).first()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session non trouvée")
    
    # Récupérer toutes les réponses
    responses = db.query(QuestionResponse).filter(QuestionResponse.session_uuid == session_id).all()
    responses_list = [{"question_key": r.question_key, "answer": r.answer} for r in responses]
    
    # Analyser
    analysis = analyze_responses(session.problem_description, responses_list)
    action_plan = generate_action_plan(analysis)
    
    # Sauvegarder l'analyse
    action_plan_record = ActionPlan(
        session_uuid=session_id,
        analysis=str(analysis),
        actions=str(action_plan)
    )
    
    db.add(action_plan_record)
    
    # Marquer la session comme terminée
    session.status = "completed"
    session.completed_at = datetime.utcnow()
    
    db.commit()
    
    return {
        "analysis": analysis,
        "action_plan": action_plan
    }

@app.get("/sessions/history")
async def get_session_history(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sessions = db.query(CoachingSession).filter(CoachingSession.user_id == current_user.id).order_by(CoachingSession.created_at.desc()).all()
    
    return [
        {
            "uuid": session.uuid,
            "problem_description": session.problem_description,
            "status": session.status,
            "created_at": session.created_at.isoformat(),
            "completed_at": session.completed_at.isoformat() if session.completed_at else None
        }
        for session in sessions
    ]

# Point d'entrée pour Railway
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
