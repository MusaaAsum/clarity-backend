# main.py - Backend FastAPI complet pour Clarity
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
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
import uvicorn
import re

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./clarity.db")

# Base de données
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Modèles de données
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    sessions = relationship("CoachingSession", back_populates="user")

class CoachingSession(Base):
    __tablename__ = "coaching_sessions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    title = Column(String)
    problem_description = Column(Text)
    status = Column(String, default="in_progress")  # in_progress, completed
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    user = relationship("User", back_populates="sessions")
    responses = relationship("QuestionResponse", back_populates="session")
    action_plan = relationship("ActionPlan", back_populates="session", uselist=False)

class QuestionResponse(Base):
    __tablename__ = "question_responses"
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("coaching_sessions.id"))
    question_key = Column(String)
    question_text = Column(Text)
    response = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    session = relationship("CoachingSession", back_populates="responses")

class ActionPlan(Base):
    __tablename__ = "action_plans"
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("coaching_sessions.id"))
    inherited_fixed = Column(Text)  # JSON des éléments hérités non changeables
    inherited_changeable = Column(Text)  # JSON des éléments hérités changeables
    created_fixed = Column(Text)  # JSON des éléments créés non changeables
    created_actionable = Column(Text)  # JSON des éléments créés actionnables
    actions = Column(Text)  # JSON des 3 actions concrètes
    created_at = Column(DateTime, default=datetime.utcnow)
    session = relationship("CoachingSession", back_populates="action_plan")

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
    question_key: str
    response: str

class Token(BaseModel):
    access_token: str
    token_type: str

# FastAPI app
app = FastAPI(title="Clarity API", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En production: spécifier les domaines autorisés
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=7)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=["HS256"])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# Moteur de questions intelligentes
class QuestionsEngine:
    @staticmethod
    def generate_questions(problem_description: str) -> List[Dict[str, Any]]:
        """Génère des questions adaptées selon le problème décrit"""
        questions = [
            {
                "key": "duration",
                "text": "Depuis combien de temps cette situation dure-t-elle ?",
                "type": "text"
            },
            {
                "key": "context",
                "text": "Dans quel contexte cela se produit-il le plus souvent ?",
                "type": "text"
            },
            {
                "key": "feelings",
                "text": "Quelles émotions ressentez-vous face à cette situation ?",
                "type": "text"
            },
            {
                "key": "attempts",
                "text": "Qu'avez-vous déjà essayé pour résoudre cela ?",
                "type": "text"
            },
            {
                "key": "patterns",
                "text": "Y a-t-il des éléments récurrents que vous remarquez ?",
                "type": "text"
            }
        ]
        
        # Questions spécifiques selon les mots-clés
        problem_lower = problem_description.lower()
        
        if any(word in problem_lower for word in ["relation", "copain", "copine", "ami", "couple"]):
            questions.extend([
                {
                    "key": "relationship_pattern",
                    "text": "Ce schéma se répète-t-il dans vos relations ?",
                    "type": "text"
                },
                {
                    "key": "communication_style",
                    "text": "Comment communiquez-vous généralement lors de conflits ?",
                    "type": "text"
                }
            ])
        
        if any(word in problem_lower for word in ["travail", "job", "carrière", "patron"]):
            questions.extend([
                {
                    "key": "work_environment",
                    "text": "L'environnement de travail influence-t-il cette situation ?",
                    "type": "text"
                },
                {
                    "key": "career_goals",
                    "text": "Cela affecte-t-il vos objectifs professionnels ?",
                    "type": "text"
                }
            ])
        
        return questions[:6]  # Maximum 6 questions
    
    @staticmethod
    def analyze_responses(responses: List[Dict[str, str]], problem_description: str) -> Dict[str, Any]:
        """Analyse les réponses et génère la matrice + plan d'action"""
        
        # Créer un texte complet pour l'analyse
        full_text = problem_description + " " + " ".join([r["response"] for r in responses])
        full_text_lower = full_text.lower()
        
        # Classification dans les 4 quadrants
        inherited_fixed = []
        inherited_changeable = []
        created_fixed = []
        created_actionable = []
        
        # Mots-clés pour détecter l'hérité vs créé
        inherited_keywords = ["né", "naissance", "famille", "parents", "enfance", "physique", "taille", "couleur", "origine", "génétique"]
        created_keywords = ["choix", "décision", "réaction", "comportement", "habitude", "communication", "attitude", "pensée"]
        
        # Mots-clés pour détecter le changeable vs fixe
        changeable_keywords = ["apprendre", "améliorer", "changer", "développer", "travailler", "effort", "pratiquer", "modifier"]
        fixed_keywords = ["passé", "déjà fait", "terminé", "impossible", "jamais", "toujours été"]
        
        # Analyse simple par mots-clés (version MVP)
        if any(keyword in full_text_lower for keyword in inherited_keywords):
            inherited_fixed.append("Caractéristiques personnelles héritées")
            inherited_changeable.append("Façons de composer avec ces caractéristiques")
        
        if any(keyword in full_text_lower for keyword in created_keywords):
            created_actionable.extend([
                "Vos réactions face à la situation",
                "Votre façon de communiquer",
                "Vos habitudes dans ce contexte"
            ])
        
        # Génération d'actions concrètes
        actions = QuestionsEngine.generate_actions(full_text_lower, responses)
        
        return {
            "inherited_fixed": inherited_fixed,
            "inherited_changeable": inherited_changeable,
            "created_fixed": created_fixed,
            "created_actionable": created_actionable,
            "actions": actions
        }
    
    @staticmethod
    def generate_actions(text: str, responses: List[Dict[str, str]]) -> List[str]:
        """Génère 3 actions concrètes basées sur l'analyse"""
        
        actions = []
        
        # Actions selon le type de problème détecté
        if any(word in text for word in ["relation", "communication", "conflit"]):
            actions = [
                "Cette semaine : Noter chaque fois que vous réagissez impulsivement dans une conversation",
                "Avant vendredi : Avoir une conversation claire avec une personne concernée par la situation",
                "Dans les 7 jours : Demander un retour honnête à un proche sur votre style de communication"
            ]
        elif any(word in text for word in ["travail", "carrière", "patron"]):
            actions = [
                "Aujourd'hui : Identifier une compétence concrète à développer pour cette situation",
                "Cette semaine : Planifier 30 minutes quotidiennes pour travail sur cette compétence",
                "Avant dimanche : Parler de votre situation à un mentor ou collègue de confiance"
            ]
        elif any(word in text for word in ["confiance", "estime", "soi"]):
            actions = [
                "Chaque jour : Noter 3 choses que vous avez bien gérées dans la journée",
                "Cette semaine : Faire une activité où vous excellez naturellement",
                "Dans 5 jours : Fixer une petite limite que vous n'aviez jamais osé poser"
            ]
        else:
            # Actions génériques
            actions = [
                "Aujourd'hui : Identifier précisément un élément sur lequel vous avez du contrôle",
                "Cette semaine : Passer à l'action sur cet élément pendant 15 minutes par jour",
                "Dans les 7 jours : Parler de votre situation à quelqu'un de confiance"
            ]
        
        return actions[:3]

# Routes d'authentification
@app.post("/auth/register", response_model=Token)
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    # Vérifier si l'utilisateur existe
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hasher le mot de passe
    hashed_password = bcrypt.hashpw(user_data.password.encode('utf-8'), bcrypt.gensalt())
    
    # Créer l'utilisateur
    user = User(email=user_data.email, hashed_password=hashed_password.decode('utf-8'))
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Créer le token
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/auth/login", response_model=Token)
async def login(user_data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == user_data.email).first()
    if not user or not bcrypt.checkpw(user_data.password.encode('utf-8'), user.hashed_password.encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# Routes des sessions
@app.post("/sessions/start")
async def start_session(session_data: SessionStart, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Créer une nouvelle session
    session = CoachingSession(
        user_id=current_user.id,
        title=session_data.problem_description[:50] + "...",
        problem_description=session_data.problem_description
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    
    # Générer les questions
    questions = QuestionsEngine.generate_questions(session_data.problem_description)
    
    return {
        "session_id": session.id,
        "questions": questions
    }

@app.post("/sessions/{session_id}/respond")
async def respond_to_question(
    session_id: int, 
    answer: QuestionAnswer, 
    current_user: User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    # Vérifier que la session appartient à l'utilisateur
    session = db.query(CoachingSession).filter(
        CoachingSession.id == session_id,
        CoachingSession.user_id == current_user.id
    ).first()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Enregistrer la réponse
    response = QuestionResponse(
        session_id=session_id,
        question_key=answer.question_key,
        question_text="",  # On pourrait stocker le texte de la question aussi
        response=answer.response
    )
    db.add(response)
    db.commit()
    
    return {"status": "success", "message": "Response recorded"}

@app.post("/sessions/{session_id}/complete")
async def complete_session(session_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Vérifier la session
    session = db.query(CoachingSession).filter(
        CoachingSession.id == session_id,
        CoachingSession.user_id == current_user.id
    ).first()
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Récupérer toutes les réponses
    responses = db.query(QuestionResponse).filter(QuestionResponse.session_id == session_id).all()
    response_data = [{"question_key": r.question_key, "response": r.response} for r in responses]
    
    # Analyser et générer le plan d'action
    analysis = QuestionsEngine.analyze_responses(response_data, session.problem_description)
    
    # Créer le plan d'action
    import json
    action_plan = ActionPlan(
        session_id=session_id,
        inherited_fixed=json.dumps(analysis["inherited_fixed"]),
        inherited_changeable=json.dumps(analysis["inherited_changeable"]),
        created_fixed=json.dumps(analysis["created_fixed"]),
        created_actionable=json.dumps(analysis["created_actionable"]),
        actions=json.dumps(analysis["actions"])
    )
    db.add(action_plan)
    
    # Marquer la session comme terminée
    session.status = "completed"
    session.completed_at = datetime.utcnow()
    db.commit()
    
    return {
        "status": "completed",
        "analysis": analysis
    }

@app.get("/sessions/history")
async def get_session_history(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sessions = db.query(CoachingSession).filter(CoachingSession.user_id == current_user.id).order_by(CoachingSession.created_at.desc()).all()
    
    result = []
    for session in sessions:
        session_data = {
            "id": session.id,
            "title": session.title,
            "status": session.status,
            "created_at": session.created_at.isoformat(),
            "completed_at": session.completed_at.isoformat() if session.completed_at else None
        }
        
        if session.action_plan:
            import json
            session_data["analysis"] = {
                "inherited_fixed": json.loads(session.action_plan.inherited_fixed),
                "inherited_changeable": json.loads(session.action_plan.inherited_changeable),
                "created_fixed": json.loads(session.action_plan.created_fixed),
                "created_actionable": json.loads(session.action_plan.created_actionable),
                "actions": json.loads(session.action_plan.actions)
            }
        
        result.append(session_data)
    
    return {"sessions": result}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)