from fastapi import FastAPI, HTTPException, Depends, Body
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime, timedelta
from uuid import uuid4
import uvicorn

DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    email = Column(String, primary_key=True, index=True)
    password = Column(String)
    public_key = Column(String)

class SessionModel(Base):
    __tablename__ = "sessions"
    session_id = Column(String, primary_key=True, index=True)
    email = Column(String)
    expires_at = Column(DateTime)

Base.metadata.create_all(bind=engine)

app = FastAPI()

class UserCreate(BaseModel):
    email: str
    password: str

class StoreData(BaseModel):
    data: str

class RetrieveData(BaseModel):
    session_id: str
    encrypted_data: str

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
    return public_pem.decode('utf-8'), private_pem.decode('utf-8')

def encrypt_data(public_key_pem: str, data: str) -> str:
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    encrypted = public_key.encrypt(data.encode('utf-8'), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return encrypted.hex()

def decrypt_data(private_key_pem: str, encrypted_data: str) -> str:
    private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None)
    decrypted = private_key.decrypt(bytes.fromhex(encrypted_data), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return decrypted.decode('utf-8')

@app.post("/auth/register")
def register_user(user: UserCreate):
    db: Session = SessionLocal()
    public_key, private_key = generate_rsa_keys()
    user_data = User(email=user.email, password=user.password, public_key=public_key)
    db.add(user_data)
    db.commit()
    db.refresh(user_data)
    return {"private_key": private_key}

@app.post("/auth/login")
def login(user: UserCreate):
    db: Session = SessionLocal()
    db_user = db.query(User).filter(User.email == user.email, User.password == user.password).first()
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    session_id = str(uuid4())
    expires_at = datetime.utcnow() + timedelta(minutes=30)
    session = SessionModel(session_id=session_id, email=user.email, expires_at=expires_at)
    db.add(session)
    db.commit()
    return {"session_id": session_id}

@app.post("/bank/data")
def store_data(store_data: StoreData, session_id: str = Body(...)):
    db: Session = SessionLocal()
    session = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
    if not session or datetime.utcnow() > session.expires_at:
        raise HTTPException(status_code=400, detail="Invalid or expired session")
    user = db.query(User).filter(User.email == session.email).first()
    encrypted_data = encrypt_data(user.public_key, store_data.data)
    return {"encrypted_data": encrypted_data}


if __name__ == "__main__":
    uvicorn.run(app=app)