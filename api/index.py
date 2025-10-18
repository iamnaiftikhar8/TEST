from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Response, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import pandas as pd
import numpy as np
from io import BytesIO
import hashlib
from datetime import datetime, date
from typing import Optional, Dict, Any
import json

# Use Pydantic v2 syntax
from pydantic import BaseModel

# Initialize FastAPI app
app = FastAPI(
    title="DataPulse API",
    description="Data analysis API for Vercel deployment",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage
user_sessions = {}
file_storage = {}
user_usage = {}
users_db = {}

# Pydantic models - UPDATED for v2
class LoginRequest(BaseModel):
    email: str
    password: str
    remember: bool = False

class SignupRequest(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None

# Utility functions
def generate_session_id():
    return hashlib.md5(str(datetime.now()).encode()).hexdigest()

def get_user_usage(email: str, today: date) -> int:
    key = f"{email}_{today.isoformat()}"
    return user_usage.get(key, 0)

def increment_user_usage(email: str, today: date):
    key = f"{email}_{today.isoformat()}"
    user_usage[key] = user_usage.get(key, 0) + 1

def authenticate_user(email: str, password: str) -> bool:
    user = users_db.get(email)
    if user and user.get('password') == password:
        return True
    return False

def create_user(email: str, password: str, full_name: Optional[str]) -> bool:
    if email in users_db:
        return False
    users_db[email] = {
        'email': email,
        'password': password,
        'full_name': full_name,
        'created_at': datetime.now().isoformat()
    }
    return True

def get_current_user(session_id: Optional[str] = Query(None)):
    if not session_id or session_id not in user_sessions:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user_sessions[session_id]

# SIMPLIFIED DataAnalyzer for now
class DataAnalyzer:
    @staticmethod
    def analyze_dataframe(df: pd.DataFrame) -> Dict[str, Any]:
        return {
            "profiling": {
                "rows": len(df),
                "columns": len(df.columns),
                "missing_values": int(df.isnull().sum().sum()),
                "shape": [len(df), len(df.columns)]
            },
            "dtypes": {col: str(dtype) for col, dtype in df.dtypes.items()},
            "numeric_columns": df.select_dtypes(include=[np.number]).columns.tolist(),
            "categorical_columns": df.select_dtypes(include=['object']).columns.tolist(),
        }

# Routes
@app.get("/")
async def root():
    return {"status": "success", "message": "DataPulse API is running"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/api/auth/login")
async def login(request: LoginRequest, response: Response):
    try:
        if authenticate_user(request.email, request.password):
            session_id = generate_session_id()
            user_sessions[session_id] = {
                "email": request.email,
                "login_time": datetime.now().isoformat()
            }
            return {
                "success": True,
                "message": "Login successful",
                "session_id": session_id,
                "user": {"email": request.email}
            }
        else:
            raise HTTPException(status_code=401, detail="Invalid credentials")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

@app.post("/api/auth/signup")
async def signup(request: SignupRequest, response: Response):
    try:
        if create_user(request.email, request.password, request.full_name):
            session_id = generate_session_id()
            user_sessions[session_id] = {
                "email": request.email,
                "login_time": datetime.now().isoformat()
            }
            return {
                "success": True,
                "message": "Signup successful",
                "session_id": session_id,
                "user": {"email": request.email}
            }
        else:
            raise HTTPException(status_code=400, detail="User already exists")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Signup failed: {str(e)}")

@app.post("/api/analyze")
async def analyze_data(file: UploadFile = File(...)):
    try:
        contents = await file.read()
        
        if len(contents) > 5 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="File too large")
        
        if file.filename.endswith('.csv'):
            df = pd.read_csv(BytesIO(contents))
        else:
            df = pd.read_excel(BytesIO(contents))
        
        analyzer = DataAnalyzer()
        analysis_result = analyzer.analyze_dataframe(df)
        
        return {
            "success": True,
            "data": {
                "file_info": {
                    "name": file.filename,
                    "size": len(contents),
                    "rows": len(df),
                    "columns": len(df.columns)
                },
                "analysis": analysis_result
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

# Vercel handler
from mangum import Mangum
handler = Mangum(app)