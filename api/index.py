import os
import json
import pandas as pd
import numpy as np
from io import BytesIO
import hashlib
from datetime import datetime, date
from typing import Optional, Dict, Any

from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Response, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# ---------------------------------------------------------
# ✅ Initialize FastAPI
# ---------------------------------------------------------
app = FastAPI(
    title="DataPulse API",
    description="Data analysis API deployed on Vercel",
    version="1.0.0"
)

# ---------------------------------------------------------
# ✅ CORS Configuration
# ---------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://data-pulse-one.vercel.app",
        "https://*.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------
# ✅ In-memory storage
# ---------------------------------------------------------
user_sessions = {}
file_storage = {}
user_usage = {}
users_db = {}

# ---------------------------------------------------------
# ✅ Models
# ---------------------------------------------------------
class LoginRequest(BaseModel):
    email: str
    password: str
    remember: bool = False

class SignupRequest(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None

# ---------------------------------------------------------
# ✅ Utility functions
# ---------------------------------------------------------
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
    return user and user.get('password') == password

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

# ---------------------------------------------------------
# ✅ Data Analyzer Service
# ---------------------------------------------------------
class DataAnalyzer:
    @staticmethod
    def analyze_dataframe(df: pd.DataFrame) -> Dict[str, Any]:
        profiling = {
            "rows": len(df),
            "columns": len(df.columns),
            "missing_values": int(df.isnull().sum().sum()),
            "memory_usage": df.memory_usage(deep=True).sum(),
            "shape": df.shape
        }
        dtypes = {col: str(dtype) for col, dtype in df.dtypes.items()}
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        numeric_stats = df[numeric_cols].describe().to_dict() if numeric_cols else {}
        categorical_cols = df.select_dtypes(include=['object']).columns.tolist()
        categorical_stats = {}
        for col in categorical_cols[:3]:
            value_counts = df[col].value_counts().head(5).to_dict()
            categorical_stats[col] = {
                "unique_values": df[col].nunique(),
                "top_values": value_counts
            }
        sample_data = df.head(10).fillna('').to_dict('records')
        return {
            "profiling": profiling,
            "dtypes": dtypes,
            "numeric_columns": numeric_cols,
            "categorical_columns": categorical_cols,
            "numeric_stats": numeric_stats,
            "categorical_stats": categorical_stats,
            "sample_data": sample_data,
            "columns_list": df.columns.tolist(),
            "analysis_timestamp": datetime.now().isoformat()
        }

    @staticmethod
    def generate_insights(df: pd.DataFrame) -> Dict[str, Any]:
        insights = {"summary": "", "key_findings": [], "recommendations": []}
        rows, cols = df.shape
        insights["summary"] = (
            f"This dataset contains {rows} rows and {cols} columns. "
            f"Found {len(df.select_dtypes(include=[np.number]).columns)} numeric columns "
            f"and {len(df.select_dtypes(include=['object']).columns)} text columns."
        )
        if rows > 0:
            insights["key_findings"].extend([
                f"Dataset has {df.isnull().sum().sum()} missing values",
                f"Average row completeness: {((1 - df.isnull().sum().sum() / (rows * cols)) * 100):.1f}%",
                f"Memory usage: {df.memory_usage(deep=True).sum() / 1024 / 1024:.2f} MB"
            ])
        insights["recommendations"].extend([
            "Handle missing values before analysis",
            "Verify data types for each column",
            "Check for duplicate rows",
            "Normalize numeric columns if using ML"
        ])
        return insights

# ---------------------------------------------------------
# ✅ Routes
# ---------------------------------------------------------
@app.get("/")
async def root():
    return {"status": "success", "message": "DataPulse API running on Vercel"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.post("/api/auth/signup")
async def signup(request: SignupRequest, response: Response):
    if create_user(request.email, request.password, request.full_name):
        session_id = generate_session_id()
        user_sessions[session_id] = {"email": request.email, "login_time": datetime.now().isoformat()}
        response.set_cookie(key="session_id", value=session_id, httponly=True)
        return {"success": True, "message": "Signup successful", "session_id": session_id}
    raise HTTPException(status_code=400, detail="User already exists")

@app.post("/api/auth/login")
async def login(request: LoginRequest, response: Response):
    if authenticate_user(request.email, request.password):
        session_id = generate_session_id()
        user_sessions[session_id] = {"email": request.email, "login_time": datetime.now().isoformat()}
        response.set_cookie(key="session_id", value=session_id, httponly=True)
        return {"success": True, "message": "Login successful", "session_id": session_id}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/api/analyze")
async def analyze_data(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large (max 10MB)")
    ext = file.filename.lower().split('.')[-1]
    df = pd.read_csv(BytesIO(content)) if ext == 'csv' else pd.read_excel(BytesIO(content))
    analyzer = DataAnalyzer()
    result = analyzer.analyze_dataframe(df)
    insights = analyzer.generate_insights(df)
    return {"success": True, "analysis": result, "insights": insights}

# ---------------------------------------------------------
# ✅ Error Handlers
# ---------------------------------------------------------
@app.exception_handler(Exception)
async def general_error(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"error": str(exc)})
