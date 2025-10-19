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

# Initialize FastAPI app
app = FastAPI(
    title="DataPulse API",
    description="Data analysis API for Vercel deployment",
    version="1.0.0"
)

# CORS middleware
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

# In-memory storage
user_sessions = {}
file_storage = {}
user_usage = {}
users_db = {}

# Pydantic models
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

# AI Analysis Service
class DataAnalyzer:
    @staticmethod
    def analyze_dataframe(df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze dataframe and return insights"""
        try:
            profiling = {
                "rows": len(df),
                "columns": len(df.columns),
                "missing_values": int(df.isnull().sum().sum()),
                "memory_usage": df.memory_usage(deep=True).sum(),
                "shape": df.shape
            }

            dtypes = {
                col: str(dtype) for col, dtype in df.dtypes.items()
            }

            numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
            numeric_stats = {}
            if numeric_cols:
                numeric_stats = df[numeric_cols].describe().to_dict()

            categorical_cols = df.select_dtypes(include=['object']).columns.tolist()
            categorical_stats = {}
            for col in categorical_cols[:3]:
                if col in df.columns:
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

        except Exception as e:
            raise Exception(f"Analysis error: {str(e)}")

    @staticmethod
    def generate_insights(df: pd.DataFrame) -> Dict[str, Any]:
        """Generate AI-like insights from data"""
        insights = {
            "summary": "",
            "key_findings": [],
            "recommendations": []
        }

        try:
            rows, cols = df.shape
            
            insights["summary"] = (
                f"This dataset contains {rows} rows and {cols} columns. "
                f"Found {len(df.select_dtypes(include=[np.number]).columns)} numeric columns "
                f"and {len(df.select_dtypes(include=['object']).columns)} text columns."
            )

            if rows > 0:
                insights["key_findings"].extend([
                    f"Dataset has {df.isnull().sum().sum()} missing values across all columns",
                    f"Average row completeness: {((1 - df.isnull().sum().sum() / (rows * cols)) * 100):.1f}%",
                    f"Memory usage: {df.memory_usage(deep=True).sum() / 1024 / 1024:.2f} MB"
                ])

            insights["recommendations"].extend([
                "Consider handling missing values before analysis",
                "Verify data types for each column",
                "Check for duplicate rows that might affect analysis",
                "Normalize numeric columns if using machine learning"
            ])

            numeric_cols = df.select_dtypes(include=[np.number]).columns
            if len(numeric_cols) > 0:
                insights["recommendations"].append(
                    f"Consider outlier detection for numeric columns: {', '.join(numeric_cols[:3])}"
                )

        except Exception as e:
            insights["error"] = f"Insights generation failed: {str(e)}"

        return insights

# Routes
@app.get("/")
async def root():
    return {
        "status": "success",
        "message": "DataPulse API is running",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "database": "in_memory",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/api/auth/login")
async def login(request: LoginRequest, response: Response):
    try:
        print(f"Login attempt for: {request.email}")
        
        if authenticate_user(request.email, request.password):
            session_id = generate_session_id()
            user_sessions[session_id] = {
                "email": request.email,
                "login_time": datetime.now().isoformat()
            }
            
            response.set_cookie(
                key="session_id",
                value=session_id,
                httponly=True,
                max_age=3600 * 24 * 30 if request.remember else 3600,
                samesite="lax"
            )
            
            return {
                "success": True,
                "message": "Login successful",
                "session_id": session_id,
                "user": {"email": request.email}
            }
        else:
            raise HTTPException(status_code=401, detail="Invalid email or password")
            
    except Exception as e:
        print(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

@app.post("/api/auth/signup")
async def signup(request: SignupRequest, response: Response):
    try:
        print(f"Signup attempt for: {request.email}")
        
        if create_user(request.email, request.password, request.full_name):
            session_id = generate_session_id()
            user_sessions[session_id] = {
                "email": request.email,
                "login_time": datetime.now().isoformat()
            }
            
            response.set_cookie(
                key="session_id",
                value=session_id,
                httponly=True,
                max_age=3600 * 24 * 30,
                samesite="lax"
            )
            
            return {
                "success": True,
                "message": "Signup successful",
                "session_id": session_id,
                "user": {"email": request.email}
            }
        else:
            raise HTTPException(status_code=400, detail="User already exists")
            
    except Exception as e:
        print(f"Signup error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Signup failed: {str(e)}")

@app.post("/api/analyze")
async def analyze_data(
    file: UploadFile = File(...),
    session_id: Optional[str] = Query(None),
    business_goal: Optional[str] = Query("general analysis"),
    current_user: dict = Depends(get_current_user)
):
    try:
        print(f"Analysis request from: {current_user['email']}")
        
        user_email = current_user["email"]
        today = date.today()
        
        if get_user_usage(user_email, today) >= 40:
            return JSONResponse(
                status_code=402,
                content={
                    "success": False,
                    "error": "DAILY_LIMIT_REACHED",
                    "message": "Daily analysis limit reached. Please try again tomorrow."
                }
            )

        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")

        file_content = await file.read()
        if len(file_content) > 10 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="File too large. Maximum size is 10MB")

        file_extension = file.filename.lower().split('.')[-1]
        
        try:
            if file_extension == 'csv':
                df = pd.read_csv(BytesIO(file_content))
            elif file_extension in ['xlsx', 'xls']:
                df = pd.read_excel(BytesIO(file_content))
            else:
                raise HTTPException(status_code=400, detail="Unsupported file format. Use CSV or Excel files.")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error reading file: {str(e)}")

        if df.empty:
            raise HTTPException(status_code=400, detail="File appears to be empty")

        if len(df.columns) == 0:
            raise HTTPException(status_code=400, detail="No columns found in the file")

        analyzer = DataAnalyzer()
        analysis_result = analyzer.analyze_dataframe(df)
        insights = analyzer.generate_insights(df)

        file_hash = hashlib.md5(file_content).hexdigest()
        file_storage[file_hash] = {
            "filename": file.filename,
            "size": len(file_content),
            "upload_time": datetime.now().isoformat(),
            "user": user_email
        }

        increment_user_usage(user_email, today)

        return {
            "success": True,
            "data": {
                "file_info": {
                    "name": file.filename,
                    "size": len(file_content),
                    "rows": len(df),
                    "columns": len(df.columns),
                    "file_hash": file_hash
                },
                "analysis": analysis_result,
                "insights": insights,
                "business_goal": business_goal,
                "analysis_id": f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "usage_count": get_user_usage(user_email, today)
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"Analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/ai-summary")
async def ai_summary(
    file: UploadFile = File(...),
    business_goal: str = Query(""),
    audience: str = Query("executive"),
    current_user: dict = Depends(get_current_user)
):
    try:
        print(f"AI Summary request from: {current_user['email']}")
        
        file_content = await file.read()
        
        if file.filename.lower().endswith('.csv'):
            df = pd.read_csv(BytesIO(file_content))
        else:
            df = pd.read_excel(BytesIO(file_content))

        rows, cols = df.shape
        numeric_cols = len(df.select_dtypes(include=[np.number]).columns)
        text_cols = len(df.select_dtypes(include=['object']).columns)
        
        summary = (
            f"This dataset contains {rows} rows and {cols} columns. "
            f"There are {numeric_cols} numeric columns and {text_cols} text columns. "
            f"The analysis was prepared for {audience} audience. "
            f"Business goal: {business_goal or 'general insights'}. "
            f"Key recommendations include data cleaning, outlier detection, and trend analysis."
        )

        return {
            "success": True,
            "summary": summary,
            "metadata": {
                "rows": rows,
                "columns": cols,
                "audience": audience,
                "business_goal": business_goal
            }
        }

    except Exception as e:
        print(f"AI Summary error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"AI summary failed: {str(e)}")

@app.get("/api/user/profile")
async def get_profile(current_user: dict = Depends(get_current_user)):
    user_email = current_user["email"]
    today = date.today()
    
    return {
        "success": True,
        "user": {
            "email": user_email,
            "today_usage": get_user_usage(user_email, today),
            "daily_limit": 40,
            "remaining_analysis": max(0, 40 - get_user_usage(user_email, today))
        }
    }

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "error": exc.detail,
            "status_code": exc.status_code
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    print(f"Unhandled error: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "Internal server error",
            "detail": str(exc)
        }
    )

# Vercel handler - FIXED: Proper Mangum initialization
# ✅ Correct Vercel Mangum integration
from mangum import Mangum

handler = Mangum(app)
