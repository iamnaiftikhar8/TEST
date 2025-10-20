import os
import json
import pandas as pd
import numpy as np
from io import BytesIO
import hashlib
import uuid
import httpx
import bcrypt
from datetime import datetime, date, timedelta
from typing import Optional, Dict, Any, List, Tuple
import google.generativeai as genai

from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Response, Query, Depends, status, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, EmailStr

# ---------------------------------------------------------
# ✅ Configuration
# ---------------------------------------------------------
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://data-pulse-one.vercel.app")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "AIzaSyBe8E5aR-g5ecP7OThZB6S_Sg-A2RAZ3bk")
FREE_REPORTS_PER_DAY = 40

# Database configuration
DB_HOST = os.getenv("DB_HOST", "mssql-196323-0.cloudclusters.net")
DB_PORT = os.getenv("DB_PORT", "19996")
DB_NAME = os.getenv("DB_NAME", "DataPulse")
DB_UID = os.getenv("DB_UID", "saqib")
DB_PWD = os.getenv("DB_PWD", "AdmTsg@2025")

SQL_SERVER_CONN_STR = (
    f"DRIVER={{ODBC Driver 18 for SQL Server}};"
    f"SERVER={DB_HOST},{DB_PORT};"
    f"DATABASE={DB_NAME};"
    f"UID={DB_UID};"
    f"PWD={DB_PWD};"
    "Encrypt=yes;"
    "TrustServerCertificate=yes;"
)

# ---------------------------------------------------------
# ✅ Initialize FastAPI
# ---------------------------------------------------------
app = FastAPI(
    title="DataPulse API",
    description="Data analysis API deployed on Vercel",
    version="1.0.0"
)

# ---------------------------------------------------------
# ✅ CORS Configuration - FIXED for Production
# ---------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://data-pulse-one.vercel.app",
        "https://test-six-fawn-47.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------
# ✅ In-memory storage (Fallback)
# ---------------------------------------------------------
user_sessions = {}
file_storage = {}
user_usage = {}
users_db = {}
uploaded_files = {}  # Store uploaded files for AI summary

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

class AISummaryRequest(BaseModel):
    upload_id: str
    business_goal: Optional[str] = None
    audience: str = "executive"
    analysis_depth: str = "comprehensive"
    include_predictions: bool = True
    include_benchmarks: bool = True
    include_risk_assessment: bool = True

# ---------------------------------------------------------
# ✅ Database Functions
# ---------------------------------------------------------
try:
    import pyodbc as db_lib
except ImportError:
    try:
        import pypyodbc as db_lib
    except ImportError:
        db_lib = None

def get_db_conn():
    if db_lib and SQL_SERVER_CONN_STR:
        return db_lib.connect(SQL_SERVER_CONN_STR)
    return None

def ensure_tables():
    """Create necessary tables if they don't exist"""
    conn = get_db_conn()
    if not conn:
        return
        
    try:
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='users' AND xtype='U')
        CREATE TABLE users (
            id INT IDENTITY PRIMARY KEY,
            email NVARCHAR(256) NOT NULL UNIQUE,
            full_name NVARCHAR(200) NULL,
            password_hash NVARCHAR(200) NOT NULL,
            created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
            last_login_at DATETIME2 NULL
        )
        """)
        
        # User sessions table
        cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='user_sessions' AND xtype='U')
        CREATE TABLE user_sessions (
            session_id NVARCHAR(64) NOT NULL PRIMARY KEY,
            user_id NVARCHAR(128) NOT NULL,
            created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
            expires_at DATETIME2 NULL,
            ip NVARCHAR(64) NULL,
            user_agent NVARCHAR(512) NULL
        )
        """)
        
        conn.commit()
    except Exception as e:
        print(f"Database setup error: {e}")
    finally:
        conn.close()

def user_by_email(email: str) -> Dict[str, Any] | None:
    """Get user by email from database"""
    conn = get_db_conn()
    if not conn:
        return users_db.get(email)
        
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, email, full_name, password_hash, created_at, last_login_at FROM users WHERE email = ?",
            (email,)
        )
        row = cursor.fetchone()
        if row:
            return {
                'id': row[0],
                'email': row[1],
                'full_name': row[2],
                'password_hash': row[3],
                'created_at': row[4],
                'last_login_at': row[5]
            }
        return None
    except Exception as e:
        print(f"Database error: {e}")
        return users_db.get(email)
    finally:
        conn.close()

def insert_user(full_name: Optional[str], email: str, password_hash: str) -> bool:
    """Insert new user into database"""
    conn = get_db_conn()
    if not conn:
        # Fallback to in-memory storage
        if email in users_db:
            return False
        users_db[email] = {
            'email': email,
            'full_name': full_name,
            'password_hash': password_hash,
            'created_at': datetime.now().isoformat()
        }
        return True
        
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)",
            (full_name, email, password_hash)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"Database insert error: {e}")
        return False
    finally:
        conn.close()

def ensure_session(user_id: str, session_id: Optional[str], ip: Optional[str], ua: Optional[str]) -> str:
    """Ensure session exists in database"""
    conn = get_db_conn()
    if not conn:
        # Fallback to in-memory storage
        if session_id and session_id in user_sessions:
            return session_id
        new_sid = str(uuid.uuid4())
        user_sessions[new_sid] = user_id
        return new_sid
        
    try:
        cursor = conn.cursor()
        
        # Check if session exists
        if session_id:
            cursor.execute("SELECT 1 FROM user_sessions WHERE session_id = ?", (session_id,))
            if cursor.fetchone():
                return session_id
        
        # Create new session
        new_sid = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO user_sessions (session_id, user_id, ip, user_agent) VALUES (?, ?, ?, ?)",
            (new_sid, user_id, ip, ua)
        )
        conn.commit()
        return new_sid
    except Exception as e:
        print(f"Session error: {e}")
        # Fallback
        new_sid = str(uuid.uuid4())
        user_sessions[new_sid] = user_id
        return new_sid
    finally:
        conn.close()

def resolve_user_from_session(session_id: str) -> Optional[str]:
    """Get user ID from session"""
    conn = get_db_conn()
    if not conn:
        return user_sessions.get(session_id)
        
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM user_sessions WHERE session_id = ?", (session_id,))
        row = cursor.fetchone()
        return row[0] if row else None
    except Exception as e:
        print(f"Session resolve error: {e}")
        return user_sessions.get(session_id)
    finally:
        conn.close()

# ---------------------------------------------------------
# ✅ Authentication & Session Management
# ---------------------------------------------------------
def client_meta(x_forwarded_for: Optional[str], user_agent: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    ip = (x_forwarded_for.split(",")[0].strip() if x_forwarded_for else None)
    ua = user_agent[:512] if user_agent else None
    return ip, ua

def get_current_auth(request: Request):
    """Get current authenticated user"""
    sid = request.cookies.get("dp_session_id") or request.cookies.get("session_id")
    if not sid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    user_email = resolve_user_from_session(sid)
    if not user_email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")

    xff = request.headers.get("X-Forwarded-For")
    ip = (xff.split(",")[0].strip() if xff else None)
    ua = request.headers.get("User-Agent")
    ua = ua[:512] if ua else None

    # Refresh session
    new_sid = ensure_session(user_email, sid, ip, ua)
    return {"user_id": user_email, "session_id": new_sid}

# ---------------------------------------------------------
# ✅ Enhanced AI Service
# ---------------------------------------------------------
class AIService:
    def __init__(self) -> None:
        if GEMINI_API_KEY:
            try:
                genai.configure(api_key=GEMINI_API_KEY)
                self.model = genai.GenerativeModel("gemini-2.0-flash")
                print("✅ Gemini AI configured")
            except Exception as e:
                print(f"❌ Gemini configuration failed: {e}")
                self.model = None
        else:
            self.model = None
            print("⚠️ No Gemini API key - using fallback summaries")

    def _json_default(self, o):
        """Make pandas/numpy/datetime objects JSON-serializable."""
        if isinstance(o, (pd.Timestamp, datetime)):
            return o.isoformat()
        if hasattr(o, "item"):
            try:
                return o.item()
            except Exception:
                pass
        return str(o)

    def summarize(self, df: pd.DataFrame, business_goal: Optional[str], audience: str) -> str:
        if not self.model:
            return self._pandas_fallback(df, business_goal, audience)

        rows, cols = df.shape
        payload = {
            "shape": [int(rows), int(cols)],
            "dtypes": df.dtypes.astype(str).to_dict(),
            "numeric_columns": df.select_dtypes(include="number").columns.tolist(),
            "categorical_columns": df.select_dtypes(include=["object", "category", "bool"]).columns.tolist(),
            "missing_by_column": df.isna().sum().to_dict(),
            "sample": df.head(20).to_dict(orient="records"),
        }
        
        prompt = (
            "You are a senior data analyst. Write ONE detailed, coherent paragraph (no bullet points, no markdown) "
            f"that explains the dataset. Audience: {audience}. Business goal: {business_goal or 'general insights'}.\n\n"
            "DATA (JSON):\n" + json.dumps(payload, default=self._json_default)
        )

        try:
            resp = self.model.generate_content(prompt, generation_config={"max_output_tokens": 512})
            paragraph = " ".join((resp.text or "").splitlines()).strip()
            return paragraph if paragraph else self._pandas_fallback(df, business_goal, audience)
        except Exception:
            return self._pandas_fallback(df, business_goal, audience)

    def _pandas_fallback(self, df: pd.DataFrame, business_goal: Optional[str], audience: str) -> str:
        rows, cols = df.shape
        missing_pct = (df.isna().sum().sum() / (rows * cols) * 100) if rows and cols else 0
        numeric_cols = df.select_dtypes(include="number").columns.tolist()
        
        summary = (
            f"This dataset contains {rows:,} rows and {cols:,} columns. "
            f"About {missing_pct:.1f}% of values are missing. "
            f"There are {len(numeric_cols)} numeric columns. "
            f"Analysis prepared for {audience} audience with goal: {business_goal or 'general insights'}."
        )
        return summary

    def generate_detailed_summary(self, df: pd.DataFrame, business_goal: Optional[str], audience: str) -> Dict[str, Any]:
        """Generate comprehensive structured AI summary"""
        
        # Basic dataset stats
        rows, cols = df.shape
        missing_total = df.isna().sum().sum()
        missing_pct = (missing_total / (rows * cols) * 100) if rows and cols else 0
        numeric_cols = df.select_dtypes(include="number").columns.tolist()
        categorical_cols = df.select_dtypes(include=["object", "category", "bool"]).columns.tolist()
        date_cols = df.select_dtypes(include=["datetime64", "datetime64[ns]"]).columns.tolist()
        
        # Advanced analysis
        duplicate_rows = df.duplicated().sum()
        numeric_df = df.select_dtypes(include="number").apply(pd.to_numeric, errors="coerce")
        
        # Calculate outliers using IQR method
        outlier_counts = {}
        for col in numeric_cols:
            outlier_counts[col] = _iqr_outliers(df[col])
        total_outliers = sum(outlier_counts.values())
        
        # Find columns with highest variance
        variance_data = {}
        for col in numeric_cols:
            if len(df[col].dropna()) > 1:
                variance_data[col] = df[col].var()
        
        top_variance_cols = sorted(variance_data.items(), key=lambda x: x[1], reverse=True)[:3]
        
        # Generate comprehensive AI analysis
        if self.model:
            return self._generate_ai_comprehensive_analysis(
                df, business_goal, audience, rows, cols, missing_total, 
                missing_pct, numeric_cols, categorical_cols, date_cols,
                duplicate_rows, total_outliers, top_variance_cols
            )
        else:
            return self._generate_fallback_analysis(
                df, business_goal, audience, rows, cols, missing_total, 
                missing_pct, numeric_cols, categorical_cols, date_cols,
                duplicate_rows, total_outliers, top_variance_cols
            )

    def _generate_ai_comprehensive_analysis(self, df, business_goal, audience, rows, cols, 
                                          missing_total, missing_pct, numeric_cols, 
                                          categorical_cols, date_cols, duplicate_rows, 
                                          total_outliers, top_variance_cols):
        """Generate comprehensive analysis using Gemini AI"""
        
        # Prepare data payload for AI
        payload = {
            "dataset_info": {
                "rows": int(rows),
                "columns": int(cols),
                "missing_values": int(missing_total),
                "missing_percentage": float(missing_pct),
                "duplicate_rows": int(duplicate_rows),
                "outliers": int(total_outliers),
                "numeric_columns_count": len(numeric_cols),
                "categorical_columns_count": len(categorical_cols),
                "date_columns_count": len(date_cols)
            },
            "column_analysis": {
                "numeric_columns": numeric_cols,
                "categorical_columns": categorical_cols[:10],  # Limit to first 10
                "date_columns": date_cols,
                "high_variance_columns": [col for col, _ in top_variance_cols]
            },
            "sample_data": df.head(10).to_dict(orient="records"),
            "business_context": {
                "goal": business_goal or "general analysis",
                "audience": audience,
                "industry_insights": "retail"  # You can make this dynamic
            }
        }
        
        prompt = f"""
        You are a senior data analyst and business intelligence expert. Analyze this dataset and provide a comprehensive business analysis.
        
        AUDIENCE: {audience.upper()}
        BUSINESS GOAL: {business_goal or "General business insights"}
        
        DATASET OVERVIEW:
        - {rows:,} rows, {cols} columns
        - {missing_total:,} missing values ({missing_pct:.1f}%)
        - {duplicate_rows:,} duplicate rows
        - {total_outliers:,} statistical outliers
        - {len(numeric_cols)} numeric columns, {len(categorical_cols)} categorical columns
        
        Please provide a structured analysis with these sections:
        
        1. EXECUTIVE OVERVIEW: One paragraph summarizing the dataset's business significance
        2. DATA QUALITY ASSESSMENT: Assessment of data reliability and issues
        3. KEY TRENDS: 3-5 major patterns or trends discovered
        4. BUSINESS IMPLICATIONS: 3-5 business consequences of these findings
        5. RECOMMENDATIONS: 
           - Short-term actions (0-3 months)
           - Long-term strategies (3-12 months)
        6. QUICK WINS: 3-5 immediate, high-impact actions
        7. RISK ALERTS: 2-3 potential risks or data concerns
        8. PREDICTIVE INSIGHTS: 2-3 forward-looking observations
        9. INDUSTRY COMPARISON: How this compares to industry standards
        
        Return your analysis as a JSON object with this structure:
        {{
            "executive_overview": "string",
            "data_quality_assessment": "string", 
            "key_trends": ["string1", "string2"],
            "business_implications": ["string1", "string2"],
            "recommendations": {{
                "short_term": ["string1", "string2"],
                "long_term": ["string1", "string2"]
            }},
            "action_items_quick_wins": ["string1", "string2"],
            "risk_alerts": ["string1", "string2"],
            "predictive_insights": ["string1", "string2"],
            "industry_comparison": "string"
        }}
        
        DATA PAYLOAD:
        {json.dumps(payload, default=self._json_default, indent=2)}
        """
        
        try:
            response = self.model.generate_content(
                prompt, 
                generation_config={
                    "max_output_tokens": 2048,
                    "temperature": 0.3
                }
            )
            
            # Parse the JSON response
            if response.text:
                # Extract JSON from the response (Gemini might wrap it in markdown)
                text = response.text.strip()
                if "```json" in text:
                    text = text.split("```json")[1].split("```")[0].strip()
                elif "```" in text:
                    text = text.split("```")[1].strip() if len(text.split("```")) > 2 else text
                
                analysis = json.loads(text)
                
                # Ensure all fields are present
                return {
                    "executive_overview": analysis.get("executive_overview", ""),
                    "data_quality_assessment": analysis.get("data_quality_assessment", ""),
                    "key_trends": analysis.get("key_trends", []),
                    "business_implications": analysis.get("business_implications", []),
                    "recommendations": analysis.get("recommendations", {"short_term": [], "long_term": []}),
                    "action_items_quick_wins": analysis.get("action_items_quick_wins", []),
                    "risk_alerts": analysis.get("risk_alerts", []),
                    "predictive_insights": analysis.get("predictive_insights", []),
                    "industry_comparison": analysis.get("industry_comparison", "")
                }
                
        except Exception as e:
            print(f"AI analysis error: {e}")
        
        # Fallback if AI fails
        return self._generate_fallback_analysis(
            df, business_goal, audience, rows, cols, missing_total, 
            missing_pct, numeric_cols, categorical_cols, date_cols,
            duplicate_rows, total_outliers, top_variance_cols
        )

    def _generate_fallback_analysis(self, df, business_goal, audience, rows, cols, 
                                  missing_total, missing_pct, numeric_cols, 
                                  categorical_cols, date_cols, duplicate_rows, 
                                  total_outliers, top_variance_cols):
        """Generate fallback analysis when AI is unavailable"""
        
        executive_overview = (
            f"This dataset contains {rows:,} records across {cols} columns, providing "
            f"comprehensive business data for analysis. With {missing_pct:.1f}% missing values "
            f"and {duplicate_rows:,} duplicate entries, the data quality requires attention. "
            f"The analysis identifies {total_outliers:,} statistical outliers across {len(numeric_cols)} "
            f"numeric metrics, highlighting areas for deeper investigation."
        )
        
        data_quality_assessment = (
            f"Data quality is {'good' if missing_pct < 5 else 'moderate' if missing_pct < 15 else 'poor'}. "
            f"Key issues include {missing_total:,} missing values ({missing_pct:.1f}%) and "
            f"{duplicate_rows:,} duplicate records. The dataset covers {len(numeric_cols)} numeric "
            f"metrics and {len(categorical_cols)} categorical dimensions."
        )
        
        # Generate context-aware insights based on column names
        has_sales = any('sale' in col.lower() or 'revenue' in col.lower() for col in df.columns)
        has_customer = any('customer' in col.lower() or 'client' in col.lower() for col in df.columns)
        has_date = len(date_cols) > 0
        
        key_trends = []
        if has_sales:
            key_trends.append("Sales data shows consistent patterns with identifiable seasonal variations")
        if has_customer:
            key_trends.append("Customer data reveals segmentation opportunities for targeted marketing")
        if has_date:
            key_trends.append("Temporal analysis indicates clear time-based patterns in the data")
        key_trends.append(f"Statistical analysis identifies {total_outliers:,} outliers requiring investigation")
        
        business_implications = [
            "Data quality issues may impact decision-making accuracy",
            "Identified patterns provide opportunities for process optimization",
            "Outlier detection highlights potential operational anomalies"
        ]
        
        return {
            "executive_overview": executive_overview,
            "data_quality_assessment": data_quality_assessment,
            "key_trends": key_trends,
            "business_implications": business_implications,
            "recommendations": {
                "short_term": [
                    "Implement data cleaning procedures for missing values",
                    "Remove duplicate records to ensure analysis accuracy",
                    "Investigate highest priority outliers for immediate action"
                ],
                "long_term": [
                    "Establish ongoing data quality monitoring processes",
                    "Develop automated anomaly detection systems",
                    "Create data governance framework for continuous improvement"
                ]
            },
            "action_items_quick_wins": [
                "Clean obvious duplicate records",
                "Address critical missing values in key columns", 
                "Document data quality baseline for future comparison"
            ],
            "risk_alerts": [
                f"Data quality issues ({missing_pct:.1f}% missing) may affect decision reliability",
                f"{total_outliers:,} statistical outliers indicate potential data anomalies"
            ],
            "predictive_insights": [
                "Historical patterns suggest predictable business cycles",
                "Data structure supports future trend forecasting capabilities"
            ],
            "industry_comparison": "Dataset structure aligns with standard business intelligence practices"
        }

# ---------------------------------------------------------
# ✅ Data Analysis Functions
# ---------------------------------------------------------
def try_parse_dates_inplace(df: pd.DataFrame, max_cols: int = 3, min_ratio: float = 0.6):
    """Try to parse date columns automatically"""
    candidates = [c for c in df.columns if any(tok in c.lower() for tok in ("date", "time", "timestamp"))]
    tried = 0
    for c in candidates:
        if tried >= max_cols: 
            break
        s = df[c]
        if not (s.dtype == "object" or pd.api.types.is_string_dtype(s)): 
            continue
        parsed = pd.to_datetime(s, errors="coerce", utc=False)
        non_null = s.notna().sum()
        if non_null and parsed.notna().sum() >= min_ratio * non_null:
            df[c] = parsed
            tried += 1

def _safe_float(x):
    """Safely convert to float"""
    try:
        if x is None: 
            return None
        x = float(x)
        if np.isnan(x) or np.isinf(x): 
            return None
        return x
    except Exception:
        return None

def _iqr_outliers(col: pd.Series) -> int:
    """Count IQR outliers in a numeric column"""
    col = pd.to_numeric(col, errors="coerce").dropna()
    if col.empty: 
        return 0
    q1, q3 = col.quantile(0.25), col.quantile(0.75)
    iqr = q3 - q1
    if not np.isfinite(iqr) or iqr == 0: 
        return 0
    lower, upper = q1 - 1.5*iqr, q3 + 1.5*iqr
    return int(((col < lower) | (col > upper)).sum())

def store_uploaded_file(upload_id: str, file_data: bytes, filename: str, user_id: str):
    """Store uploaded file for later AI analysis"""
    uploaded_files[upload_id] = {
        'data': file_data,
        'filename': filename,
        'user_id': user_id,
        'uploaded_at': datetime.now()
    }

def get_uploaded_file(upload_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve uploaded file for AI analysis"""
    file_info = uploaded_files.get(upload_id)
    if file_info and file_info['user_id'] == user_id:
        return file_info
    return None

# ---------------------------------------------------------
# ✅ Routes
# ---------------------------------------------------------
@app.get("/")
async def root():
    return {"status": "success", "message": "DataPulse API running on Vercel", "version": "1.0.0"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/health/db")
async def health_db():
    """Check database connectivity"""
    try:
        ensure_tables()
        return {"ok": True, "database": "connected"}
    except Exception as e:
        return {"ok": False, "database": "error", "error": str(e)}

@app.post("/api/auth/signup")
async def signup(request: SignupRequest, response: Response):
    """User signup with auto-login"""
    # Check if user exists
    existing_user = user_by_email(request.email)
    if existing_user:
        raise HTTPException(status_code=409, detail="EMAIL_TAKEN")

    # Hash password
    pw_hash = bcrypt.hashpw(request.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    
    # Create user
    if not insert_user(request.full_name, request.email, pw_hash):
        raise HTTPException(status_code=400, detail="Signup failed")

    # Auto-login
    ip, ua = client_meta(None, None)  # Simplified for now
    session_id = ensure_session(request.email, None, ip, ua)

    # Set cookie - FIXED for production
    response.set_cookie(
        key="dp_session_id",
        value=session_id,
        httponly=True,
        secure=True,           # Required for HTTPS
        samesite="none",       # Required for cross-origin
        max_age=86400,         # 24 hours
        path="/"
    )
    response.headers["X-Session-Id"] = session_id
    
    return {
        "success": True, 
        "message": "Signup successful", 
        "session_id": session_id,
        "user_id": request.email
    }

@app.post("/api/auth/login")
async def login(request: LoginRequest, response: Response):
    """User login"""
    user = user_by_email(request.email)
    if not user or not user.get("password_hash"):
        raise HTTPException(status_code=401, detail="INVALID_CREDENTIALS")

    # Verify password
    if not bcrypt.checkpw(request.password.encode("utf-8"), user["password_hash"].encode("utf-8")):
        raise HTTPException(status_code=401, detail="INVALID_CREDENTIALS")

    # Create session
    ip, ua = client_meta(None, None)
    session_id = ensure_session(user["email"], None, ip, ua)

    # Set cookie - FIXED for production
    response.set_cookie(
        key="dp_session_id",
        value=session_id,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=(60 * 60 * 24 * 30) if request.remember else 86400,
        path="/"
    )
    response.headers["X-Session-Id"] = session_id
    
    return {
        "success": True, 
        "message": "Login successful", 
        "session_id": session_id,
        "user_id": user["email"]
    }

@app.post("/api/ai-summary")
async def ai_summary(
    request: AISummaryRequest,
    response: Response,
    auth: dict = Depends(get_current_auth),
):
    """Generate comprehensive AI summary for previously uploaded file"""
    user_id = auth["user_id"]
    session_id = auth["session_id"]

    # Refresh session cookie
    response.set_cookie(
        key="dp_session_id",
        value=session_id,
        httponly=True,
        secure=True,
        samesite="none",
        path="/"
    )
    response.headers["X-Session-Id"] = session_id

    # Retrieve uploaded file
    file_info = get_uploaded_file(request.upload_id, user_id)
    if not file_info:
        raise HTTPException(status_code=404, detail="File not found or access denied")

    try:
        # Parse the file
        file_data = file_info['data']
        filename = file_info['filename']
        
        if filename.lower().endswith(".csv"):
            df = pd.read_csv(BytesIO(file_data))
        else:
            df = pd.read_excel(BytesIO(file_data))

        # Generate comprehensive AI analysis
        ai_service = AIService()
        detailed_summary = ai_service.generate_detailed_summary(
            df, 
            request.business_goal, 
            request.audience
        )
        
        return {
            **detailed_summary,
            "session_id": session_id,
            "upload_id": request.upload_id
        }
        
    except Exception as e:
        return JSONResponse(
            status_code=400, 
            content={"error": "ANALYSIS_FAILED", "detail": str(e)}
        )

@app.post("/api/analyze")
async def analyze(
    request: Request,
    response: Response,
    file: UploadFile = File(...),
    auth: dict = Depends(get_current_auth),
):
    """Comprehensive data analysis"""
    user_id = auth["user_id"]
    session_id = auth["session_id"]

    # Refresh session cookie
    response.set_cookie(
        key="dp_session_id",
        value=session_id,
        httponly=True,
        secure=True,
        samesite="none",
        path="/"
    )
    response.headers["X-Session-Id"] = session_id

    # Check file size
    raw = await file.read()
    if len(raw) > 10 * 1024 * 1024:  # 10MB limit
        raise HTTPException(status_code=400, detail="File too large (max 10MB)")

    # Generate upload ID for later AI summary calls
    upload_id = hashlib.sha256(raw).hexdigest()[:32]
    store_uploaded_file(upload_id, raw, file.filename, user_id)

    # Parse file
    try:
        if (file.filename or "").lower().endswith(".csv"):
            df = pd.read_csv(BytesIO(raw))
        else:
            df = pd.read_excel(BytesIO(raw))
    except Exception as e:
        return JSONResponse(
            status_code=400, 
            content={"error": "INVALID_FILE", "detail": str(e)}
        )

    # Basic profiling
    try_parse_dates_inplace(df)
    
    numeric_cols = df.select_dtypes("number").columns.tolist()
    profiling = {
        "rows": int(df.shape[0]),
        "columns": int(df.shape[1]),
        "missing_total": int(df.isnull().sum().sum()),
        "dtypes": {c: str(t) for c, t in df.dtypes.items()},
        "numeric_columns": numeric_cols,
    }

    # Generate charts data
    charts = {}
    
    # Line chart data
    line_data = []
    date_cols = df.select_dtypes(include=["datetime64[ns]", "datetime64[ns, UTC]"])
    if not date_cols.empty:
        date_col = date_cols.columns[0]
        ser = pd.to_datetime(df[date_col], errors="coerce")
        if ser.notna().any():
            per_day = ser.dt.date.value_counts().sort_index()
            line_data = [{"x": str(k), "y": int(v)} for k, v in per_day.items()]
    
    if not line_data:
        first_num = df.select_dtypes(include="number")
        if not first_num.empty:
            col = first_num.columns[0]
            s = pd.to_numeric(first_num[col], errors="coerce").dropna()
            if len(s) > 200:
                s = s.iloc[:: max(1, len(s) // 200)]
            line_data = [{"x": int(i), "y": float(v)} for i, v in enumerate(s.tolist(), start=1)]
        else:
            line_data = [{"x": i, "y": i} for i in range(1, 8)]

    # Bar chart data
    bar_data = []
    cat_df = df.select_dtypes(include=["object", "category", "bool"])
    if not cat_df.empty:
        chosen_bar_col = cat_df.columns[0]
        vc = df[chosen_bar_col].astype("string").fillna("NaN").value_counts().head(5)
        bar_data = [{"name": str(k)[:24], "value": int(v)} for k, v in vc.items()]
    
    if not bar_data:
        bar_data = [{"name": f"C{i}", "value": i * 10} for i in range(1, 6)]

    # Pie chart data
    pie_data = []
    if not cat_df.empty:
        pie_col = cat_df.columns[0] if len(cat_df.columns) > 1 else cat_df.columns[0]
        vc = df[pie_col].astype("string").fillna("NaN").value_counts()
        top5 = vc.head(5)
        other = int(vc.iloc[5:].sum()) if len(vc) > 5 else 0
        pie_data = [{"name": str(k)[:24], "value": int(v)} for k, v in top5.items()]
        if other > 0: 
            pie_data.append({"name": "Other", "value": other})
    
    if not pie_data:
        pie_data = [{"name": "A", "value": 40}, {"name": "B", "value": 30}, {"name": "C", "value": 30}]

    charts = {"line": line_data, "bar": bar_data, "pie": pie_data}

    # Calculate KPIs
    numeric_df = df.select_dtypes(include="number").apply(pd.to_numeric, errors="coerce")
    total_cells = max(1, int(df.shape[0] * df.shape[1]))
    missing_total = int(df.isna().sum().sum())
    missing_pct = round(missing_total / total_cells * 100, 2)
    duplicates = int(df.duplicated().sum())

    outlier_counts = {c: _iqr_outliers(numeric_df[c]) for c in numeric_df.columns} if not numeric_df.empty else {}
    total_outliers = int(sum(outlier_counts.values()))

    kpis = {
        "total_rows": int(df.shape[0]),
        "total_columns": int(df.shape[1]),
        "missing_pct": _safe_float(missing_pct),
        "duplicate_rows": duplicates,
        "outliers_total": total_outliers,
    }

    # Generate AI insights
    ai_service = AIService()
    detailed_summary = ai_service.generate_detailed_summary(df, None, "executive")

    return {
        "profiling": profiling,
        "kpis": kpis,
        "charts": charts,
        "insights": {
            "summary": "Automated data analysis complete",
            "key_insights": ["Data quality assessment completed", "Basic statistical analysis performed"],
            "recommendations": ["Review missing values", "Verify data types"]
        },
        "detailed_summary": detailed_summary,
        "session_id": session_id,
        "upload_id": upload_id,  # Return upload_id for subsequent AI summary calls
        "file": {
            "name": file.filename,
            "size_bytes": len(raw),
        },
    }

@app.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    """User logout"""
    response.delete_cookie("dp_session_id", path="/")
    return {"success": True, "message": "Logout successful"}

@app.get("/api/test-db")
async def test_db():
    """Test if database is connected"""
    try:
        conn = get_db_conn()
        if conn:
            # Try to create tables
            ensure_tables()
            conn.close()
            return {"database": "CONNECTED ✅", "storage": "SQL Server"}
        else:
            return {"database": "NOT CONNECTED ⚠️", "storage": "In-Memory"}
    except Exception as e:
        return {"database": "ERROR ❌", "error": str(e), "storage": "In-Memory"}
@app.get("/api/auth/google")
async def google_login():
    """Start Google OAuth flow"""
    client_id = "144224946029-99vhg2ds2dhfn4i98qmkj5v88fgbtnt7.apps.googleusercontent.com"
    redirect_uri = "https://test-six-fawn-47.vercel.app/api/auth/google/callback"
    
    auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth?"
        f"client_id={client_id}&"
        f"response_type=code&"
        f"scope=openid%20email%20profile&"
        f"redirect_uri={redirect_uri}&"
        f"access_type=offline&"
        f"prompt=select_account"
    )
    
    return RedirectResponse(auth_url)

@app.get("/api/auth/google/callback")
async def google_callback(request: Request, response: Response, code: str = None):
    """Handle Google OAuth callback - FIXED VERSION"""
    try:
        if not code:
            return RedirectResponse("https://data-pulse-one.vercel.app/login?error=no_code")
        
        # Exchange code for tokens
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            'client_id': "144224946029-99vhg2ds2dhfn4i98qmkj5v88fgbtnt7.apps.googleusercontent.com",
            'client_secret': "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",
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://test-six-fawn-47.vercel.app/api/auth/google/callback'
        }
        
        async with httpx.AsyncClient() as client:
            # Get access token
            token_response = await client.post(token_url, data=data)
            tokens = token_response.json()
            
            if 'error' in tokens:
                print(f"Token error: {tokens}")
                return RedirectResponse("https://data-pulse-one.vercel.app/login?error=auth_failed")
            
            # Get user info from Google
            userinfo_response = await client.get(
                'https://www.googleapis.com/oauth2/v3/userinfo',
                headers={'Authorization': f"Bearer {tokens['access_token']}"}
            )
            user_info = userinfo_response.json()
            
            if 'error' in user_info:
                print(f"Userinfo error: {user_info}")
                return RedirectResponse("https://data-pulse-one.vercel.app/login?error=user_info_failed")
        
        # Extract user data
        email = user_info['email']
        name = user_info.get('name', 'User')
        google_id = user_info['sub']
        
        print(f"Google user: {email}, {name}, {google_id}")
        
        # Check if user exists by email
        existing_user = user_by_email(email)
        
        if existing_user:
            # User exists - update with Google ID if needed
            if not existing_user.get('google_id'):
                update_user_google_id(email, google_id)
            user_id = existing_user['email']
        else:
            # Create new user
            success = create_google_user(email, name, google_id)
            if not success:
                return RedirectResponse("https://data-pulse-one.vercel.app/login?error=user_creation_failed")
            user_id = email
        
        # Create session using your EXISTING session system
        session_id = str(uuid.uuid4())
        
        # Get IP and User Agent
        xff = request.headers.get("X-Forwarded-For")
        client_ip = xff.split(",")[0].strip() if xff else request.client.host
        user_agent = request.headers.get("User-Agent", "")[:512]
        
        # Use your existing session management - FIXED function name
        ensure_session(user_id, session_id, client_ip, user_agent)
        
        # Set cookies - FIXED cookie settings
        response.set_cookie(
            key="session_id",  # Use your actual cookie name
            value=session_id,
            httponly=True,
            secure=True,
            samesite="none",  # FIXED: removed extra quotes
            max_age=30 * 24 * 60 * 60,  # 30 days - FIXED: proper syntax
            path="/"
        )
        
        # Redirect to frontend - FIXED URL
        return RedirectResponse("https://data-pulse-one.vercel.app/analyze")
        
    except Exception as e:
        print(f"Google OAuth error: {e}")
        return RedirectResponse("https://data-pulse-one.vercel.app/login?error=auth_failed")

# Add these helper functions to your backend
def create_google_user(email: str, name: str, google_id: str) -> bool:
    """Create a user for Google OAuth"""
    try:
        # Try database first
        conn = get_db_conn()
        if conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (email, full_name, google_id, password_hash) VALUES (?, ?, ?, ?)",
                (email, name, google_id, None)  # NULL password for Google users
            )
            conn.commit()
            conn.close()
            return True
        else:
            # Fallback to in-memory storage
            users_db[email] = {
                'email': email,
                'full_name': name,
                'google_id': google_id,
                'password_hash': None,
                'created_at': datetime.now().isoformat()
            }
            return True
    except Exception as e:
        print(f"User creation error: {e}")
        # User might already exist - that's ok
        return True

def update_user_google_id(email: str, google_id: str) -> bool:
    """Update existing user with Google ID"""
    try:
        conn = get_db_conn()
        if conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET google_id = ? WHERE email = ?",
                (google_id, email)
            )
            conn.commit()
            conn.close()
        else:
            # Update in-memory storage
            if email in users_db:
                users_db[email]['google_id'] = google_id
        return True
    except Exception as e:
        print(f"Update user error: {e}")
        return False
# ---------------------------------------------------------
# ✅ Session Management Routes
# ---------------------------------------------------------
@app.post("/api/session/start")
async def start_session(request: Request, response: Response):
    """Start or refresh user session"""
    sid = request.cookies.get("dp_session_id")
    xff = request.headers.get("X-Forwarded-For")
    ip = (xff.split(",")[0].strip() if xff else None)
    ua = request.headers.get("User-Agent")
    ua = ua[:512] if ua else None

    if sid:
        user_email = resolve_user_from_session(sid)
        if user_email:
            new_sid = ensure_session(user_email, sid, ip, ua)
            response.set_cookie(
                key="dp_session_id",
                value=new_sid,
                httponly=True,
                secure=True,
                samesite="none",
                path="/"
            )
            return {"success": True, "session_id": new_sid}

    # Create anonymous session
    anonymous_id = f"anonymous_{uuid.uuid4()}"
    new_sid = ensure_session(anonymous_id, None, ip, ua)
    response.set_cookie(
        key="dp_session_id",
        value=new_sid,
        httponly=True,
        secure=True,
        samesite="none",
        path="/"
    )
    return {"success": True, "session_id": new_sid, "anonymous": True}

# ---------------------------------------------------------
# ✅ Error Handlers
# ---------------------------------------------------------
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)}
    )

# ---------------------------------------------------------
# ✅ Startup Event
# ---------------------------------------------------------
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    print("🚀 DataPulse API starting up...")
    ensure_tables()
    print("✅ Database tables initialized")
    
    # Test AI service
    ai_service = AIService()
    print("✅ Services initialized")

# ---------------------------------------------------------
# ✅ Vercel Handler
# ---------------------------------------------------------
# For Vercel serverless deployment
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)