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
FREE_REPORTS_PER_DAY = 4

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
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
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
# ✅ Database Functions - UPDATED FOR FILE STORAGE
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
    """Create necessary tables if they don't exist - UPDATED with uploaded_files table"""
    conn = get_db_conn()
    if not conn:
        return
        
    try:
        cursor = conn.cursor()
        
        # Users table - UPDATED with google_id
        cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='users' AND xtype='U')
        CREATE TABLE users (
            id INT IDENTITY PRIMARY KEY,
            email NVARCHAR(256) NOT NULL UNIQUE,
            full_name NVARCHAR(200) NULL,
            password_hash NVARCHAR(200) NULL,  -- NULL for Google users
            google_id NVARCHAR(128) NULL,      -- ADDED for Google OAuth
            created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
            last_login_at DATETIME2 NULL
        )
        """)
        
        # User sessions table
        # ✅ FIXED: User sessions table with proper columns
        cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='user_sessions' AND xtype='U')
        CREATE TABLE user_sessions (
            session_id NVARCHAR(64) NOT NULL PRIMARY KEY,
            user_id NVARCHAR(128) NOT NULL,
            created_at DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
            last_accessed DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
            expires_at DATETIME2 NOT NULL DEFAULT DATEADD(HOUR, 24, SYSDATETIME()),
            ip NVARCHAR(64) NULL,
            user_agent NVARCHAR(512) NULL,
            is_active BIT NOT NULL DEFAULT 1
        )
        """)
        
        # Uploaded files table - NEW TABLE for file storage
        cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='uploaded_files' AND xtype='U')
        CREATE TABLE uploaded_files (
            id INT IDENTITY PRIMARY KEY,
            upload_id NVARCHAR(64) NOT NULL UNIQUE,
            user_id NVARCHAR(128) NOT NULL,
            filename NVARCHAR(255) NOT NULL,
            file_size BIGINT NOT NULL,
            file_data VARBINARY(MAX) NOT NULL,
            file_type NVARCHAR(50) NOT NULL,
            uploaded_at DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
            expires_at DATETIME2 NOT NULL DEFAULT DATEADD(DAY, 7, SYSDATETIME()),
            is_active BIT NOT NULL DEFAULT 1
        )
        """)
        
        conn.commit()
    except Exception as e:
        print(f"Database setup error: {e}")
    finally:
        conn.close()
# Add these functions to your database functions section

def check_usage_limit(user_id: str) -> bool:
    """Check if user has reached daily usage limit"""
    conn = get_db_conn()
    if not conn:
        # Fallback to in-memory storage
        today = date.today().isoformat()
        user_today_usage = user_usage.get(user_id, {}).get(today, 0)
        return user_today_usage < FREE_REPORTS_PER_DAY
        
    try:
        cursor = conn.cursor()
        today = date.today()
        
        # Check if user exists in usage table
        cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='user_usage' AND xtype='U')
        CREATE TABLE user_usage (
            id INT IDENTITY PRIMARY KEY,
            user_id NVARCHAR(128) NOT NULL,
            usage_date DATE NOT NULL,
            report_count INT NOT NULL DEFAULT 0,
            created_at DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
            UNIQUE (user_id, usage_date)
        )
        """)
        
        # Get today's usage
        cursor.execute(
            "SELECT report_count FROM user_usage WHERE user_id = ? AND usage_date = ?",
            (user_id, today)
        )
        row = cursor.fetchone()
        
        if row:
            return row[0] < FREE_REPORTS_PER_DAY
        else:
            # No usage today, so within limit
            return True
            
    except Exception as e:
        print(f"Usage check error: {e}")
        return True
    finally:
        conn.close()

def increment_usage_count(user_id: str) -> bool:
    """Increment user's daily usage count"""
    conn = get_db_conn()
    if not conn:
        # Fallback to in-memory storage
        today = date.today().isoformat()
        if user_id not in user_usage:
            user_usage[user_id] = {}
        user_usage[user_id][today] = user_usage[user_id].get(today, 0) + 1
        return True
        
    try:
        cursor = conn.cursor()
        today = date.today()
        
        # Insert or update usage count
        cursor.execute("""
        MERGE user_usage AS target
        USING (SELECT ? AS user_id, ? AS usage_date) AS source
        ON target.user_id = source.user_id AND target.usage_date = source.usage_date
        WHEN MATCHED THEN
            UPDATE SET report_count = report_count + 1
        WHEN NOT MATCHED THEN
            INSERT (user_id, usage_date, report_count) VALUES (?, ?, 1);
        """, (user_id, today, user_id, today))
        
        conn.commit()
        return True
    except Exception as e:
        print(f"Increment usage error: {e}")
        return False
    finally:
        conn.close()
        
def get_usage_stats(user_id: str) -> Dict[str, Any]:
    """Get user's current usage statistics"""
    conn = get_db_conn()
    if not conn:
        # Fallback to in-memory storage
        today = date.today().isoformat()
        today_usage = user_usage.get(user_id, {}).get(today, 0)
        return {
            "today_usage": today_usage,
            "daily_limit": FREE_REPORTS_PER_DAY,
            "remaining": FREE_REPORTS_PER_DAY - today_usage
        }
        
    try:
        cursor = conn.cursor()
        today = date.today()
        
        # First ensure the table exists
        cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='user_usage' AND xtype='U')
        CREATE TABLE user_usage (
            id INT IDENTITY PRIMARY KEY,
            user_id NVARCHAR(128) NOT NULL,
            usage_date DATE NOT NULL,
            report_count INT NOT NULL DEFAULT 0,
            created_at DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
            UNIQUE (user_id, usage_date)
        )
        """)
        
        # Get today's usage
        cursor.execute(
            "SELECT report_count FROM user_usage WHERE user_id = ? AND usage_date = ?",
            (user_id, today)
        )
        row = cursor.fetchone()
        
        today_usage = row[0] if row else 0
        
        return {
            "today_usage": today_usage,
            "daily_limit": FREE_REPORTS_PER_DAY,
            "remaining": FREE_REPORTS_PER_DAY - today_usage
        }
    except Exception as e:
        print(f"Get usage stats error: {e}")
        return {
            "today_usage": 0,
            "daily_limit": FREE_REPORTS_PER_DAY,
            "remaining": FREE_REPORTS_PER_DAY
        }
    finally:
        conn.close()
        
def user_by_email(email: str) -> Dict[str, Any] | None:
    """Get user by email from database - UPDATED with google_id"""
    conn = get_db_conn()
    if not conn:
        return users_db.get(email)
        
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, email, full_name, password_hash, google_id, created_at, last_login_at FROM users WHERE email = ?",
            (email,)
        )
        row = cursor.fetchone()
        if row:
            return {
                'id': row[0],
                'email': row[1],
                'full_name': row[2],
                'password_hash': row[3],
                'google_id': row[4],  # ADDED
                'created_at': row[5],
                'last_login_at': row[6]
            }
        return None
    except Exception as e:
        print(f"Database error: {e}")
        return users_db.get(email)
    finally:
        conn.close()

def user_by_google_id(google_id: str) -> Dict[str, Any] | None:
    """Get user by Google ID from database - NEW FUNCTION"""
    conn = get_db_conn()
    if not conn:
        # Check in-memory storage
        for user in users_db.values():
            if user.get('google_id') == google_id:
                return user
        return None
        
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, email, full_name, password_hash, google_id, created_at, last_login_at FROM users WHERE google_id = ?",
            (google_id,)
        )
        row = cursor.fetchone()
        if row:
            return {
                'id': row[0],
                'email': row[1],
                'full_name': row[2],
                'password_hash': row[3],
                'google_id': row[4],
                'created_at': row[5],
                'last_login_at': row[6]
            }
        return None
    except Exception as e:
        print(f"Database error: {e}")
        return None
    finally:
        conn.close()

def insert_user(full_name: Optional[str], email: str, password_hash: str) -> bool:
    """Insert new user into database with local time"""
    conn = get_db_conn()
    if not conn:
        # Fallback to in-memory storage
        if email in users_db:
            return False
        users_db[email] = {
            'email': email,
            'full_name': full_name,
            'password_hash': password_hash,
            'google_id': None,
            'created_at': datetime.now().isoformat()
        }
        return True
        
    try:
        cursor = conn.cursor()
        # Use explicit local time instead of relying on default
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        cursor.execute(
            "INSERT INTO users (full_name, email, password_hash, google_id, created_at) VALUES (?, ?, ?, ?, ?)",
            (full_name, email, password_hash, None, current_time)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"Database insert error: {e}")
        return False
    finally:
        conn.close()

def create_google_user(email: str, name: str, google_id: str) -> bool:
    """Create a user for Google OAuth with local time"""
    try:
        # Try database first
        conn = get_db_conn()
        if conn:
            cursor = conn.cursor()
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            cursor.execute(
                "INSERT INTO users (email, full_name, google_id, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                (email, name, google_id, None, current_time)  # NULL password for Google users
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
    """Update existing user with Google ID - NEW FUNCTION"""
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
def cleanup_expired_sessions() -> int:
    """Clean up expired sessions and deactivate duplicates"""
    conn = get_db_conn()
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    if not conn:
        # Clean in-memory storage
        expired_count = 0
        for session_id, session_data in list(user_sessions.items()):
            if isinstance(session_data, dict):
                if datetime.now() - session_data.get('created_at', datetime.now()) >= timedelta(hours=24):
                    del user_sessions[session_id]
                    expired_count += 1
        return expired_count
        
    try:
        cursor = conn.cursor()
        
        # First, deactivate duplicate active sessions for same user
        cursor.execute("""
            WITH RankedSessions AS (
                SELECT session_id, user_id, last_accessed,
                       ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY last_accessed DESC) as rn
                FROM user_sessions 
                WHERE is_active = 1 AND expires_at > ?
            )
            UPDATE user_sessions 
            SET is_active = 0 
            WHERE session_id IN (
                SELECT session_id FROM RankedSessions WHERE rn > 1
            )
        """, (current_time,))
        duplicate_count = cursor.rowcount
        
        # Then delete truly expired sessions
        cursor.execute("DELETE FROM user_sessions WHERE expires_at <= ?", (current_time,))
        expired_count = cursor.rowcount
        
        conn.commit()
        print(f"🧹 Cleaned up {expired_count} expired sessions and {duplicate_count} duplicates")
        return expired_count + duplicate_count
    except Exception as e:
        print(f"Session cleanup error: {e}")
        return 0
    finally:
        if conn:
            conn.close()
        
def ensure_session(user_id: str, session_id: Optional[str], ip: Optional[str], ua: Optional[str]) -> str:
    """FIXED: Ensure session exists with proper duplicate prevention"""
    conn = get_db_conn()
    
    # Get current local time
    current_time = datetime.now()
    expires_time = current_time + timedelta(hours=24)
    
    # Format for SQL Server
    current_time_str = current_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    expires_time_str = expires_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    if not conn:
        # Fallback to in-memory storage
        if session_id and session_id in user_sessions:
            user_sessions[session_id]['last_accessed'] = current_time
            return session_id
        new_sid = str(uuid.uuid4())
        user_sessions[new_sid] = {
            'user_id': user_id,
            'created_at': current_time,
            'last_accessed': current_time
        }
        return new_sid
        
    try:
        cursor = conn.cursor()
        
        # 🚨 FIX: Check if session exists and is valid - PROPERLY
        if session_id:
            cursor.execute(
                """SELECT session_id FROM user_sessions 
                   WHERE session_id = ? AND is_active = 1 AND expires_at > ?""",
                (session_id, current_time_str)
            )
            existing_session = cursor.fetchone()
            
            if existing_session:
                # ✅ UPDATE existing session instead of creating new one
                cursor.execute(
                    """UPDATE user_sessions 
                       SET last_accessed = ?, expires_at = ?
                       WHERE session_id = ?""",
                    (current_time_str, expires_time_str, session_id)
                )
                conn.commit()
                conn.close()
             #   print(f"✅ Updated existing session: {session_id}")
                return session_id
        
        # 🚨 FIX: Check for existing active sessions for this user
        cursor.execute(
            """SELECT session_id FROM user_sessions 
               WHERE user_id = ? AND is_active = 1 AND expires_at > ?
               ORDER BY last_accessed DESC""",
            (user_id, current_time_str)
        )
        existing_user_sessions = cursor.fetchall()
        
        # If user has existing active sessions, use the most recent one
        if existing_user_sessions:
            existing_session_id = existing_user_sessions[0][0]
            # Update the existing session
            cursor.execute(
                """UPDATE user_sessions 
                   SET last_accessed = ?, expires_at = ?, ip = ?, user_agent = ?
                   WHERE session_id = ?""",
                (current_time_str, expires_time_str, ip, ua, existing_session_id)
            )
            conn.commit()
            conn.close()
            print(f"✅ Reused existing user session: {existing_session_id}")
            return existing_session_id
        
        # 🚨 ONLY CREATE NEW SESSION if no valid sessions exist
        new_sid = str(uuid.uuid4())
        
        cursor.execute(
            """INSERT INTO user_sessions 
               (session_id, user_id, ip, user_agent, created_at, last_accessed, expires_at, is_active) 
               VALUES (?, ?, ?, ?, ?, ?, ?, 1)""",
            (new_sid, user_id, ip, ua, current_time_str, current_time_str, expires_time_str)
        )
        conn.commit()
        conn.close()
        print(f"✅ Created new session: {new_sid}")
        return new_sid
        
    except Exception as e:
        print(f"❌ Session error: {e}")
        # Fallback to in-memory
        new_sid = str(uuid.uuid4())
        user_sessions[new_sid] = {
            'user_id': user_id,
            'created_at': current_time,
            'last_accessed': current_time
        }
        return new_sid

def resolve_user_from_session(session_id: str) -> Optional[str]:
    """FIXED: Resolve user from session with proper session management"""
    if not session_id:
        return None
        
    conn = get_db_conn()
    if not conn:
        session_data = user_sessions.get(session_id)
        return session_data.get('user_id') if session_data else None
        
    try:
        cursor = conn.cursor()
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        cursor.execute(
            """SELECT user_id FROM user_sessions 
               WHERE session_id = ? AND is_active = 1 AND expires_at > ?""",
            (session_id, current_time)
        )
        row = cursor.fetchone()
        
        if row:
            # ✅ Update session expiry when accessed
            new_expires = (datetime.now() + timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            cursor.execute(
                """UPDATE user_sessions 
                   SET last_accessed = ?, expires_at = ?
                   WHERE session_id = ?""",
                (current_time, new_expires, session_id)
            )
            conn.commit()
            return row[0]
        return None
        
    except Exception as e:
        print(f"❌ Session resolve error: {e}")
        session_data = user_sessions.get(session_id)
        return session_data.get('user_id') if session_data else None
    finally:
        if conn:
            conn.close()
        
        # ---------------------------------------------------------
# ✅ Database Functions - ADD MISSING FUNCTION
# ---------------------------------------------------------

def update_user_last_login(email: str) -> bool:
    """Update user's last login timestamp with local time"""
    conn = get_db_conn()
    if not conn:
        # Fallback to in-memory storage
        if email in users_db:
            users_db[email]['last_login_at'] = datetime.now().isoformat()
        return True
        
    try:
        cursor = conn.cursor()
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        cursor.execute(
            "UPDATE users SET last_login_at = ? WHERE email = ?",
            (current_time, email)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"Update last login error: {e}")
        return False
    finally:
        conn.close()

# ---------------------------------------------------------
# ✅ FILE STORAGE FUNCTIONS - NEW SECTION
# ---------------------------------------------------------


def store_file_in_db(upload_id: str, file_data: bytes, filename: str, user_id: str) -> bool:
    """Store uploaded file in database with local time"""
    conn = get_db_conn()
    if not conn:
        # Fallback to in-memory storage
        uploaded_files[upload_id] = {
            'data': file_data,
            'filename': filename,
            'user_id': user_id,
            'uploaded_at': datetime.now()
        }
        return True
        
    try:
        cursor = conn.cursor()
        
        # Determine file type
        file_type = "csv" if filename.lower().endswith(".csv") else "excel"
        file_size = len(file_data)
        
        # Get current local time
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        expires_time = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        # FIXED: Proper duplicate handling with local time
        cursor.execute("SELECT 1 FROM uploaded_files WHERE upload_id = ?", (upload_id,))
        if cursor.fetchone():
            # Update existing record with local time
            cursor.execute(
                """UPDATE uploaded_files 
                   SET filename = ?, file_size = ?, file_data = ?, file_type = ?, uploaded_at = ?, expires_at = ?, is_active = 1
                   WHERE upload_id = ? AND user_id = ?""",
                (filename, file_size, file_data, file_type, current_time, expires_time, upload_id, user_id)
            )
        else:
            # Insert new record with local time
            cursor.execute(
                """INSERT INTO uploaded_files 
                   (upload_id, user_id, filename, file_size, file_data, file_type, uploaded_at, expires_at) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (upload_id, user_id, filename, file_size, file_data, file_type, current_time, expires_time)
            )
        
        conn.commit()
        return True
    except Exception as e:
        print(f"File storage error: {e}")
        # Fallback to in-memory storage
        uploaded_files[upload_id] = {
            'data': file_data,
            'filename': filename,
            'user_id': user_id,
            'uploaded_at': datetime.now()
        }
        return True
    finally:
        conn.close()

def get_file_from_db(upload_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve uploaded file from database with local time comparison"""
    conn = get_db_conn()
    if not conn:
        # Fallback to in-memory storage
        file_info = uploaded_files.get(upload_id)
        if file_info and file_info['user_id'] == user_id:
            return file_info
        return None
        
    try:
        cursor = conn.cursor()
        # Use local time for comparison
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        cursor.execute(
            """SELECT upload_id, user_id, filename, file_size, file_data, file_type, uploaded_at 
               FROM uploaded_files 
               WHERE upload_id = ? AND user_id = ? AND is_active = 1 AND expires_at > ?""",
            (upload_id, user_id, current_time)
        )
        row = cursor.fetchone()
        if row:
            return {
                'upload_id': row[0],
                'user_id': row[1],
                'filename': row[2],
                'file_size': row[3],
                'data': row[4],  # This is the actual file data
                'file_type': row[5],
                'uploaded_at': row[6]
            }
        return None
    except Exception as e:
        print(f"File retrieval error: {e}")
        # Fallback to in-memory storage
        file_info = uploaded_files.get(upload_id)
        if file_info and file_info['user_id'] == user_id:
            return file_info
        return None
    finally:
        conn.close()

def cleanup_expired_files() -> int:
    """Clean up expired files using local time"""
    conn = get_db_conn()
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    if not conn:
        # Clean in-memory storage
        current_datetime = datetime.now()
        expired_count = 0
        for upload_id, file_info in list(uploaded_files.items()):
            # Files expire after 7 days in memory
            if file_info['uploaded_at'] + timedelta(days=7) < current_datetime:
                del uploaded_files[upload_id]
                expired_count += 1
        return expired_count
        
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM uploaded_files WHERE expires_at <= ? OR is_active = 0", (current_time,))
        deleted_count = cursor.rowcount
        conn.commit()
        return deleted_count
    except Exception as e:
        print(f"File cleanup error: {e}")
        return 0
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
# ✅ Enhanced AI Service (UNCHANGED)
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
           
    def recommend_visualizations(self, df: pd.DataFrame, business_goal: Optional[str] = None) -> Dict[str, Any]:
        """AI-powered visualization recommendations"""
        if not self.model:
            return self._fallback_visualizations(df)
        
        # Sample data for AI analysis
        sample_data = df.head(20).to_dict(orient='records')
        numeric_cols = df.select_dtypes(include="number").columns.tolist()
        categorical_cols = df.select_dtypes(include=["object", "category", "bool"]).columns.tolist()
        date_cols = df.select_dtypes(include=["datetime64", "datetime64[ns]"]).columns.tolist()
        
        payload = {
            "dataset_info": {
                "rows": len(df),
                "columns": len(df.columns),
                "numeric_columns": numeric_cols,
                "categorical_columns": categorical_cols,
                "date_columns": date_cols,
                "business_goal": business_goal or "general analysis"
            },
            "sample_data": sample_data,
            "column_stats": {
                col: {
                    "dtype": str(df[col].dtype),
                    "unique_values": df[col].nunique() if df[col].dtype == 'object' else None,
                    "null_count": df[col].isnull().sum(),
                    "sample_values": df[col].dropna().head(5).tolist() if df[col].dtype == 'object' else None
                } for col in df.columns
            }
        }
        
        prompt = f"""
        **ROLE**: You are a Chief Data Visualization Officer with 15+ years experience in business intelligence, data storytelling,
        and dashboard design for Fortune 500 companies. Analyze this dataset and recommend the most appropriate visualizations.
        
        BUSINESS CONTEXT: {business_goal or "General data analysis"}
        
        DATASET OVERVIEW:
        - {len(df)} rows, {len(df.columns)} columns
        - Numeric columns: {numeric_cols}
        - Categorical columns: {categorical_cols}
        - Date columns: {date_cols}
        
        Recommend 3-5 visualization types that would provide the most insights. For each visualization, provide:
        1. Chart type
        2. Data columns to use
        3. Reason why this visualization is appropriate
        4. Specific chart configuration
        
        Return your analysis as JSON with this structure:
        {{
            "recommended_visualizations": [
                {{
                    "chart_type": "line|bar|scatter|histogram|pie|heatmap|box",
                    "title": "Descriptive title",
                    "description": "Why this visualization is useful",
                    "data_columns": ["col1", "col2"],
                    "x_axis": "column_name",
                    "y_axis": "column_name",
                    "color_by": "column_name", // optional
                    "filters": {{ // optional
                        "column": "column_name",
                        "values": ["value1", "value2"]
                    }},
                    "insights": ["Key insight 1", "Key insight 2"]
                }}
            ],
            "primary_insights": ["Overall insight 1", "Overall insight 2"],
            "data_story": "Brief narrative about what story the data tells"
        }}
        
        DATA PAYLOAD:
        {json.dumps(payload, default=self._json_default, indent=2)}
        """
        
        try:
            response = self.model.generate_content(
                prompt,
                generation_config={
                    "max_output_tokens": 2048,
                    "temperature": 0.2
                }
            )
            
            if response.text:
                text = response.text.strip()
                if "```json" in text:
                    text = text.split("```json")[1].split("```")[0].strip()
                elif "```" in text:
                    text = text.split("```")[1].strip() if len(text.split("```")) > 2 else text
                
                visualizations = json.loads(text)
                return self._generate_chart_data(df, visualizations)
                
        except Exception as e:
            print(f"AI visualization error: {e}")
        
        return self._fallback_visualizations(df)
    
    def _generate_chart_data(self, df: pd.DataFrame, visualizations: Dict[str, Any]) -> Dict[str, Any]:
        """Generate actual chart data based on AI recommendations"""
        charts = {}
        recommended_viz = visualizations.get("recommended_visualizations", [])
        
        for i, viz in enumerate(recommended_viz[:4]):  # Limit to 4 charts
            chart_type = viz.get("chart_type", "bar")
            chart_id = f"chart_{i+1}"
            
            try:
                if chart_type == "line":
                    charts[chart_id] = self._create_line_chart(df, viz)
                elif chart_type == "bar":
                    charts[chart_id] = self._create_bar_chart(df, viz)
                elif chart_type == "pie":
                    charts[chart_id] = self._create_pie_chart(df, viz)
                elif chart_type == "scatter":
                    charts[chart_id] = self._create_scatter_chart(df, viz)
                elif chart_type == "histogram":
                    charts[chart_id] = self._create_histogram(df, viz)
                else:
                    charts[chart_id] = self._create_bar_chart(df, viz)  # Default fallback
                    
                # Add AI metadata
                charts[chart_id]["ai_metadata"] = {
                    "title": viz.get("title", f"Chart {i+1}"),
                    "description": viz.get("description", ""),
                    "insights": viz.get("insights", []),
                    "recommended_by": "AI"
                }
                
            except Exception as e:
                print(f"Error generating {chart_type} chart: {e}")
                continue
        
        # Ensure we have at least one chart
        if not charts:
            charts = self._fallback_visualizations(df)
            
        return {
            "charts": charts,
            "primary_insights": visualizations.get("primary_insights", []),
            "data_story": visualizations.get("data_story", ""),
            "recommendations": recommended_viz
        }
    
    def _create_line_chart(self, df: pd.DataFrame, viz: Dict[str, Any]) -> Dict[str, Any]:
        """Create line chart data"""
        x_col = viz.get("x_axis")
        y_col = viz.get("y_axis")
        
        if not x_col or not y_col or x_col not in df.columns or y_col not in df.columns:
            return self._create_fallback_chart(df, "line")
        
        # Try to sort by x if it's numeric or date
        chart_data = df[[x_col, y_col]].dropna()
        if pd.api.types.is_datetime64_any_dtype(chart_data[x_col]):
         chart_data = chart_data.copy()
        chart_data[x_col] = chart_data[x_col].dt.strftime('%B-%d-%Y')
        if pd.api.types.is_numeric_dtype(chart_data[x_col]) or pd.api.types.is_datetime64_any_dtype(chart_data[x_col]):
            chart_data = chart_data.sort_values(x_col)
        
        return {
            "type": "line",
            "data": chart_data.head(100).to_dict(orient='records'),  # Limit data points
            "config": {
                "x_axis": x_col,
                "y_axis": y_col,
                "color_by": viz.get("color_by")
            }
        }
    
    def _create_bar_chart(self, df: pd.DataFrame, viz: Dict[str, Any]) -> Dict[str, Any]:
        """Create bar chart data"""
        x_col = viz.get("x_axis")
        y_col = viz.get("y_axis")
        
        if not x_col or x_col not in df.columns:
            return self._create_fallback_chart(df, "bar")
        
       
    
        if y_col and y_col in df.columns:
            # Grouped bar chart
            chart_data = df.groupby(x_col)[y_col].mean().reset_index()
        else:
            # Count chart
            chart_data = df[x_col].value_counts().reset_index()
            chart_data.columns = [x_col, 'count']
            y_col = 'count'
        
        return {
            "type": "bar",
            "data": chart_data.head(20).to_dict(orient='records'),  # Limit categories
            "config": {
                "x_axis": x_col,
                "y_axis": y_col or 'count'
            }
        }
    
    def _create_pie_chart(self, df: pd.DataFrame, viz: Dict[str, Any]) -> Dict[str, Any]:
        """Create pie chart data"""
        category_col = viz.get("x_axis") or viz.get("color_by")
        
        if not category_col or category_col not in df.columns:
            return self._create_fallback_chart(df, "pie")
        
        chart_data = df[category_col].value_counts().head(8).reset_index()  # Top 8 categories
        chart_data.columns = ['name', 'value']
        
        return {
            "type": "pie",
            "data": chart_data.to_dict(orient='records'),
            "config": {
                "category": category_col
            }
        }
    
    def _create_scatter_chart(self, df: pd.DataFrame, viz: Dict[str, Any]) -> Dict[str, Any]:
        """Create scatter plot data"""
        x_col = viz.get("x_axis")
        y_col = viz.get("y_axis")
        color_col = viz.get("color_by")
        
        if not x_col or not y_col or x_col not in df.columns or y_col not in df.columns:
            return self._create_fallback_chart(df, "scatter")
        
        columns = [x_col, y_col]
        if color_col and color_col in df.columns:
            columns.append(color_col)
            
        chart_data = df[columns].dropna().head(100)  # Limit data points
      
        return {
            "type": "scatter",
            "data": chart_data.to_dict(orient='records'),
            "config": {
                "x_axis": x_col,
                "y_axis": y_col,
                "color_by": color_col
            }
        }
    
    def _create_histogram(self, df: pd.DataFrame, viz: Dict[str, Any]) -> Dict[str, Any]:
        """Create histogram data"""
        numeric_col = viz.get("x_axis") or viz.get("y_axis")
        
        if not numeric_col or numeric_col not in df.columns or not pd.api.types.is_numeric_dtype(df[numeric_col]):
            return self._create_fallback_chart(df, "histogram")
        
        # Create bins for histogram
        series = df[numeric_col].dropna()
        hist, bins = np.histogram(series, bins=min(20, len(series.unique())))
        
        chart_data = []
        for i in range(len(hist)):
            chart_data.append({
                'bin_start': bins[i],
                'bin_end': bins[i+1],
                'count': int(hist[i]),
                'range': f"{bins[i]:.1f}-{bins[i+1]:.1f}"
            })
        
        return {
            "type": "bar",  # Use bar for histogram
            "data": chart_data,
            "config": {
                "x_axis": "range",
                "y_axis": "count",
                "is_histogram": True
            }
        }
    
    def _create_fallback_chart(self, df: pd.DataFrame, chart_type: str) -> Dict[str, Any]:
        """Create fallback chart when AI recommendations fail"""
        numeric_cols = df.select_dtypes(include="number").columns.tolist()
        categorical_cols = df.select_dtypes(include=["object", "category"]).columns.tolist()
        
        if chart_type == "line" and numeric_cols:
            # Simple line chart with first numeric column
            series = df[numeric_cols[0]].dropna().head(50)
            data = [{"x": i, "y": float(val)} for i, val in enumerate(series)]
            return {"type": "line", "data": data, "config": {"x_axis": "index", "y_axis": numeric_cols[0]}}
        
        elif chart_type == "bar" and categorical_cols:
            # Simple bar chart with first categorical column
            counts = df[categorical_cols[0]].value_counts().head(10).reset_index()
            counts.columns = ['name', 'value']
            return {"type": "bar", "data": counts.to_dict('records'), "config": {"x_axis": "name", "y_axis": "value"}}
        
        elif chart_type == "pie" and categorical_cols:
            # Simple pie chart
            counts = df[categorical_cols[0]].value_counts().head(6).reset_index()
            counts.columns = ['name', 'value']
            return {"type": "pie", "data": counts.to_dict('records'), "config": {"category": categorical_cols[0]}}
        
        else:
            # Ultimate fallback
            return {
                "type": "bar",
                "data": [{"name": "A", "value": 30}, {"name": "B", "value": 45}, {"name": "C", "value": 25}],
                "config": {"x_axis": "name", "y_axis": "value"}
            }
    
    def _fallback_visualizations(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Generate basic visualizations when AI is unavailable"""
        charts = {}
        
        # Try to create 2-3 basic charts
        numeric_cols = df.select_dtypes(include="number").columns.tolist()
        categorical_cols = df.select_dtypes(include=["object", "category"]).columns.tolist()
        
        # Chart 1: Line chart with first numeric column
        if numeric_cols:
            series = df[numeric_cols[0]].dropna().head(50)
            charts["chart_1"] = {
                "type": "line",
                "data": [{"x": i, "y": float(val)} for i, val in enumerate(series)],
                "config": {"x_axis": "index", "y_axis": numeric_cols[0]},
                "ai_metadata": {
                    "title": f"Trend of {numeric_cols[0]}",
                    "description": "Shows the progression of values over the dataset",
                    "insights": ["Visualizes the distribution and pattern of numerical data"],
                    "recommended_by": "fallback"
                }
            }
        
        # Chart 2: Bar chart with first categorical column
        if categorical_cols:
            counts = df[categorical_cols[0]].value_counts().head(8).reset_index()
            counts.columns = ['name', 'value']
            charts["chart_2"] = {
                "type": "bar",
                "data": counts.to_dict('records'),
                "config": {"x_axis": "name", "y_axis": "value"},
                "ai_metadata": {
                    "title": f"Distribution of {categorical_cols[0]}",
                    "description": "Shows frequency of different categories",
                    "insights": ["Reveals the most common categories in your data"],
                    "recommended_by": "fallback"
                }
            }
        
        # Chart 3: Pie chart if we have categorical data
        if categorical_cols and len(charts) < 3:
            counts = df[categorical_cols[0]].value_counts().head(6).reset_index()
            counts.columns = ['name', 'value']
            charts["chart_3"] = {
                "type": "pie",
                "data": counts.to_dict('records'),
                "config": {"category": categorical_cols[0]},
                "ai_metadata": {
                    "title": f"Composition of {categorical_cols[0]}",
                    "description": "Shows proportional distribution of categories",
                    "insights": ["Helps understand the relative size of different segments"],
                    "recommended_by": "fallback"
                }
            }
        
        return {
            "charts": charts,
            "primary_insights": ["Basic data patterns and distributions identified"],
            "data_story": "The dataset shows various patterns across different dimensions",
            "recommendations": []
        }

# ---------------------------------------------------------
# ✅ Data Analysis Functions
# ---------------------------------------------------------
def try_parse_dates_inplace(df: pd.DataFrame, max_cols: int = 3, min_ratio: float = 0.6):
    """Try to parse date columns automatically - FIXED VERSION"""
    candidates = [c for c in df.columns if any(tok in c.lower() for tok in ("date", "time", "timestamp", "day", "month", "year"))]
    tried = 0
    
    for c in candidates:
        if tried >= max_cols: 
            break
            
        s = df[c]
        # Skip if already datetime or not string-like
        if pd.api.types.is_datetime64_any_dtype(s):
            continue
            
        if not (pd.api.types.is_string_dtype(s) or pd.api.types.is_object_dtype(s)):
            continue
            
        # Try multiple date formats to avoid the warning
        try:
            parsed = pd.to_datetime(s, errors="coerce", utc=False, format='mixed')
            non_null = s.notna().sum()
            
            if non_null > 0 and parsed.notna().sum() >= min_ratio * non_null:
                df[c] = parsed
                tried += 1
                print(f"✅ Successfully parsed date column: {c}")
        except Exception as e:
            print(f"⚠️ Could not parse column {c} as date: {e}")
            continue

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
    """Count IQR outliers in a numeric column - FIXED VERSION"""
    try:
        # Convert to numeric, handling errors
        col = pd.to_numeric(col, errors="coerce").dropna()
        if col.empty: 
            return 0
        
        # Calculate IQR
        q1, q3 = col.quantile(0.25), col.quantile(0.75)
        iqr = q3 - q1
        
        # Check for valid IQR
        if not np.isfinite(iqr) or iqr == 0: 
            return 0
        
        # Calculate bounds and count outliers
        lower, upper = q1 - 1.5*iqr, q3 + 1.5*iqr
        outlier_mask = (col < lower) | (col > upper)
        
        # Convert to int properly
        return int(outlier_mask.sum())
        
    except Exception as e:
        print(f"Outlier calculation error for column: {e}")
        return 0

# ---------------------------------------------------------
# ✅ Routes - UPDATED FOR DATABASE FILE STORAGE
# ---------------------------------------------------------
@app.get("/api/debug/users")
async def debug_users():
    """Debug endpoint to see all users in database"""
    conn = get_db_conn()
    if not conn:
        return {"storage": "in_memory", "users": users_db}
    
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, full_name, created_at FROM users")
        rows = cursor.fetchall()
        users = []
        for row in rows:
            users.append({
                'id': row[0],
                'email': row[1],
                'full_name': row[2],
                'created_at': row[3].isoformat() if row[3] else None
            })
        return {"storage": "database", "users": users}
    except Exception as e:
        return {"error": str(e), "storage": "in_memory", "users": users_db}
    finally:
        conn.close()
        
@app.get("/api/debug/db-status")
async def debug_db_status():
    """Check database connection status"""
    try:
        conn = get_db_conn()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT @@version as version")
            version = cursor.fetchone()
            cursor.execute("SELECT COUNT(*) as user_count FROM users")
            count = cursor.fetchone()
            cursor.execute("SELECT COUNT(*) as file_count FROM uploaded_files")
            file_count = cursor.fetchone()
            conn.close()
            return {
                "status": "connected",
                "database": "SQL Server",
                "version": version[0] if version else "unknown",
                "user_count": count[0] if count else 0,
                "file_count": file_count[0] if file_count else 0
            }
        else:
            return {"status": "disconnected", "storage": "in_memory", "user_count": len(users_db), "file_count": len(uploaded_files)}
    except Exception as e:
        return {"status": "error", "error": str(e)}
    
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

    # Retrieve uploaded file FROM DATABASE
    file_info = get_file_from_db(request.upload_id, user_id)
    if not file_info:
        raise HTTPException(status_code=404, detail="File not found or access denied")

    try:
        # Parse the file
        file_data = file_info['data']  # This now comes from database
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
    """Comprehensive data analysis - UPDATED FOR DATABASE FILE STORAGE"""
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

  # ✅ CHECK USAGE LIMITS
    if not check_usage_limit(user_id):
        return JSONResponse(
            status_code=402,
            content={
                "error": "USAGE_LIMIT_EXCEEDED",
                "message": "You've reached your daily report limit",
                "upgrade_url": "/pricing"
            }
        )
    # Check file size
    raw = await file.read()
    if len(raw) > 10 * 1024 * 1024:  # 10MB limit
        raise HTTPException(status_code=400, detail="File too large (max 10MB)")

    
    # Generate UNIQUE upload ID with timestamp and random component
    timestamp = int(datetime.now().timestamp())
    random_component = str(uuid.uuid4())[:8]
    file_hash = hashlib.sha256(raw).hexdigest()[:16]
    upload_id = f"{timestamp}_{random_component}_{file_hash}"
    
     # STORE FILE IN DATABASE with enhanced logging
    print(f"📁 Storing file: {file.filename}, size: {len(raw)} bytes, upload_id: {upload_id}")
    store_success = store_file_in_db(upload_id, raw, file.filename, user_id)
    
    if not store_success:
        raise HTTPException(status_code=500, detail="Failed to store file")

    # ✅ INCREMENT USAGE COUNT
    increment_usage_count(user_id)


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

    # Calculate KPIs
    numeric_df = df.select_dtypes(include="number").apply(pd.to_numeric, errors="coerce")
    total_cells = max(1, int(df.shape[0] * df.shape[1]))
    missing_total = int(df.isna().sum().sum())
    missing_pct = round(missing_total / total_cells * 100, 2)
    duplicates = int(df.duplicated().sum())

    outlier_counts = {c: _iqr_outliers(numeric_df[c]) for c in numeric_df.columns} if not numeric_df.empty else {}
    total_outliers = int(sum(outlier_counts.values()))
    rows_per_day = None
    date_cols = df.select_dtypes(include=['datetime64']).columns.tolist()
    if date_cols:
      try:
        # Use first date column
        date_col = date_cols[0]
        # Count unique days and calculate average rows per day
        unique_days = df[date_col].dt.normalize().nunique()
        if unique_days > 0:
            rows_per_day = round(len(df) / unique_days, 1)
      except Exception as e:
        print(f"Rows per day calculation error: {e}")
        
    kpis = {
        "total_rows": int(df.shape[0]),
        "total_columns": int(df.shape[1]),
        "missing_pct": _safe_float(missing_pct),
        "duplicate_rows": duplicates,
        "outliers_total": total_outliers,
        "rows_per_day": rows_per_day # ✅ ADD THIS LINE

    }

    # Generate AI insights and visualizations
    ai_service = AIService()
    detailed_summary = ai_service.generate_detailed_summary(df, None, "executive")
    visualizations = ai_service.recommend_visualizations(df, None)

    return {
        "profiling": profiling,
        "kpis": kpis,
        "charts": visualizations.get("charts", {}),  # ✅ ADD THIS LINE
        "visualizations_metadata": {  # ✅ ADD THIS SECTION
            "primary_insights": visualizations.get("primary_insights", []),
            "data_story": visualizations.get("data_story", ""),
            "recommendations": visualizations.get("recommendations", [])
        },
        "insights": {
            "summary": "AI-powered analysis complete",
            "key_insights": visualizations.get("primary_insights", []),
            "recommendations": ["Review AI-generated visualizations for insights"]
        },
        "detailed_summary": detailed_summary,
        "session_id": session_id,
        "upload_id": upload_id,
        "file": {
            "name": file.filename,
            "size_bytes": len(raw),
        },
    }

@app.post("/api/ai-visualizations")
async def ai_visualizations(
    request: AISummaryRequest,  # Reuse the same request model
    response: Response,
    auth: dict = Depends(get_current_auth),
):
    
    """Generate AI-powered visualizations for uploaded file"""
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

    # Retrieve uploaded file FROM DATABASE
    file_info = get_file_from_db(request.upload_id, user_id)
    if not file_info:
        raise HTTPException(status_code=404, detail="File not found or access denied")

    try:
        # Parse the file
        file_data = file_info['data']  # This now comes from database
        filename = file_info['filename']
        
        if filename.lower().endswith(".csv"):
            df = pd.read_csv(BytesIO(file_data))
        else:
            df = pd.read_excel(BytesIO(file_data))

        # Generate AI-powered visualizations
        ai_service = AIService()
        visualizations = ai_service.recommend_visualizations(df, request.business_goal)
        
        return {
            **visualizations,
            "session_id": session_id,
            "upload_id": request.upload_id
        }
        
    except Exception as e:
        return JSONResponse(
            status_code=400, 
            content={"error": "VISUALIZATION_FAILED", "detail": str(e)}
        )
        
@app.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    """ENHANCED: User logout with session invalidation"""
    sid = request.cookies.get("dp_session_id")
    if sid:
        # Invalidate session in database
        conn = get_db_conn()
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM user_sessions WHERE session_id = ?", (sid,))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"Session deletion error: {e}")
        
        # Remove from in-memory storage
        if sid in user_sessions:
            del user_sessions[sid]
    
    # Clear cookie
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

@app.post("/api/debug-analysis")
async def debug_analysis(
    request: Request,
    response: Response,
    file: UploadFile = File(...),
    auth: dict = Depends(get_current_auth),
):
    """Debug endpoint to see the complete analysis structure"""
    user_id = auth["user_id"]
    session_id = auth["session_id"]

    # Check file size
    raw = await file.read()
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large")

    # Parse file
    try:
        if (file.filename or "").lower().endswith(".csv"):
            df = pd.read_csv(BytesIO(raw))
        else:
            df = pd.read_excel(BytesIO(raw))
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": "INVALID_FILE", "detail": str(e)})

    # Generate AI analysis
    ai_service = AIService()
    detailed_summary = ai_service.generate_detailed_summary(df, None, "executive")

    # Return debug information
    return {
        "debug_info": {
            "detailed_summary_keys": list(detailed_summary.keys()),
            "has_executive_overview": "executive_overview" in detailed_summary,
            "has_key_trends": "key_trends" in detailed_summary and len(detailed_summary["key_trends"]) > 0,
            "has_quick_wins": "action_items_quick_wins" in detailed_summary and len(detailed_summary["action_items_quick_wins"]) > 0,
            "has_business_implications": "business_implications" in detailed_summary,
            "has_recommendations": "recommendations" in detailed_summary,
            "has_risk_alerts": "risk_alerts" in detailed_summary,
            "has_predictive_insights": "predictive_insights" in detailed_summary,
            "has_industry_comparison": "industry_comparison" in detailed_summary,
        },
        "complete_detailed_summary": detailed_summary,
        "sample_data_structure": {
            "executive_overview_length": len(detailed_summary.get("executive_overview", "")),
            "key_trends_count": len(detailed_summary.get("key_trends", [])),
            "quick_wins_count": len(detailed_summary.get("action_items_quick_wins", [])),
            "business_implications_count": len(detailed_summary.get("business_implications", [])),
            "risk_alerts_count": len(detailed_summary.get("risk_alerts", [])),
            "predictive_insights_count": len(detailed_summary.get("predictive_insights", [])),
        }
    }

# ---------------------------------------------------------
# ✅ GOOGLE OAUTH ROUTES - COMPLETE FIXED VERSION
# ---------------------------------------------------------
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
    """Handle Google OAuth callback with local time"""
    try:
        if not code:
            return RedirectResponse(f"{FRONTEND_URL}/login?error=no_code")
        
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
            token_response = await client.post(token_url, data=data)
            tokens = token_response.json()
            
            if 'error' in tokens:
                print(f"Token error: {tokens}")
                return RedirectResponse(f"{FRONTEND_URL}/login?error=auth_failed")
            
            # Get user info from Google
            userinfo_response = await client.get(
                'https://www.googleapis.com/oauth2/v3/userinfo',
                headers={'Authorization': f"Bearer {tokens['access_token']}"}
            )
            user_info = userinfo_response.json()
            
            if 'error' in user_info:
                print(f"Userinfo error: {user_info}")
                return RedirectResponse(f"{FRONTEND_URL}/login?error=user_info_failed")
        
        # Extract user data
        email = user_info['email']
        name = user_info.get('name', 'User')
        google_id = user_info['sub']
        
        print(f"Google user: {email}, {name}, {google_id}")
        
        # Check if user exists by Google ID first
        existing_user = user_by_google_id(google_id)
        
        if not existing_user:
            # Check if user exists by email (merge accounts)
            existing_user = user_by_email(email)
            if existing_user:
                # Update existing user with Google ID
                update_user_google_id(email, google_id)
            else:
                # Create new Google user
                if not create_google_user(email, name, google_id):
                    return RedirectResponse(f"{FRONTEND_URL}/login?error=user_creation_failed")
                existing_user = user_by_google_id(google_id)
        
        user_id = existing_user['email']
        
        # Get IP and User Agent
        xff = request.headers.get("X-Forwarded-For")
        client_ip = xff.split(",")[0].strip() if xff else request.client.host
        user_agent = request.headers.get("User-Agent", "")[:512]
        
        # Update last login with local time
        update_user_last_login(user_id)
        
        # Create session with local time
        session_id = ensure_session(user_id, None, client_ip, user_agent)
        
        # Set cookies
        response.set_cookie(
            key="dp_session_id",
            value=session_id,
            httponly=True,
            secure=True,
            samesite="none",
            max_age=30 * 24 * 60 * 60,  # 30 days
            path="/",
        )
        
        print(f"✅ Google OAuth successful for {email}, session: {session_id}")
        
        # Redirect to analyze page
        return RedirectResponse(f"{FRONTEND_URL}/analyze")
        
    except Exception as e:
        print(f"Google OAuth error: {e}")
        return RedirectResponse(f"{FRONTEND_URL}/login?error=auth_failed")
    
@app.get("/api/usage/stats")
async def get_usage_stats_endpoint(auth: dict = Depends(get_current_auth)):
    """Get current user's usage statistics"""
    try:
        user_id = auth["user_id"]
        
        # Get usage stats with proper error handling
        stats = get_usage_stats(user_id)
        
        # Ensure all required fields are present
        return {
            "today_usage": stats.get("today_usage", 0),
            "daily_limit": stats.get("daily_limit", 1),
            "remaining": stats.get("remaining", 1)
        }
        
    except Exception as e:
        print(f"Error in usage stats endpoint: {e}")
        # Return safe default values
        return {
            "today_usage": 0,
            "daily_limit": 1,
            "remaining": 1
        }
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

@app.get("/api/auth/me")
async def get_current_user(auth: dict = Depends(get_current_auth)):
    """Get current user info - useful for debugging"""
    return {
        "success": True,
        "user_id": auth["user_id"],
        "session_id": auth["session_id"],
        "authenticated": True
    }

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
# ✅ Startup Event - UPDATED FOR FILE CLEANUP
# ---------------------------------------------------------
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    print("🚀 DataPulse API starting up...")
    ensure_tables()
    print("✅ Database tables initialized")
    
    # Clean up expired files AND sessions on startup
    cleaned_files = cleanup_expired_files()
    cleaned_sessions = cleanup_expired_sessions()
    
    if cleaned_files > 0:
        print(f"🧹 Cleaned up {cleaned_files} expired files")
    if cleaned_sessions > 0:
        print(f"🧹 Cleaned up {cleaned_sessions} expired sessions")
    
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