import os
import json
import pandas as pd
import numpy as np
from io import BytesIO
import hashlib
import uuid
import httpx
import bcrypt
import textwrap  # ADD THIS IMPORT
from datetime import datetime, date, timedelta
from typing import Optional, Dict, Any, List, Tuple
import google.generativeai as genai
import asyncio
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Response, Query, Depends, status, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, EmailStr

# ---------------------------------------------------------
# ✅ Configuration
# ---------------------------------------------------------
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://data-pulse-one.vercel.app")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "AIzaSyBe8E5aR-g5ecP7OThZB6S_Sg-A2RAZ3bk")


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
user_reports = {}  # user_id -> {date -> count}  # ADD THIS LINE

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
    
## ---------------------------------------------------------
# ✅ Database Functions - COMPLETE SESSION MANAGEMENT 
# ---------------------------------------------------------
try:
    import pymssql as db_lib
    print("✅ pymssql imported successfully ")
except ImportError as e:
    print(f"❌ pymssql import failed: {e}")
    db_lib = None

def get_db_conn():
    if not db_lib:
        print("❌ No database library available")
        return None
        
    try:
        print(f"🔗 Attempting database connection to {DB_HOST}:{DB_PORT}")
        
        # pymssql connection (pure Python - most compatible)
        conn = db_lib.connect(
            server=DB_HOST,
            port=int(DB_PORT),
            user=DB_UID, 
            password=DB_PWD,
            database=DB_NAME,
            timeout=30
        )
            
        print("✅ Database connection successful")
        return conn
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return None

def ensure_tables():
    """Create necessary tables if they don't exist - COMPLETE SESSION MANAGEMENT"""
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
            password_hash NVARCHAR(200) NULL,
            google_id NVARCHAR(128) NULL,
            created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
            last_login_at DATETIME2 NULL,
            is_premium BIT NOT NULL DEFAULT 0,
            is_admin BIT NOT NULL DEFAULT 0,  
            premium_expires_at DATETIME2 NULL
        )
        """)
        
        # User sessions table - ENHANCED
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
            is_active BIT NOT NULL DEFAULT 1,
            login_method NVARCHAR(20) NOT NULL DEFAULT 'email'  -- 'email' or 'google'
        )
        """)
        
        # User reports table - NEW: Track report usage
        cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='user_reports' AND xtype='U')
        CREATE TABLE user_reports (
            id INT IDENTITY PRIMARY KEY,
            user_id NVARCHAR(128) NOT NULL,
            report_date DATE NOT NULL,
            report_count INT NOT NULL DEFAULT 0,
            last_report_at DATETIME2 NULL,
            created_at DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
            UNIQUE (user_id, report_date)
        )
        """)
        
        # Uploaded files table
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
        cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='pdf_reports' AND xtype='U')
        CREATE TABLE pdf_reports (
            id NVARCHAR(64) NOT NULL PRIMARY KEY,
            user_id NVARCHAR(128) NOT NULL,
            upload_id NVARCHAR(64) NOT NULL,
            filename NVARCHAR(255) NOT NULL,
            original_filename NVARCHAR(255) NOT NULL,
            file_size BIGINT NOT NULL,
            pdf_data VARBINARY(MAX) NOT NULL,
            created_at DATETIME2 NOT NULL DEFAULT SYSDATETIME()
        )
        """)
        
        conn.commit()
        print("✅ Database tables ensured")
    except Exception as e:
        print(f"Database setup error: {e}")
    finally:
        conn.close()


# ✅ ADD THESE NEW FAST FUNCTIONS AFTER YOUR EXISTING DATABASE FUNCTIONS:

def user_by_email_fast(email: str) -> Dict[str, Any] | None:
    """Ultra-fast user lookup - only essential fields"""
    conn = get_db_conn()
    if not conn:
        user_data = users_db.get(email)
        if user_data:
            return {
                'email': user_data.get('email'),
                'password_hash': user_data.get('password_hash'),
                'full_name': user_data.get('full_name')
            }
        return None
        
    try:
        cursor = conn.cursor()
        # Only select needed fields for login
        cursor.execute(
            "SELECT email, password_hash, full_name FROM users WHERE email = %s",
            (email,)
        )
        row = cursor.fetchone()
        if row:
            return {
                'email': row[0],
                'password_hash': row[1],
                'full_name': row[2]
            }
        return None
    except Exception as e:
        print(f"Fast user lookup error: {e}")
        user_data = users_db.get(email)
        if user_data:
            return {
                'email': user_data.get('email'),
                'password_hash': user_data.get('password_hash'),
                'full_name': user_data.get('full_name')
            }
        return None
    finally:
        if conn:
            conn.close()

def ensure_session_fast(user_id: str, ip: Optional[str], ua: Optional[str]) -> str:
    """Fast session creation without complex checks"""
    current_time = datetime.now()
    expires_time = current_time + timedelta(hours=24)
    
    # In-memory session for speed
    new_sid = str(uuid.uuid4())
    user_sessions[new_sid] = {
        'user_id': user_id,
        'created_at': current_time,
        'last_accessed': current_time,
        'login_method': 'email'
    }
    
    # Queue database write for background
    asyncio.create_task(write_session_to_db_background({
        'session_id': new_sid,
        'user_id': user_id,
        'ip': ip,
        'user_agent': ua,
        'created_at': current_time,
        'expires_at': expires_time
    }))
    
    print(f"🚀 Fast session created: {new_sid} for user: {user_id}")
    return new_sid

# ✅ ADD BACKGROUND PROCESSING FUNCTIONS:


# Thread pool for background tasks
background_executor = ThreadPoolExecutor(max_workers=2)

async def update_last_login_background(email: str):
    """Update last login in background without blocking response"""
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            background_executor, 
            _update_last_login_sync, 
            email
        )
    except Exception as e:
        print(f"Background last login update error: {e}")

def _update_last_login_sync(email: str):
    """Sync function for background last login update"""
    try:
        conn = get_db_conn()
        if conn:
            cursor = conn.cursor()
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            cursor.execute(
                "UPDATE users SET last_login_at = %s WHERE email = %s",
                (current_time, email)
            )
            conn.commit()
            conn.close()
            print(f"✅ Background last login updated for: {email}")
    except Exception as e:
        print(f"Background last login error: {e}")

async def write_session_to_db_background(session_data: dict):
    """Write session to database in background"""
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            background_executor,
            _write_session_to_db_sync,
            session_data
        )
    except Exception as e:
        print(f"Background session write error: {e}")

def _write_session_to_db_sync(session_data: dict):
    """Actual database write called from background thread"""
    try:
        conn = get_db_conn()
        if conn:
            cursor = conn.cursor()
            
            current_time_str = session_data['created_at'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            expires_time_str = session_data['expires_at'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            
            cursor.execute(
                """INSERT INTO user_sessions 
                   (session_id, user_id, ip, user_agent, created_at, last_accessed, expires_at, is_active, login_method) 
                   VALUES (%s, %s, %s, %s, %s, %s, %s, 1, %s)""",
                (session_data['session_id'], session_data['user_id'], session_data['ip'], 
                 session_data['user_agent'], current_time_str, current_time_str, 
                 expires_time_str, 'email')
            )
            conn.commit()
            conn.close()
            print(f"✅ Background session saved: {session_data['session_id']}")
    except Exception as e:
        print(f"Background session write error: {e}")
        
from fpdf import FPDF
from datetime import datetime
from typing import Dict, Any
import textwrap

def generate_complete_analysis_pdf(analysis_data: Dict[str, Any]) -> bytes:
    """Generate a complete PDF with all analysis data using FPDF"""
    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        # Add first page
        pdf.add_page()
        
        # Title
        pdf.set_font("Arial", "B", 24)
        pdf.cell(0, 15, "DataPulse AI Analysis Report", 0, 1, "C")
        pdf.ln(10)
        
        # File Information
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "File Information", 0, 1)
        pdf.set_font("Arial", "", 12)
        
        file_info = analysis_data.get('file', {})
        pdf.cell(0, 8, f"Filename: {file_info.get('name', 'Unknown')}", 0, 1)
        pdf.cell(0, 8, f"Size: {file_info.get('size_bytes', 0)} bytes", 0, 1)
        pdf.cell(0, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1)
        pdf.ln(5)
        
        # Data Profiling
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Data Profiling", 0, 1)
        
        profiling = analysis_data.get('profiling', {})
        profile_data = [
            ("Total Rows", str(profiling.get('rows', 'N/A'))),
            ("Total Columns", str(profiling.get('columns', 'N/A'))),
            ("Missing Values", str(profiling.get('missing_total', 'N/A'))),
            ("Numeric Columns", str(len(profiling.get('numeric_columns', [])))),
        ]
        
        _create_table(pdf, profile_data, header_bg=(30, 64, 175))
        pdf.ln(10)
        
        # Key Performance Indicators
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Key Performance Indicators", 0, 1)
        
        kpis = analysis_data.get('kpis', {})
        kpi_data = [
            ("Metric", "Value"),
            ("Total Rows", str(kpis.get('total_rows', 'N/A'))),
            ("Total Columns", str(kpis.get('total_columns', 'N/A'))),
            ("Missing Data %", f"{kpis.get('missing_pct', 'N/A')}%"),
            ("Duplicate Rows", str(kpis.get('duplicate_rows', 'N/A'))),
            ("Statistical Outliers", str(kpis.get('outliers_total', 'N/A'))),
        ]
        if kpis.get('rows_per_day'):
            kpi_data.append(("Rows Per Day", str(kpis.get('rows_per_day'))))
        
        _create_table(pdf, kpi_data, header_bg=(5, 150, 105))
        pdf.ln(10)
        
        # AI Insights and Summary
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "AI Executive Summary", 0, 1)
        
        insights = analysis_data.get('insights', {})
        detailed_summary = analysis_data.get('detailed_summary', {})
        
        # Executive Overview
        if detailed_summary.get('executive_overview'):
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 8, "Overview", 0, 1)
            pdf.set_font("Arial", "", 12)
            _wrap_text(pdf, detailed_summary['executive_overview'])
            pdf.ln(5)
        
        # Key Insights
        if insights.get('key_insights'):
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 8, "Key Insights", 0, 1)
            pdf.set_font("Arial", "", 12)
            for insight in insights['key_insights']:
                pdf.cell(10, 8, "•", 0, 0)
                pdf.multi_cell(0, 8, f" {insight}")
            pdf.ln(5)
        
        # Data Quality Assessment
        if detailed_summary.get('data_quality_assessment'):
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 8, "Data Quality", 0, 1)
            pdf.set_font("Arial", "", 12)
            _wrap_text(pdf, detailed_summary['data_quality_assessment'])
            pdf.ln(5)
        
        # Key Trends & Patterns
        if detailed_summary.get('key_trends'):
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 8, "Key Trends & Patterns", 0, 1)
            pdf.set_font("Arial", "", 12)
            for trend in detailed_summary['key_trends']:
                pdf.cell(10, 8, "•", 0, 0)
                pdf.multi_cell(0, 8, f" {trend}")
            pdf.ln(5)
        
        # Business Implications
        if detailed_summary.get('business_implications'):
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 8, "Business Implications", 0, 1)
            pdf.set_font("Arial", "", 12)
            for implication in detailed_summary['business_implications']:
                pdf.cell(10, 8, "•", 0, 0)
                pdf.multi_cell(0, 8, f" {implication}")
            pdf.ln(5)
        
        # Recommendations
        if detailed_summary.get('recommendations'):
            recs = detailed_summary['recommendations']
            if recs.get('short_term'):
                pdf.set_font("Arial", "B", 14)
                pdf.cell(0, 8, "Short-term Recommendations (0-3 months)", 0, 1)
                pdf.set_font("Arial", "", 12)
                for rec in recs['short_term']:
                    pdf.cell(10, 8, "•", 0, 0)
                    pdf.multi_cell(0, 8, f" {rec}")
                pdf.ln(5)
            
            if recs.get('long_term'):
                pdf.set_font("Arial", "B", 14)
                pdf.cell(0, 8, "Long-term Strategies (3-12 months)", 0, 1)
                pdf.set_font("Arial", "", 12)
                for rec in recs['long_term']:
                    pdf.cell(10, 8, "•", 0, 0)
                    pdf.multi_cell(0, 8, f" {rec}")
                pdf.ln(5)
        
        # Immediate Quick Wins
        if detailed_summary.get('action_items_quick_wins'):
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 8, "Immediate Quick Wins", 0, 1)
            pdf.set_font("Arial", "", 12)
            for win in detailed_summary['action_items_quick_wins']:
                pdf.cell(10, 8, "•", 0, 0)
                pdf.multi_cell(0, 8, f" {win}")
            pdf.ln(5)
        
        # Risk Alerts
        if detailed_summary.get('risk_alerts'):
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 8, "Risk Alerts", 0, 1)
            pdf.set_font("Arial", "", 12)
            for risk in detailed_summary['risk_alerts']:
                pdf.cell(10, 8, "⚠", 0, 0)
                pdf.multi_cell(0, 8, f" {risk}")
            pdf.ln(5)
        
        # Predictive Insights
        if detailed_summary.get('predictive_insights'):
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 8, "Predictive Insights", 0, 1)
            pdf.set_font("Arial", "", 12)
            for insight in detailed_summary['predictive_insights']:
                pdf.cell(10, 8, "•", 0, 0)
                pdf.multi_cell(0, 8, f" {insight}")
            pdf.ln(5)
        
        # Industry Benchmarking
        if detailed_summary.get('industry_comparison'):
            pdf.set_font("Arial", "B", 14)
            pdf.cell(0, 8, "Industry Benchmarking", 0, 1)
            pdf.set_font("Arial", "", 12)
            _wrap_text(pdf, detailed_summary['industry_comparison'])
            pdf.ln(5)
        
        # Get PDF as bytes
        pdf_output = pdf.output(dest='S').encode('latin1')
        
        print(f"📊 Complete PDF generated: {len(pdf_output)} bytes")
        
        # Debug: Print available fields
        print(f"🔍 Available detailed_summary fields: {list(detailed_summary.keys())}")
        for key, value in detailed_summary.items():
            if isinstance(value, list):
                print(f"  {key}: {len(value)} items")
            else:
                print(f"  {key}: {type(value)}")
        
        return pdf_output
        
    except Exception as e:
        print(f"❌ PDF generation error: {e}")
        import traceback
        traceback.print_exc()
        # Fallback to simple PDF
        return generate_simple_pdf(analysis_data)

def _create_table(pdf, data, header_bg=(0, 0, 0)):
    """Helper function to create styled tables"""
    col_width = 95 if len(data[0]) == 2 else 63
    row_height = 10
    
    for i, row in enumerate(data):
        is_header = i == 0
        for j, cell in enumerate(row):
            if is_header:
                pdf.set_fill_color(*header_bg)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font("Arial", "B", 12)
            else:
                pdf.set_fill_color(243, 244, 246)
                pdf.set_text_color(0, 0, 0)
                pdf.set_font("Arial", "", 12)
            
            pdf.cell(col_width, row_height, str(cell), 1, 0, "L", fill=True)
        
        pdf.ln(row_height)

def _wrap_text(pdf, text, max_width=180):
    """Helper function to wrap long text"""
    lines = textwrap.wrap(text, width=80)
    for line in lines:
        pdf.cell(0, 8, line, 0, 1)

def generate_simple_pdf(analysis_data: Dict[str, Any]) -> bytes:
    """Fallback simple PDF generator using FPDF"""
    pdf = FPDF()
    pdf.add_page()
    
    # Title
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 15, "DataPulse Analysis Report", 0, 1, "C")
    pdf.ln(10)
    
    # Basic file info
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 8, f"File: {analysis_data.get('file', {}).get('name', 'Unknown')}", 0, 1)
    pdf.cell(0, 8, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", 0, 1)
    pdf.ln(10)
    
    # KPIs
    kpis = analysis_data.get('kpis', {})
    if kpis:
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Key Metrics", 0, 1)
        pdf.set_font("Arial", "", 12)
        
        pdf.cell(0, 8, f"Rows: {kpis.get('total_rows', 'N/A')}", 0, 1)
        pdf.cell(0, 8, f"Columns: {kpis.get('total_columns', 'N/A')}", 0, 1)
        pdf.cell(0, 8, f"Missing Data: {kpis.get('missing_pct', 'N/A')}%", 0, 1)
        pdf.ln(10)
    
    # Insights summary
    insights = analysis_data.get('insights', {})
    if insights.get('summary'):
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Summary", 0, 1)
        pdf.set_font("Arial", "", 12)
        _wrap_text(pdf, insights['summary'])
    
    return pdf.output(dest='S').encode('latin1')


# ---------------------------------------------------------
# ✅ USAGE LIMIT MANAGEMENT
# ---------------------------------------------------------

def check_report_eligibility(user_id: str) -> Dict[str, Any]:
    """
    Check if user can generate a report - FIXED VERSION
    Returns: {
        "can_generate": bool,
        "reason": str,
        "next_available": datetime | None,
        "is_premium": bool,
        "is_admin": bool  
    }
    """
    conn = get_db_conn()
    if not conn:
        # Fallback to in-memory (for development)
        today = date.today().isoformat()
        user_today_reports = user_reports.get(user_id, {}).get(today, 0)
        
        user_data = users_db.get(user_id, {})
        is_admin = user_data.get('is_admin', False)
        
        can_generate = user_today_reports < 1
        return {
            "can_generate": can_generate,
            "reason": "DAILY_LIMIT_REACHED" if not can_generate else "ELIGIBLE",
            "next_available": None if can_generate else datetime.now() + timedelta(days=1),
            "is_premium": False,
            "is_admin": is_admin  
        }
        
    try:
        cursor = conn.cursor()
        
        # ✅ CHECK IF USER IS ADMIN
        cursor.execute(
            "SELECT is_premium, premium_expires_at, is_admin FROM users WHERE email = %s",
            (user_id,)
        )
        user_row = cursor.fetchone()
        
        is_premium = user_row[0] if user_row else False
        premium_expires = user_row[1] if user_row else None
        is_admin = user_row[2] if user_row else False  
        
        # ✅ ADMIN USERS HAVE UNLIMITED REPORTS
        if is_admin:
            return {
                "can_generate": True,
                "reason": "ADMIN_USER",
                "next_available": None,
                "is_premium": is_premium,
                "is_admin": True
            }
        
        # ✅ PREMIUM USERS HAVE UNLIMITED REPORTS
        if is_premium and premium_expires and premium_expires > datetime.now():
            return {
                "can_generate": True,
                "reason": "PREMIUM_USER",
                "next_available": None,
                "is_premium": True,
                "is_admin": False
            }
        
        today = date.today()
        
        # ✅ CHECK TODAY'S REPORT COUNT - READ ONLY, NO UPDATES!
        cursor.execute(
            "SELECT report_count, last_report_at FROM user_reports WHERE user_id = %s AND report_date = %s",
            (user_id, today)
        )
        row = cursor.fetchone()
        
        if row:
            report_count, last_report_at = row
            if report_count >= 1:
                # Calculate next available time (24 hours from last report)
                next_available = last_report_at + timedelta(hours=24)
                if datetime.now() < next_available:
                    return {
                        "can_generate": False,
                        "reason": "DAILY_LIMIT_REACHED",
                        "next_available": next_available,
                        "is_premium": False,
                        "is_admin": False
                    }
                else:
                    # 🚨 CRITICAL FIX: Don't reset here - let increment_report_count handle it
                    # The record will be updated when user actually generates a report
                    return {
                        "can_generate": True,
                        "reason": "ELIGIBLE_AFTER_COOLDOWN",
                        "next_available": None,
                        "is_premium": False,
                        "is_admin": False
                    }
            else:
                return {
                    "can_generate": True,
                    "reason": "ELIGIBLE",
                    "next_available": None,
                    "is_premium": False,
                    "is_admin": False
                }
        else:
            # No reports today - user is eligible
            return {
                "can_generate": True,
                "reason": "ELIGIBLE",
                "next_available": None,
                "is_premium": False,
                "is_admin": False
            }
            
    except Exception as e:
        print(f"Report eligibility error: {e}")
        return {
            "can_generate": True,  
            "reason": "ERROR",
            "next_available": None,
            "is_premium": False,
            "is_admin": False
        }
    finally:
        conn.close()

def increment_report_count(user_id: str) -> bool:
    """Increment user's report count for today - ENHANCED VERSION"""
    conn = get_db_conn()
    if not conn:
        # Fallback to in-memory storage
        today = date.today().isoformat()
        if user_id not in user_reports:
            user_reports[user_id] = {}
        user_reports[user_id][today] = user_reports[user_id].get(today, 0) + 1
        return True
        
    try:
        cursor = conn.cursor()
        today = date.today()
        current_time = datetime.now()
        
        # ✅ FIRST: Check if we need to reset due to 24-hour cooldown
        cursor.execute(
            "SELECT report_count, last_report_at FROM user_reports WHERE user_id = %s AND report_date = %s",
            (user_id, today)
        )
        existing_record = cursor.fetchone()
        
        if existing_record:
            report_count, last_report_at = existing_record
            # If 24 hours have passed since last report, reset the count
            if report_count >= 1 and last_report_at and (current_time - last_report_at) >= timedelta(hours=24):
                cursor.execute(
                    "UPDATE user_reports SET report_count = 0, last_report_at = %s WHERE user_id = %s AND report_date = %s",
                    (current_time, user_id, today)
                )
                conn.commit()
                print(f"🔄 Reset report count for {user_id} after 24-hour cooldown")
        
        # ✅ NOW: Insert or update report count
        cursor.execute("""
        MERGE user_reports AS target
        USING (SELECT %s AS user_id, %s AS report_date) AS source
        ON target.user_id = source.user_id AND target.report_date = source.report_date
        WHEN MATCHED THEN
            UPDATE SET report_count = report_count + 1, last_report_at = %s
        WHEN NOT MATCHED THEN
            INSERT (user_id, report_date, report_count, last_report_at) VALUES (%s, %s, 1, %s);
        """, (user_id, today, current_time, user_id, today, current_time))
        
        conn.commit()
        return True
    except Exception as e:
        print(f"Increment report count error: {e}")
        return False
    finally:
        conn.close()

def get_user_report_stats(user_id: str) -> Dict[str, Any]:
    """Get user's report statistics"""
    eligibility = check_report_eligibility(user_id)
    
    conn = get_db_conn()
    if not conn:
        return {
            "can_generate": eligibility["can_generate"],
            "reason": eligibility["reason"],
            "next_available": eligibility["next_available"],
            "is_premium": eligibility["is_premium"],
            "is_admin": eligibility["is_admin"],  
            "today_used": user_reports.get(user_id, {}).get(date.today().isoformat(), 0),
            "daily_limit": 1
        }
        
    try:
        cursor = conn.cursor()
        today = date.today()
        
        cursor.execute(
            "SELECT report_count FROM user_reports WHERE user_id = %s AND report_date = %s",
            (user_id, today)
        )
        row = cursor.fetchone()
        today_used = row[0] if row else 0
        
        return {
            "can_generate": eligibility["can_generate"],
            "reason": eligibility["reason"],
            "next_available": eligibility["next_available"],
            "is_premium": eligibility["is_premium"],
            "today_used": today_used,
            "daily_limit": "∞" if eligibility["is_admin"] else 1  
        }
    except Exception as e:
        print(f"Get report stats error: {e}")
        return {
            "can_generate": True,
            "reason": "ERROR",
            "next_available": None,
            "is_premium": False,
            "today_used": 0,
            "daily_limit": 1
        }
    finally:
        conn.close()

# ---------------------------------------------------------
# ✅ USER MANAGEMENT FUNCTIONS
# ---------------------------------------------------------

def user_by_email(email: str) -> Dict[str, Any] | None:
    """Get user by email from database"""
    conn = get_db_conn()
    if not conn:
        return users_db.get(email)
        
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, email, full_name, password_hash, google_id, created_at, last_login_at, is_premium FROM users WHERE email = %s",
            (email,)
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
                'last_login_at': row[6],
                'is_premium': row[7]
            }
        return None
    except Exception as e:
        print(f"Database error: {e}")
        return users_db.get(email)
    finally:
        conn.close()

def user_by_google_id(google_id: str) -> Dict[str, Any] | None:
    """Get user by Google ID from database"""
    conn = get_db_conn()
    if not conn:
        for user in users_db.values():
            if user.get('google_id') == google_id:
                return user
        return None
        
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, email, full_name, password_hash, google_id, created_at, last_login_at, is_premium FROM users WHERE google_id = %s",
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
                'last_login_at': row[6],
                'is_premium': row[7]
            }
        return None
    except Exception as e:
        print(f"Database error: {e}")
        return None
    finally:
        conn.close()

def create_oauth_session(user_id: str, ip: Optional[str], ua: Optional[str]) -> str:
    """Create session specifically for OAuth without deactivating others"""
    conn = get_db_conn()
    
    current_time = datetime.now()
    expires_time = current_time + timedelta(hours=24)
    
    current_time_str = current_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    expires_time_str = expires_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    if not conn:
        # In-memory session
        new_sid = str(uuid.uuid4())
        user_sessions[new_sid] = {
            'user_id': user_id,
            'created_at': current_time,
            'last_accessed': current_time,
            'login_method': 'google'
        }
        return new_sid
        
    try:
        cursor = conn.cursor()
        
        # 🚨 FIX: Don't deactivate other sessions during OAuth
        # Just create a new session
        new_sid = str(uuid.uuid4())
        cursor.execute(
            """INSERT INTO user_sessions 
               (session_id, user_id, ip, user_agent, created_at, last_accessed, expires_at, is_active, login_method) 
               VALUES (%s, %s, %s, %s, %s, %s, %s, 1, %s)""",
            (new_sid, user_id, ip, ua, current_time_str, current_time_str, expires_time_str, 'google')
        )
        conn.commit()
        conn.close()
        return new_sid
        
    except Exception as e:
        print(f"❌ OAuth session creation error: {e}")
        # Fallback to in-memory
        new_sid = str(uuid.uuid4())
        user_sessions[new_sid] = {
            'user_id': user_id,
            'created_at': current_time,
            'last_accessed': current_time,
            'login_method': 'google'
        }
        return new_sid

def insert_user(full_name: Optional[str], email: str, password_hash: str) -> bool:
    """Insert new user into database with admin check"""
    conn = get_db_conn()
    
    # ✅ CHECK FOR ADMIN EMAIL
    is_admin = check_if_admin_email(email)
    
    if not conn:
        if email in users_db:
            return False
        users_db[email] = {
            'email': email,
            'full_name': full_name,
            'password_hash': password_hash,
            'google_id': None,
            'created_at': datetime.now().isoformat(),
            'is_premium': False,
            'is_admin': is_admin  
        }
        return True
        
    try:
        cursor = conn.cursor()
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        cursor.execute(
            "INSERT INTO users (full_name, email, password_hash, google_id, created_at, is_admin) VALUES (%s, %s, %s, %s, %s, %s)",
            (full_name, email, password_hash, None, current_time, is_admin)  
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"Database insert error: {e}")
        return False
    finally:
        conn.close()

def create_google_user(email: str, name: str, google_id: str) -> bool:
    """Create a user for Google OAuth with admin check"""
    try:
        # ✅ CHECK FOR ADMIN EMAIL
        is_admin = check_if_admin_email(email)
        
        conn = get_db_conn()
        if conn:
            cursor = conn.cursor()
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            cursor.execute(
                "INSERT INTO users (email, full_name, google_id, password_hash, created_at, is_admin) VALUES (%s, %s, %s, %s, %s, %s)",
                (email, name, google_id, None, current_time, is_admin)  
            )
            conn.commit()
            conn.close()
            return True
        else:
            users_db[email] = {
                'email': email,
                'full_name': name,
                'google_id': google_id,
                'password_hash': None,
                'created_at': datetime.now().isoformat(),
                'is_premium': False,
                'is_admin': is_admin  
            }
            return True
    except Exception as e:
        print(f"User creation error: {e}")
        return True

def check_if_admin_email(email: str) -> bool:
    """Check if email is in the admin whitelist"""
    admin_emails = {
        "gms-world@gmail.com",
        "saqibaltaf27@gmail.com",
        "iamnaiftikhar8@gmail.com",
        "sap.admin@gms-world.com",
        
        # Add more admin emails here
    }
    
    # Case-insensitive check
    return email.lower().strip() in {admin_email.lower() for admin_email in admin_emails}

def create_google_user(email: str, name: str, google_id: str) -> bool:
    """Create a user for Google OAuth"""
    try:
        conn = get_db_conn()
        if conn:
            cursor = conn.cursor()
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            cursor.execute(
                "INSERT INTO users (email, full_name, google_id, password_hash, created_at) VALUES (%s, %s, %s, %s, %s)",
                (email, name, google_id, None, current_time)
            )
            conn.commit()
            conn.close()
            return True
        else:
            users_db[email] = {
                'email': email,
                'full_name': name,
                'google_id': google_id,
                'password_hash': None,
                'created_at': datetime.now().isoformat(),
                'is_premium': False
            }
            return True
    except Exception as e:
        print(f"User creation error: {e}")
        return True

def update_user_google_id(email: str, google_id: str) -> bool:
    """Update existing user with Google ID"""
    try:
        conn = get_db_conn()
        if conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET google_id = %s WHERE email = %s",
                (google_id, email)
            )
            conn.commit()
            conn.close()
        else:
            if email in users_db:
                users_db[email]['google_id'] = google_id
        return True
    except Exception as e:
        print(f"Update user error: {e}")
        return False

def update_user_last_login(email: str) -> bool:
    """Update user's last login timestamp"""
    conn = get_db_conn()
    if not conn:
        if email in users_db:
            users_db[email]['last_login_at'] = datetime.now().isoformat()
        return True
        
    try:
        cursor = conn.cursor()
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        cursor.execute(
            "UPDATE users SET last_login_at = %s WHERE email = %s",
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
# ✅ SESSION MANAGEMENT FUNCTIONS
# ---------------------------------------------------------

def ensure_session(user_id: str, session_id: Optional[str], ip: Optional[str], ua: Optional[str], login_method: str = 'email') -> str:
    """Create or update user session with conflict prevention"""
    conn = get_db_conn()
    
    current_time = datetime.now()
    expires_time = current_time + timedelta(hours=24)
    
    current_time_str = current_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    expires_time_str = expires_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    if not conn:
        # In-memory: Always create new session on login
        new_sid = str(uuid.uuid4())
        user_sessions[new_sid] = {
            'user_id': user_id,
            'created_at': current_time,
            'last_accessed': current_time,
            'login_method': login_method
        }
        print(f"✅ Created new in-memory session: {new_sid} for user: {user_id}")
        return new_sid
        
    try:
        cursor = conn.cursor()
        
        # 🚨 CRITICAL FIX: Deactivate ALL other active sessions for this user
        cursor.execute("""
            UPDATE user_sessions 
            SET is_active = 0 
            WHERE user_id = %s AND is_active = 1 AND session_id != %s
        """, (user_id, session_id or ''))
        
        deactivated_count = cursor.rowcount
        if deactivated_count > 0:
            print(f"🔄 Deactivated {deactivated_count} previous sessions for user: {user_id}")
        
        # Check if provided session ID is valid and belongs to this user
        if session_id:
            cursor.execute(
                """SELECT session_id, user_id FROM user_sessions 
                   WHERE session_id = %s AND is_active = 1 AND expires_at > %s""",
                (session_id, current_time_str)
            )
            existing_session = cursor.fetchone()
            
            if existing_session and existing_session[1] == user_id:
                # Valid session for same user - update it
                cursor.execute(
                    """UPDATE user_sessions 
                       SET last_accessed = %s, expires_at = %s, login_method = %s
                       WHERE session_id = %s""",
                    (current_time_str, expires_time_str, login_method, session_id)
                )
                conn.commit()
                conn.close()
                print(f"✅ Updated existing session: {session_id}")
                return session_id
        
        # 🚨 CREATE NEW SESSION (always on fresh login)
        new_sid = str(uuid.uuid4())
        cursor.execute(
            """INSERT INTO user_sessions 
               (session_id, user_id, ip, user_agent, created_at, last_accessed, expires_at, is_active, login_method) 
               VALUES (%s, %s, %s, %s, %s, %s, %s, 1, %s)""",
            (new_sid, user_id, ip, ua, current_time_str, current_time_str, expires_time_str, login_method)
        )
        conn.commit()
        conn.close()
        print(f"✅ Created new database session: {new_sid} for user: {user_id}")
        return new_sid
        
    except Exception as e:
        print(f"❌ Session error: {e}")
        # Fallback to in-memory
        new_sid = str(uuid.uuid4())
        user_sessions[new_sid] = {
            'user_id': user_id,
            'created_at': current_time,
            'last_accessed': current_time,
            'login_method': login_method
        }
        return new_sid

def resolve_user_from_session(session_id: str) -> Optional[str]:
    """Resolve user from session with enhanced validation"""
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
               WHERE session_id = %s AND is_active = 1 AND expires_at > %s""",
            (session_id, current_time)
        )
        row = cursor.fetchone()
        
        if row:
            user_id = row[0]
            # Update session expiry when accessed
            new_expires = (datetime.now() + timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            cursor.execute(
                """UPDATE user_sessions 
                   SET last_accessed = %s, expires_at = %s
                   WHERE session_id = %s""",
                (current_time, new_expires, session_id)
            )
            conn.commit()
            print(f"✅ Session validated for user: {user_id}")
            return user_id
        
        print(f"❌ Invalid or expired session: {session_id}")
        return None
        
    except Exception as e:
        print(f"❌ Session resolve error: {e}")
        session_data = user_sessions.get(session_id)
        return session_data.get('user_id') if session_data else None
    finally:
        if conn:
            conn.close()
            

def cleanup_expired_sessions() -> int:
    """Clean up expired sessions"""
    conn = get_db_conn()
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    if not conn:
        expired_count = 0
        for session_id, session_data in list(user_sessions.items()):
            if isinstance(session_data, dict):
                if datetime.now() - session_data.get('created_at', datetime.now()) >= timedelta(hours=24):
                    del user_sessions[session_id]
                    expired_count += 1
        return expired_count
        
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM user_sessions WHERE expires_at <= %s", (current_time,))
        expired_count = cursor.rowcount
        conn.commit()
        return expired_count
    except Exception as e:
        print(f"Session cleanup error: {e}")
        return 0
    finally:
        if conn:
            conn.close()

# ---------------------------------------------------------
# ✅ FILE STORAGE FUNCTIONS
# ---------------------------------------------------------

def store_file_in_db(upload_id: str, file_data: bytes, filename: str, user_id: str) -> bool:
    """Store uploaded file in database"""
    conn = get_db_conn()
    if not conn:
        uploaded_files[upload_id] = {
            'data': file_data,
            'filename': filename,
            'user_id': user_id,
            'uploaded_at': datetime.now()
        }
        return True
        
    try:
        cursor = conn.cursor()
        
        file_type = "csv" if filename.lower().endswith(".csv") else "excel"
        file_size = len(file_data)
        
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        expires_time = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        cursor.execute("SELECT 1 FROM uploaded_files WHERE upload_id = %s", (upload_id,))
        if cursor.fetchone():
            cursor.execute(
                """UPDATE uploaded_files 
                   SET filename = %s, file_size = %s, file_data = %s, file_type = %s, uploaded_at = %s, expires_at = %s, is_active = 1
                   WHERE upload_id = %s AND user_id = %s""",
                (filename, file_size, file_data, file_type, current_time, expires_time, upload_id, user_id)
            )
        else:
            cursor.execute(
                """INSERT INTO uploaded_files 
                   (upload_id, user_id, filename, file_size, file_data, file_type, uploaded_at, expires_at) 
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (upload_id, user_id, filename, file_size, file_data, file_type, current_time, expires_time)
            )
        
        conn.commit()
        return True
    except Exception as e:
        print(f"File storage error: {e}")
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
    """Retrieve uploaded file from database"""
    conn = get_db_conn()
    if not conn:
        file_info = uploaded_files.get(upload_id)
        if file_info and file_info['user_id'] == user_id:
            return file_info
        return None
        
    try:
        cursor = conn.cursor()
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        cursor.execute(
            """SELECT upload_id, user_id, filename, file_size, file_data, file_type, uploaded_at 
               FROM uploaded_files 
               WHERE upload_id = %s AND user_id = %s AND is_active = 1 AND expires_at > %s""",
            (upload_id, user_id, current_time)
        )
        row = cursor.fetchone()
        if row:
            return {
                'upload_id': row[0],
                'user_id': row[1],
                'filename': row[2],
                'file_size': row[3],
                'data': row[4],
                'file_type': row[5],
                'uploaded_at': row[6]
            }
        return None
    except Exception as e:
        print(f"File retrieval error: {e}")
        file_info = uploaded_files.get(upload_id)
        if file_info and file_info['user_id'] == user_id:
            return file_info
        return None
    finally:
        conn.close()

def cleanup_expired_files() -> int:
    """Clean up expired files"""
    conn = get_db_conn()
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    if not conn:
        current_datetime = datetime.now()
        expired_count = 0
        for upload_id, file_info in list(uploaded_files.items()):
            if file_info['uploaded_at'] + timedelta(days=7) < current_datetime:
                del uploaded_files[upload_id]
                expired_count += 1
        return expired_count
        
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM uploaded_files WHERE expires_at <= %s OR is_active = 0", (current_time,))
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
    """Get current authenticated user with better error handling"""
    sid = request.cookies.get("dp_session_id")
    
    print(f"🔍 Checking auth - Session ID from cookies: {sid}")
    
    if not sid:
        print("❌ No session ID in cookies")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    user_email = resolve_user_from_session(sid)
    if not user_email:
        print(f"❌ Invalid session: {sid}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")

    # Get client info for session refresh
    xff = request.headers.get("X-Forwarded-For")
    ip = (xff.split(",")[0].strip() if xff else None)
    ua = request.headers.get("User-Agent")
    ua = ua[:512] if ua else None

    # Refresh session
    new_sid = ensure_session(user_email, sid, ip, ua)
    
    print(f"✅ Authenticated user: {user_email}, session: {new_sid}")
    return {"user_id": user_email, "session_id": new_sid}

def store_pdf_report(user_id: str, upload_id: str, pdf_data: bytes, filename: str, original_filename: str) -> str:
    """Store PDF report in database"""
    conn = get_db_conn()
    pdf_id = str(uuid.uuid4())
    
    if not conn:
        # Fallback to in-memory storage
        if 'pdf_reports' not in uploaded_files:
            uploaded_files['pdf_reports'] = {}
        uploaded_files['pdf_reports'][pdf_id] = {
            'user_id': user_id,
            'pdf_data': pdf_data,
            'filename': filename,
            'original_filename': original_filename,
            'upload_id': upload_id,
            'created_at': datetime.now(),
            'file_size': len(pdf_data)
        }
        return pdf_id
        
    try:
        cursor = conn.cursor()
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        file_size = len(pdf_data)
        
        cursor.execute(
            """INSERT INTO pdf_reports 
               (id, user_id, upload_id, filename, original_filename, file_size, pdf_data, created_at) 
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (pdf_id, user_id, upload_id, filename, original_filename, file_size, pdf_data, current_time)
        )
        conn.commit()
        print(f"✅ PDF stored in database: {pdf_id}")
        return pdf_id
    except Exception as e:
        print(f"❌ PDF storage error: {e}")
        # Fallback to in-memory
        if 'pdf_reports' not in uploaded_files:
            uploaded_files['pdf_reports'] = {}
        uploaded_files['pdf_reports'][pdf_id] = {
            'user_id': user_id,
            'pdf_data': pdf_data,
            'filename': filename,
            'original_filename': original_filename,
            'upload_id': upload_id,
            'created_at': datetime.now(),
            'file_size': len(pdf_data)
        }
        return pdf_id
    finally:
        if conn:
            conn.close()
# ---------------------------------------------------------
# ✅ Routes - COMPLETE SESSION MANAGEMENT
# ---------------------------------------------------------
@app.post("/api/export-pdf")
async def export_pdf_report(
    auth: dict = Depends(get_current_auth),
    upload_id: str = Body(..., embed=True),
    analysis_data: Dict[str, Any] = Body(..., embed=True)
):
    user_id = auth["user_id"]
    
    print(f"📄 COMPLETE PDF Export requested by {user_id}")
    print(f"📊 Analysis data type: {type(analysis_data)}")
    print(f"📊 Analysis keys: {analysis_data.keys() if analysis_data else 'None'}")
    
    try:
        # Get file info
        file_info = get_file_from_db(upload_id, user_id)
        if not file_info:
            return {"success": False, "error": "Original file not found"}
            
        original_filename = file_info['filename']
        print(f"📁 Original filename: {original_filename}")

        # Generate COMPLETE PDF with all analysis data
        print("🔄 Generating complete analysis PDF...")
        pdf_data = generate_complete_analysis_pdf(analysis_data)
        print(f"✅ Complete PDF generated: {len(pdf_data)} bytes")

        # Store in database
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_filename = f"DataPulse_Analysis_{original_filename}_{timestamp}.pdf"
        
        pdf_id = store_pdf_report(
            user_id=user_id,
            upload_id=upload_id,
            pdf_data=pdf_data,
            filename=pdf_filename,
            original_filename=original_filename
        )
        
        print(f"💾 PDF stored in database with ID: {pdf_id}")
        
        # Verify storage
        conn = get_db_conn()
        if conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM pdf_reports WHERE id = %s", (pdf_id,))
            count = cursor.fetchone()[0]
            conn.close()
            print(f"🔍 Database verification: {count} records found")
        
        return {
            "success": True,
            "pdf_id": pdf_id,
            "filename": pdf_filename,
            "message": "Complete analysis PDF exported and stored successfully"
        }
        
    except Exception as e:
        print(f"❌ Export failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"success": False, "error": f"Export failed: {str(e)}"}
    
@app.get("/api/user/profile")
async def get_user_profile(auth: dict = Depends(get_current_auth)):
    """Get user profile information"""
    user_id = auth["user_id"]
    
    conn = get_db_conn()
    if not conn:
        return {
            "user_id": user_id,
            "email": user_id,
            "user_name": user_id.split('@')[0],
            "full_name": None,
            "is_premium": False,
            "created_at": datetime.now().isoformat(),
            "last_login": datetime.now().isoformat()
        }
    
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT email, full_name, created_at, last_login_at, is_premium 
            FROM users WHERE email = %s
        """, (user_id,))
        
        row = cursor.fetchone()
        if row:
            return {
                "user_id": user_id,
                "email": row[0],
                "user_name": row[1] or user_id.split('@')[0],
                "full_name": row[1],
               # You can add role field to users table
                "is_premium": bool(row[4]),
                "created_at": row[2].isoformat() if row[2] else datetime.now().isoformat(),
                "last_login": row[3].isoformat() if row[3] else datetime.now().isoformat()
            }
        else:
            return {
                "user_id": user_id,
                "email": user_id,
                "user_name": user_id.split('@')[0],
                "full_name": None,
                "company": None,
                "role": None,
                "is_premium": False,
                "created_at": datetime.now().isoformat(),
                "last_login": datetime.now().isoformat()
            }
            
    except Exception as e:
        print(f"Profile fetch error: {e}")
        return {
            "user_id": user_id,
            "email": user_id,
            "user_name": user_id.split('@')[0],
            "full_name": None,
            "is_premium": False,
            "created_at": datetime.now().isoformat(),
            "last_login": datetime.now().isoformat()
        }
    finally:
        conn.close()

        
@app.get("/api/user/pdf-reports")
async def get_user_pdf_reports(auth: dict = Depends(get_current_auth)):
    """Get user's PDF reports"""
    user_id = auth["user_id"]
    
    print(f"📥 Fetching PDF reports for user: {user_id}")
    
    conn = get_db_conn()
    if not conn:
        # Fallback to in-memory storage
        pdf_reports = uploaded_files.get('pdf_reports', {})
        user_reports = []
        
        for pdf_id, report_data in pdf_reports.items():
            if report_data.get('user_id') == user_id:
                user_reports.append({
                    "id": pdf_id,
                    "filename": report_data.get('filename', 'Unknown'),
                    "file_size": report_data.get('file_size', 0),
                    "upload_date": report_data.get('created_at').isoformat() if report_data.get('created_at') else datetime.now().isoformat(),
                    "analysis_date": report_data.get('created_at').isoformat() if report_data.get('created_at') else datetime.now().isoformat(),
                    "download_url": f"/api/download-pdf/{pdf_id}"
                })
        
        print(f"📋 Found {len(user_reports)} PDF reports in memory")
        return {"reports": user_reports}
    
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, filename, file_size, created_at 
            FROM pdf_reports 
            WHERE user_id = %s 
            ORDER BY created_at DESC
        """, (user_id,))
        
        reports = []
        for row in cursor.fetchall():
            reports.append({
                "id": row[0],
                "filename": row[1],
                "file_size": row[2],
                "upload_date": row[3].isoformat() if row[3] else datetime.now().isoformat(),
                "analysis_date": row[3].isoformat() if row[3] else datetime.now().isoformat(),
                "download_url": f"/api/download-pdf/{row[0]}"
            })
        
        print(f"📋 Found {len(reports)} PDF reports in database")
        return {"reports": reports}
        
    except Exception as e:
        print(f"PDF reports fetch error: {e}")
        return {"reports": []}
    finally:
        conn.close()

@app.get("/api/download-pdf/{pdf_id}")
async def download_pdf(pdf_id: str, auth: dict = Depends(get_current_auth)):
    """Download PDF report"""
    user_id = auth["user_id"]
    
    print(f"📥 Download request for PDF: {pdf_id} by user: {user_id}")
    
    conn = get_db_conn()
    if not conn:
        # Check in-memory storage
        pdf_reports = uploaded_files.get('pdf_reports', {})
        report_data = pdf_reports.get(pdf_id)
        
        if not report_data or report_data.get('user_id') != user_id:
            raise HTTPException(status_code=404, detail="PDF not found")
        
        pdf_data = report_data.get('pdf_data')
        filename = report_data.get('filename', 'report.pdf')
        
        print(f"✅ PDF found in memory: {len(pdf_data)} bytes")
        
        return Response(
            content=pdf_data,
            media_type='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Length': str(len(pdf_data))
            }
        )
    
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT filename, pdf_data, user_id 
            FROM pdf_reports 
            WHERE id = %s
        """, (pdf_id,))
        
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="PDF not found")
        
        filename, pdf_data, pdf_user_id = row
        
        # Check if user owns this PDF
        if pdf_user_id != user_id:
            raise HTTPException(status_code=403, detail="Access denied")
        
        print(f"✅ PDF found in database: {filename}, {len(pdf_data)} bytes")
        
        return Response(
            content=pdf_data,
            media_type='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Length': str(len(pdf_data))
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"PDF download error: {e}")
        raise HTTPException(status_code=500, detail="Failed to download PDF")
    finally:
        conn.close()
@app.get("/api/debug/verify-pdf-storage")
async def debug_verify_pdf_storage(auth: dict = Depends(get_current_auth)):
    """Verify PDF storage is working"""
    user_id = auth["user_id"]
    
    # Create a test PDF
    from reportlab.pdfgen import canvas
    from io import BytesIO
    
    buffer = BytesIO()
    p = canvas.Canvas(buffer)
    p.drawString(100, 800, "TEST PDF - DataPulse Analysis")
    p.drawString(100, 780, f"User: {user_id}")
    p.drawString(100, 760, f"Time: {datetime.now()}")
    p.drawString(100, 740, "This is a test PDF for verification")
    p.save()
    buffer.seek(0)
    pdf_data = buffer.getvalue()
    
    # Store it
    pdf_id = str(uuid.uuid4())
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    store_success = store_pdf_report(
        user_id=user_id,
        upload_id="debug_test",
        pdf_data=pdf_data,
        filename=f"debug_test_{timestamp}.pdf",
        original_filename="debug_test.pdf"
    )
    
    # Verify
    conn = get_db_conn()
    db_count = 0
    if conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM pdf_reports WHERE user_id = %s", (user_id,))
        db_count = cursor.fetchone()[0]
        conn.close()
    
    return {
        "user_id": user_id,
        "pdf_stored": store_success,
        "pdf_id": pdf_id,
        "pdf_size": len(pdf_data),
        "total_user_pdfs": db_count,
        "message": "Test PDF storage completed"
    }
    
@app.get("/api/debug/db-connection")
async def debug_db_connection():
    """Test database connection with detailed info"""
    import sys
    
    debug_info = {
        "python_version": sys.version,
        "database_library": str(db_lib) if db_lib else "None",
        "connection_string_set": bool(SQL_SERVER_CONN_STR),
        "environment_variables": {
            "DB_HOST": "SET" if os.getenv("DB_HOST") else "NOT SET",
            "DB_PORT": "SET" if os.getenv("DB_PORT") else "NOT SET", 
            "DB_NAME": "SET" if os.getenv("DB_NAME") else "NOT SET",
            "DB_UID": "SET" if os.getenv("DB_UID") else "NOT SET",
            "DB_PWD": "SET" if os.getenv("DB_PWD") else "NOT SET",
        }
    }
    
    # Test connection
    conn = get_db_conn()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT @@VERSION as version")
            version = cursor.fetchone()[0]
            debug_info["connection_test"] = "SUCCESS"
            debug_info["sql_server_version"] = str(version)
            conn.close()
        except Exception as e:
            debug_info["connection_test"] = "FAILED"
            debug_info["error"] = str(e)
    else:
        debug_info["connection_test"] = "NO_CONNECTION"
    
    return debug_info

# ✅ SIGNUP ENDPOINT:
@app.post("/api/auth/signup")
async def signup(request: SignupRequest, response: Response):
    """Ultra-fast user signup"""
    # Quick email validation
    if not request.email or "@" not in request.email:
        raise HTTPException(status_code=400, detail="INVALID_EMAIL")
    
    # Fast existence check
    existing_user = user_by_email(request.email)
    if existing_user:
        raise HTTPException(status_code=409, detail="EMAIL_TAKEN")

    # Quick password validation
    if len(request.password) < 6:
        raise HTTPException(status_code=400, detail="PASSWORD_TOO_SHORT")

    # Fast password hashing with optimized rounds
    pw_hash = bcrypt.hashpw(request.password.encode("utf-8"), bcrypt.gensalt(rounds=10)).decode("utf-8")
    
    # Create user with minimal data
    if not insert_user(request.full_name, request.email, pw_hash):
        raise HTTPException(status_code=400, detail="SIGNUP_FAILED")

    return {
        "success": True, 
        "message": "Signup successful - Please login",
        "redirect_to_login": True
    }

# ✅ LOGIN ENDPOINT:
@app.post("/api/auth/login")
async def login(request: LoginRequest, fastapi_request: Request, response: Response): 
    """High-speed login with minimal overhead"""
    # Quick validation
    if not request.email or not request.password:
        raise HTTPException(status_code=401, detail="INVALID_CREDENTIALS")

    # Fast user lookup
    user = user_by_email_fast(request.email)
    if not user or not user.get("password_hash"):
        raise HTTPException(status_code=401, detail="INVALID_CREDENTIALS")

    # Optimized password verification
    try:
        if not bcrypt.checkpw(request.password.encode("utf-8"), user["password_hash"].encode("utf-8")):
            raise HTTPException(status_code=401, detail="INVALID_CREDENTIALS")
    except Exception:
        raise HTTPException(status_code=401, detail="INVALID_CREDENTIALS")

    # Get client info quickly
    xff = fastapi_request.headers.get("X-Forwarded-For")  
    ip = (xff.split(",")[0].strip() if xff else None)
    ua = fastapi_request.headers.get("User-Agent", "")[:128]  # Only store first 128 chars

    # Create session WITHOUT immediate database update for last_login
    session_id = ensure_session_fast(user["email"], ip, ua)

    # Set cookie with optimized settings
    response.set_cookie(
        key="dp_session_id",
        value=session_id,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=(60 * 60 * 24 * 30) if request.remember else 86400,
        path="/"
    )
    
    # Background update for last login (don't wait for it)
    asyncio.create_task(update_last_login_background(user["email"]))
    
    return {
        "success": True, 
        "message": "Login successful", 
        "session_id": session_id,
        "user_id": user["email"],
        "user_name": user.get("full_name", "User")
    }
    
@app.post("/api/analyze")
async def analyze(
    request: Request,
    response: Response,
    file: UploadFile = File(...),
    auth: dict = Depends(get_current_auth),
):
    """Comprehensive data analysis - WITH DAILY LIMIT ENFORCEMENT"""
    user_id = auth["user_id"]
    session_id = auth["session_id"]

    # ✅ CHECK REPORT ELIGIBILITY
    eligibility = check_report_eligibility(user_id)
    if not eligibility["can_generate"]:
        return JSONResponse(
            status_code=402,
            content={
                "error": "DAILY_LIMIT_REACHED",
                "message": "You've reached your daily report limit",
                "next_available": eligibility["next_available"].isoformat() if eligibility["next_available"] else None,
                "upgrade_url": "/pricing",
                "reason": eligibility["reason"]
            }
        )

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
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large (max 10MB)")

    # Generate upload ID
    timestamp = int(datetime.now().timestamp())
    random_component = str(uuid.uuid4())[:8]
    file_hash = hashlib.sha256(raw).hexdigest()[:16]
    upload_id = f"{timestamp}_{random_component}_{file_hash}"
    
    # Store file in database
    store_success = store_file_in_db(upload_id, raw, file.filename, user_id)
    if not store_success:
        raise HTTPException(status_code=500, detail="Failed to store file")

    # ✅ INCREMENT REPORT COUNT
    increment_report_count(user_id)

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
        date_col = date_cols[0]
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
        "rows_per_day": rows_per_day
    }

    # Generate AI insights and visualizations
    ai_service = AIService()
    detailed_summary = ai_service.generate_detailed_summary(df, None, "executive")
    visualizations = ai_service.recommend_visualizations(df, None)

    return {
        "profiling": profiling,
        "kpis": kpis,
        "charts": visualizations.get("charts", {}),
        "visualizations_metadata": {
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
        "usage_info": {
            "report_used": True,
            "remaining_today": 0,
            "next_report_available": (datetime.now() + timedelta(hours=24)).isoformat()
        }
    }

@app.post("/api/ai-summary")
async def ai_summary(
    request: AISummaryRequest,
    response: Response,
    auth: dict = Depends(get_current_auth),
):
    """Generate AI summary - WITH USAGE CHECK"""
    user_id = auth["user_id"]
    session_id = auth["session_id"]

    # ✅ CHECK REPORT ELIGIBILITY for premium features
    eligibility = check_report_eligibility(user_id)
    if not eligibility["can_generate"] and not eligibility["is_premium"]:
        return JSONResponse(
            status_code=402,
            content={
                "error": "DAILY_LIMIT_REACHED",
                "message": "You've reached your daily report limit",
                "next_available": eligibility["next_available"].isoformat() if eligibility["next_available"] else None,
                "upgrade_url": "/pricing"
            }
        )

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
    file_info = get_file_from_db(request.upload_id, user_id)
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

@app.get("/api/debug/pdf-status")
async def debug_pdf_status(auth: dict = Depends(get_current_auth)):
    """Check PDF storage status"""
    user_id = auth["user_id"]
    
    conn = get_db_conn()
    if not conn:
        return {"database_connection": "failed", "user_id": user_id}
    
    try:
        cursor = conn.cursor()
        
        # Check if pdf_reports table exists and has data
        cursor.execute("SELECT COUNT(*) FROM pdf_reports WHERE user_id = %s", (user_id,))
        user_pdf_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM pdf_reports")
        total_pdf_count = cursor.fetchone()[0]
        
        # Get latest PDFs for this user
        cursor.execute("""
            SELECT id, filename, created_at, file_size 
            FROM pdf_reports 
            WHERE user_id = %s 
            ORDER BY created_at DESC 
            LIMIT 5
        """, (user_id,))
        
        recent_pdfs = []
        for row in cursor.fetchall():
            recent_pdfs.append({
                "id": row[0],
                "filename": row[1],
                "created_at": row[2].isoformat() if row[2] else None,
                "file_size": row[3]
            })
        
        return {
            "database_connection": "success",
            "user_id": user_id,
            "user_pdf_count": user_pdf_count,
            "total_pdf_count": total_pdf_count,
            "recent_pdfs": recent_pdfs
        }
        
    except Exception as e:
        return {"database_connection": "error", "error": str(e)}
    finally:
        conn.close()
        
@app.get("/api/auth/google/callback")
async def google_callback(request: Request, code: str = None):
    """Handle Google OAuth callback with PROPER session management"""
    try:
        if not code:
            print("❌ No code parameter in Google callback")
            return RedirectResponse(f"{FRONTEND_URL}/login?error=no_code")
        
        print(f"🔄 Google OAuth callback received with code: {code[:20]}...")
        
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
                print(f"❌ Token exchange error: {tokens}")
                return RedirectResponse(f"{FRONTEND_URL}/login?error=auth_failed")
            
            # Get user info from Google
            userinfo_response = await client.get(
                'https://www.googleapis.com/oauth2/v3/userinfo',
                headers={'Authorization': f"Bearer {tokens['access_token']}"}
            )
            user_info = userinfo_response.json()
            
            if 'error' in user_info:
                print(f"❌ Userinfo error: {user_info}")
                return RedirectResponse(f"{FRONTEND_URL}/login?error=user_info_failed")
        
        # Extract user data
        email = user_info['email']
        name = user_info.get('name', 'User')
        google_id = user_info['sub']
        
        print(f"✅ Google user authenticated: {email}, {name}, {google_id}")
        
        # Check if user exists by Google ID first
        existing_user = user_by_google_id(google_id)
        
        if not existing_user:
            # Check if user exists by email (merge accounts)
            existing_user = user_by_email(email)
            if existing_user:
                # Update existing user with Google ID
                update_user_google_id(email, google_id)
                print(f"✅ Updated existing user with Google ID: {email}")
            else:
                # Create new Google user
                if not create_google_user(email, name, google_id):
                    print(f"❌ Failed to create Google user: {email}")
                    return RedirectResponse(f"{FRONTEND_URL}/login?error=user_creation_failed")
                existing_user = user_by_google_id(google_id)
                print(f"✅ Created new Google user: {email}")
        
        user_id = existing_user['email']
        
        # Update last login
        update_user_last_login(user_id)
        
        # Get IP and User Agent
        xff = request.headers.get("X-Forwarded-For")
        client_ip = xff.split(",")[0].strip() if xff else request.client.host
        user_agent = request.headers.get("User-Agent", "")[:512]
        
        # 🚨 CRITICAL FIX: Create session WITHOUT deactivating others during OAuth
        session_id = create_oauth_session(user_id, client_ip, user_agent)
        
        print(f"✅ Google OAuth successful for {email}, session: {session_id}")
        
        # 🚨 CRITICAL FIX: Use session parameter instead of cookie for development
        redirect_url = f"{FRONTEND_URL}/analyze?session={session_id}"
        response = RedirectResponse(url=redirect_url, status_code=302)
        
        # 🚨 ALSO set cookie as backup
        response.set_cookie(
            key="dp_session_id",
            value=session_id,
            httponly=True,
            secure=False,  # ✅ FALSE for local development
            samesite="lax",  # ✅ "lax" for localhost
            max_age=30 * 24 * 60 * 60,  # 30 days
            path="/",
        )
        
        print(f"✅ Redirecting to: {redirect_url}")
        return response
        
    except Exception as e:
        print(f"❌ Google OAuth error: {e}")
        import traceback
        traceback.print_exc()
        return RedirectResponse(f"{FRONTEND_URL}/login?error=auth_failed")


# ---------------------------------------------------------
# ✅ USAGE & SESSION MANAGEMENT ROUTES
# ---------------------------------------------------------
@app.get("/api/usage/stats")
async def get_usage_stats_endpoint(auth: dict = Depends(get_current_auth)):
    """Get current user's usage statistics"""
    try:
        user_id = auth["user_id"]
        stats = get_user_report_stats(user_id)
        
        return {
            "can_generate": stats["can_generate"],
            "today_used": stats["today_used"],
            "daily_limit": stats["daily_limit"],
            "is_premium": stats["is_premium"],
            "next_available": stats["next_available"].isoformat() if stats["next_available"] else None,
            "reason": stats["reason"]
        }
        
    except Exception as e:
        print(f"Error in usage stats endpoint: {e}")
        return {
            "can_generate": True,
            "today_used": 0,
            "daily_limit": 1,
            "is_premium": False,
            "next_available": None,
            "reason": "ERROR"
        }

@app.get("/api/auth/me")
async def get_current_user(auth: dict = Depends(get_current_auth)):
    """Get current user info"""
    user_data = user_by_email(auth["user_id"])
    return {
        "success": True,
        "user_id": auth["user_id"],
        "session_id": auth["session_id"],
        "authenticated": True,
        "user_name": user_data.get("full_name") if user_data else "User",
        "email": auth["user_id"],
        "is_premium": user_data.get("is_premium", False) if user_data else False
    }

@app.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    """Enhanced logout with proper session cleanup"""
    sid = request.cookies.get("dp_session_id")
    
    print(f"🚪 Logout requested for session: {sid}")
    
    if sid:
        # Invalidate session in database
        conn = get_db_conn()
        if conn:
            try:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM user_sessions WHERE session_id = %s", (sid,))
                conn.commit()
                conn.close()
                print(f"✅ Session {sid} deleted from database")
            except Exception as e:
                print(f"Session deletion error: {e}")
        
        # Remove from in-memory storage
        if sid in user_sessions:
            del user_sessions[sid]
            print(f"✅ Session {sid} deleted from memory")
    
    # Clear cookie with proper settings
    response.delete_cookie(
        key="dp_session_id",
        path="/",
        secure=True,
        httponly=True,
        samesite="none"
    )
    print("✅ Cookie cleared, logout complete")
    return {"success": True, "message": "Logout successful"}

# ---------------------------------------------------------
# ✅ PAYMENT REDIRECTION ENDPOINT
# ---------------------------------------------------------

@app.get("/api/payment/redirect")
async def payment_redirect(auth: dict = Depends(get_current_auth)):
    """Redirect user to payment page with user context"""
    return {
        "success": True,
        "payment_url": f"/pricing?user_id={auth['user_id']}",
        "user_id": auth['user_id']
    }

# ---------------------------------------------------------
# ✅ DEBUG ROUTES
# ---------------------------------------------------------
@app.get("/api/debug/sessions")
async def debug_sessions():
    """Debug endpoint to see all active sessions"""
    conn = get_db_conn()
    if not conn:
        return {"storage": "in_memory", "sessions": user_sessions}
    
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT session_id, user_id, created_at, last_accessed, expires_at, login_method 
            FROM user_sessions 
            WHERE is_active = 1 AND expires_at > GETDATE()
        """)
        rows = cursor.fetchall()
        sessions = []
        for row in rows:
            sessions.append({
                'session_id': row[0],
                'user_id': row[1],
                'created_at': row[2].isoformat() if row[2] else None,
                'last_accessed': row[3].isoformat() if row[3] else None,
                'expires_at': row[4].isoformat() if row[4] else None,
                'login_method': row[5]
            })
        return {"storage": "database", "sessions": sessions}
    except Exception as e:
        return {"error": str(e), "storage": "in_memory", "sessions": user_sessions}
    finally:
        conn.close()
        
@app.get("/api/test-db")
async def test_db():
    """Test database connection and basic queries"""
    try:
        conn = get_db_conn()
        if not conn:
            return {"status": "error", "message": "No database connection"}
        
        cursor = conn.cursor()
        
        # Test 1: Basic query
        cursor.execute("SELECT @@VERSION as version")
        version = cursor.fetchone()[0]
        
        # Test 2: Check if users table exists
        cursor.execute("SELECT COUNT(*) FROM users")
        users_count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "status": "success",
            "database": "connected", 
            "version": str(version),
            "users_count": users_count
        }
        
    except Exception as e:
        return {"status": "error", "message": str(e)}
    
@app.get("/api/debug/reports")
async def debug_reports():
    """Debug endpoint to see report usage"""
    conn = get_db_conn()
    if not conn:
        return {"storage": "in_memory", "reports": user_reports}
    
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT user_id, report_date, report_count, last_report_at 
            FROM user_reports 
            WHERE report_date >= CAST(GETDATE() AS DATE)
        """)
        rows = cursor.fetchall()
        reports = []
        for row in rows:
            reports.append({
                'user_id': row[0],
                'report_date': row[1].isoformat() if row[1] else None,
                'report_count': row[2],
                'last_report_at': row[3].isoformat() if row[3] else None
            })
        return {"storage": "database", "reports": reports}
    except Exception as e:
        return {"error": str(e), "storage": "in_memory", "reports": user_reports}
    finally:
        conn.close()
        
        
# ✅ ENSURE THIS ENDPOINT EXISTS AND IS OPTIMIZED:
@app.get("/api/auth/quick-check")
async def quick_auth_check(request: Request):
    """Ultra-fast authentication check - minimal overhead"""
    sid = request.cookies.get("dp_session_id")
    
    if not sid:
        return {"authenticated": False}
    
    # Check in-memory first for speed
    if sid in user_sessions:
        session_data = user_sessions[sid]
        return {
            "authenticated": True,
            "user_id": session_data['user_id'],
            "session_id": sid
        }
    
    # Fallback to database (still fast)
    user_email = resolve_user_from_session(sid)
    if not user_email:
        return {"authenticated": False}
    
    return {
        "authenticated": True,
        "user_id": user_email,
        "session_id": sid
    }
    
    # ✅ ADD THIS NEW QUICK LOGIN ENDPOINT:

@app.post("/api/auth/quick-login")
async def quick_login(request: LoginRequest, fastapi_request: Request, response: Response):
    """Minimal login endpoint for maximum speed"""
    # Ultra-fast validation
    if not request.email or not request.password:
        raise HTTPException(status_code=401, detail="INVALID_CREDENTIALS")
    
    user = user_by_email_fast(request.email)
    if not user or not user.get("password_hash"):
        raise HTTPException(status_code=401, detail="INVALID_CREDENTIALS")
    
    # Quick password check
    if not bcrypt.checkpw(request.password.encode("utf-8"), user["password_hash"].encode("utf-8")):
        raise HTTPException(status_code=401, detail="INVALID_CREDENTIALS")
    
    # Fast session creation
    session_id = ensure_session_fast(user["email"], None, None)
    
    # Quick cookie set
    response.set_cookie(
        key="dp_session_id",
        value=session_id,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=86400,
        path="/"
    )
    
    # Return minimal response
    return {
        "success": True,
        "session_id": session_id,
        "user_id": user["email"]
    }
# ---------------------------------------------------------
# ✅ STARTUP EVENT
# ---------------------------------------------------------
@app.on_event("startup")
async def startup_event():
    """Initialize application on startup"""
    print("🚀 DataPulse API starting up...")
    ensure_tables()
    print("✅ Database tables initialized")
    
    # Clean up expired files and sessions
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
            f"THAT EXPLAINS THE COMPLETE DATASET. Audience: {audience}. Business goal: {business_goal or 'general insights'}.\n\n"
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
                "date_columns_count": len(date_cols),
                "analysis_coverage": "100% COMPLETE DATASET"

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
        """IMPORTANT: When recommending visualizations, ensure the data columns exist in the dataset and analyze the complete file
        GIVE COMPLETE AND ACCURATE CHARTS .
        For line charts, recommend datetime or sequential numeric data for x-axis.
        For bar charts, recommend categorical data for x-axis.
        Always specify actual column names that exist in the dataset. """
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
        
        **CRITICAL**: Recommend ONLY charts that work with the ACTUAL data columns provided below AND ANALYZE COMPLETE FILE.

**RULES**:
- STRICT INSTRUCTION -> DON'T SHOW EMPTY CHARTS AT ALL.
- Line charts: ONLY if there are date/time columns + numeric columns
- Bar charts: For categorical vs numeric data  
- Pie charts: ONLY for categorical data (max 6 categories)
- Scatter plots: ONLY if 2+ numeric columns
- If data doesn't support a chart type, DO NOT recommend it

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
                    "max_output_tokens": 2048,   # Response Length Limit
                    "temperature": 0.2           # Control creativity vs consistency
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
                print(f" Successfully parsed date column: {c}")
        except Exception as e:
            print(f"Could not parse column {c} as date: {e}")
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
# ✅ Vercel Handler
# ---------------------------------------------------------
# For Vercel serverless deployment
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)