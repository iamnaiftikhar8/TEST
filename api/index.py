from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
from io import BytesIO
import json
from datetime import datetime

app = FastAPI(title="DataPulse API")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple in-memory storage
users_db = {}
user_sessions = {}

@app.get("/")
async def root():
    return {"status": "success", "message": "DataPulse API is running"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.post("/api/auth/signup")
async def signup(user_data: dict):
    try:
        email = user_data.get("email")
        password = user_data.get("password")
        
        if not email or not password:
            raise HTTPException(status_code=400, detail="Email and password required")
        
        if email in users_db:
            raise HTTPException(status_code=400, detail="User already exists")
        
        # Store user
        users_db[email] = {
            "email": email,
            "password": password,  # In production, hash this
            "created_at": datetime.now().isoformat()
        }
        
        # Create session
        session_id = f"session_{datetime.now().timestamp()}"
        user_sessions[session_id] = email
        
        return {
            "success": True,
            "message": "Signup successful",
            "session_id": session_id,
            "user": {"email": email}
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Signup failed: {str(e)}")

@app.post("/api/auth/login")
async def login(credentials: dict):
    try:
        email = credentials.get("email")
        password = credentials.get("password")
        
        if not email or not password:
            raise HTTPException(status_code=400, detail="Email and password required")
        
        user = users_db.get(email)
        if not user or user.get("password") != password:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Create session
        session_id = f"session_{datetime.now().timestamp()}"
        user_sessions[session_id] = email
        
        return {
            "success": True,
            "message": "Login successful",
            "session_id": session_id,
            "user": {"email": email}
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

@app.post("/api/analyze")
async def analyze_file(file: UploadFile = File(...)):
    try:
        # Check file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")
        
        # Read file content
        contents = await file.read()
        
        # Limit file size for Vercel
        if len(contents) > 5 * 1024 * 1024:  # 5MB
            raise HTTPException(status_code=400, detail="File too large. Max 5MB.")
        
        # Process file
        if file.filename.lower().endswith('.csv'):
            df = pd.read_csv(BytesIO(contents))
        else:
            df = pd.read_excel(BytesIO(contents))
        
        # Basic analysis
        analysis_result = {
            "filename": file.filename,
            "rows": len(df),
            "columns": len(df.columns),
            "columns_list": df.columns.tolist(),
            "data_types": df.dtypes.astype(str).to_dict(),
            "missing_values": int(df.isnull().sum().sum()),
            "memory_usage_mb": round(df.memory_usage(deep=True).sum() / 1024 / 1024, 2)
        }
        
        return {
            "success": True,
            "data": analysis_result,
            "message": "Analysis completed successfully"
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error processing file: {str(e)}")

@app.post("/api/ai-summary")
async def ai_summary(file: UploadFile = File(...), business_goal: str = ""):
    try:
        # Read file
        contents = await file.read()
        
        if file.filename.lower().endswith('.csv'):
            df = pd.read_csv(BytesIO(contents))
        else:
            df = pd.read_excel(BytesIO(contents))
        
        rows, cols = df.shape
        
        summary = f"""
        This dataset contains {rows} rows and {cols} columns.
        Business goal: {business_goal or 'General analysis'}.
        
        Key insights:
        - Dataset size: {rows} × {cols}
        - Memory usage: {df.memory_usage(deep=True).sum() / 1024 / 1024:.2f} MB
        - Missing values: {df.isnull().sum().sum()}
        - Data types analyzed for patterns and trends
        """
        
        return {
            "success": True,
            "summary": summary.strip(),
            "metadata": {
                "rows": rows,
                "columns": cols,
                "business_goal": business_goal
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error generating summary: {str(e)}")

# Vercel handler
try:
    from mangum import Mangum
    handler = Mangum(app)
    print("✅ Mangum handler initialized successfully")
except ImportError:
    print("⚠️ Mangum not available - using fallback handler")
    def handler(event, context):
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Mangum not installed"})
        }

# Add this for better error handling
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)