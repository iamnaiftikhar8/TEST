from fastapi import FastAPI
import json

app = FastAPI()

@app.get("/")
async def root():
    return {"status": "ok", "message": "DataPulse API is working"}

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": "2024-01-01T00:00:00Z"}

# Vercel handler - SIMPLIFIED
try:
    from mangum import Mangum
    handler = Mangum(app)
    print("Mangum handler initialized")
except Exception as e:
    print(f"Mangum error: {e}")
    def handler(event, context):
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "*",
                "Access-Control-Allow-Headers": "*"
            },
            "body": json.dumps({"message": "Fallback handler", "event": event})
        }