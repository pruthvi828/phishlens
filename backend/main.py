
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title="PhishGuard AI API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5500",
        "http://127.0.0.1:5500",
    ],
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type"],
)

class AnalyzeRequest(BaseModel):
    sender: str = Field(default="", max_length=200)
    message: str = Field(min_length=1, max_length=5000)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/analyze")
def analyze(request: AnalyzeRequest):
    # Replace this example with Parth's real detection engine.
    # Do not ship a hardcoded score as real analysis.

    from detector import analyze_message

    return analyze_message(
        sender=request.sender,
        message=request.message,
    )
