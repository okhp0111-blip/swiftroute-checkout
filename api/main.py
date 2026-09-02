import os
import uuid
import hmac
import hashlib
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_headers=["*"],
    allow_methods=["*"],
)

WEBHOOK_SECRET = os.getenv("SWIFTROUTE_WEBHOOK_SECRET", "default_secret_key_12345")

class CheckoutSessionPayload(BaseModel):
    amount: float
    currency: str
    route_id: str

@app.post("/api/v1/checkout/session")
async def create_checkout_session(payload: CheckoutSessionPayload):
    if payload.amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid value.")
    
    session_id = f"sr_sess_{uuid.uuid4().hex[:16]}"
    return {
        "status": "success",
        "session_id": session_id,
        "amount": payload.amount,
        "currency": payload.currency
    }

@app.post("/api/v1/checkout/webhook")
async def handle_checkout_webhook(request: Request, x_swiftroute_signature: str = Header(None)):
    if not x_swiftroute_signature:
        raise HTTPException(status_code=401, detail="Missing signature.")
        
    body = await request.body()
    expected_sig = hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_sig, x_swiftroute_signature):
        raise HTTPException(status_code=403, detail="Invalid signature.")
        
    return {"status": "processed", "acknowledged": True}
