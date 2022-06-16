from __future__ import annotations
import sys
import datetime
import secrets
import logging
from fastapi import FastAPI, Header, Request, Response, status, Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

class WebhookResponse(BaseModel):
    result: str

class WebhookData(BaseModel):
    receiver: str    

class NGALabels(BaseModel):
    alertname: str
    instance: str

class NGAAnnotations(BaseModel):
    summary: str

class NGAlert(BaseModel):
    status: str
    labels: NGALabels 
    annotations: NGAAnnotations
    startsAt: datetime.datetime
    endsAt: datetime.datetime
    generatorURL: str 
    fingerprint: str
    silenceURL: str 
    dashboardURL: str 
    panelURL: str 
    valueString: str 

class NGAGrafanaOutgoing(BaseModel):
    receiver: str
    status: str
    alerts: list[NGAlert]
    commonLabels: NGALabels
    commonAnnotations: NGAAnnotations
    version: str
    groupKey: str
    externalURL: str
    truncatedAlerts: int
    orgId: int    
    title: str
    state: str    
    message: str    
        

app = FastAPI(
    title       = "Webhook Listener",
    description = "Webhook Listener Alarms",
    version     = "0.1", 
)
security = HTTPBasic()

APP_NAME       = "mg-webhook"
WEBHOOK_SECRET = "XXXXX"

logger = logging.getLogger(APP_NAME)
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(levelname)s: %(asctime)s -  %(message)s")

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(formatter)

logger.addHandler(stdout_handler)

@app.post("/webhook", response_model = WebhookResponse, status_code = status.HTTP_200_OK)
async def webhook(
    webhook_input: NGAGrafanaOutgoing,
    request: Request, 
    response: Response,
    credentials: HTTPBasicCredentials = Depends(security),
    content_length: int = Header(...),    
):
    check_username = secrets.compare_digest(credentials.username, "admin")
    check_password = secrets.compare_digest(credentials.password, "password")
    if not ( check_username and check_password):
        logger.error("Incorrect email or password")
        raise HTTPException( 
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Incorrect email or password", 
            headers={"WWW-Authenticate": "Basic"},)        
    if content_length > 1_000_000:
        logger.error("Content too long")
        raise HTTPException(
            status_code = status.HTTP_400_BAD_REQUEST,
            detail="Content too long",
        )        
    
    logger.info(await request.body())    
    logger.info(f"Receiver: {(webhook_input.receiver)}")
    logger.info(f"Status: {(webhook_input.status)}")    
    
    
    return {"result": "ok",}