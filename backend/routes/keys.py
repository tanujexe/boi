from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from database import get_db
from schemas import ApiKeyResponse, ApiKeyGeneratedResponse
import services.db_service as db_service

router = APIRouter(prefix="/api/api-keys", tags=["API Keys"])

@router.post("", response_model=ApiKeyGeneratedResponse)
def create_key(name: str, db: Session = Depends(get_db)):
    try:
        new_key = db_service.generate_new_api_key(db, name)
        return new_key
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate API Key: {str(e)}")

@router.get("", response_model=List[ApiKeyResponse])
def get_keys(db: Session = Depends(get_db)):
    return db_service.get_api_keys(db)

@router.delete("/{key_id}")
def revoke_key(key_id: str, db: Session = Depends(get_db)):
    success = db_service.revoke_api_key(db, key_id)
    if not success:
        raise HTTPException(status_code=404, detail="API Key not found.")
    return {"message": "API Key successfully revoked."}
