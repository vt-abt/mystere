from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func
from ..db import get_db
from ..models.blobs import Blob, Challenge
from ..security import hex_bytes

router = APIRouter()


class DeleteRequest(BaseModel):
    key: str


@router.post("/delete")
def delete_blob(request: DeleteRequest, db: Session = Depends(get_db)):
    key = hex_bytes(request.key, 32, "storage key")
    removed = db.query(Blob).filter(Blob.storage_key == key).delete()
    db.commit()
    return {"deleted": bool(removed)}

@router.post("/cleanup")
def cleanup(db: Session = Depends(get_db)):
    db.query(Blob).filter(Blob.expires_at < func.now()).delete()
    db.query(Challenge).filter(Challenge.expires_at < func.now()).delete()
    db.commit()
    return {"status": "ok"}
