from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from auth import get_current_user
from database import get_db
from models import User, Vlog
from schemas import VlogCreate, VlogResponse, VlogUpdate

router = APIRouter(prefix="/vlogs", tags=["vlogs"])


@router.get("", response_model=list[VlogResponse])
def list_vlogs(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    vlogs = db.execute(
        select(Vlog).options(joinedload(Vlog.author)).order_by(Vlog.created_at.desc())
    ).scalars().all()
    return vlogs


@router.get("/{vlog_id}", response_model=VlogResponse)
def get_vlog(vlog_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    vlog = db.execute(
        select(Vlog).options(joinedload(Vlog.author)).where(Vlog.id == vlog_id)
    ).scalar_one_or_none()
    if not vlog:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Vlog not found")
    return vlog


@router.post("", response_model=VlogResponse, status_code=status.HTTP_201_CREATED)
def create_vlog(data: VlogCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    vlog = Vlog(
        title=data.title.strip(),
        content=data.content.strip(),
        author_id=current_user.id,
    )
    db.add(vlog)
    db.commit()
    db.refresh(vlog)
    vlog.author = current_user
    return vlog


@router.put("/{vlog_id}", response_model=VlogResponse)
def update_vlog(vlog_id: int, data: VlogUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    vlog = db.get(Vlog, vlog_id)
    if not vlog:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Vlog not found")
    if vlog.author_id != current_user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Not your vlog")

    vlog.title = data.title.strip()
    vlog.content = data.content.strip()
    db.commit()
    db.refresh(vlog)
    vlog.author = current_user
    return vlog


@router.delete("/{vlog_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_vlog(vlog_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    vlog = db.get(Vlog, vlog_id)
    if not vlog:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Vlog not found")
    if vlog.author_id != current_user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Not your vlog")

    db.delete(vlog)
    db.commit()
