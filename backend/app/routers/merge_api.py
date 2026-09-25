"""HTTP API for working copies and semantic three-way merges."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import db as dbmod, merge_service as msvc
from ..schemas import (
    MergeCommitIn, MergeDecisionIn, MergePreviewIn, ProbesIn,
    WorkingCopyEditIn, WorkingCopyIn,
)

router = APIRouter(prefix="/api")


def get_db():
    s = dbmod.SessionLocal()
    try:
        yield s
    finally:
        s.close()


def _error(exc: Exception, status: int = 409) -> HTTPException:
    # MergeError may carry a structured body ({message, violations})
    if isinstance(exc.args[0] if exc.args else None, dict):
        return HTTPException(status, exc.args[0])
    return HTTPException(status, str(exc))


# ------------------------------------------------------------ working copies
@router.get("/policies/{pid}/working-copies")
def list_copies(pid: int, db: Session = Depends(get_db)):
    if db.get(dbmod.Policy, pid) is None:
        raise HTTPException(404, "policy not found")
    return [msvc.working_copy_dict(wc)
            for wc in msvc.list_working_copies(db, pid)]


@router.post("/policies/{pid}/working-copies", status_code=201)
def create_copy(pid: int, body: WorkingCopyIn, db: Session = Depends(get_db)):
    try:
        wc = msvc.create_working_copy(
            db, pid, body.name, body.base_snapshot_id, body.editor)
    except msvc.MergeError as e:
        raise _error(e, 404 if "not found" in str(e) else 409)
    return msvc.working_copy_dict(wc)


@router.get("/working-copies/{wid}")
def get_copy(wid: int, db: Session = Depends(get_db)):
    try:
        return msvc.working_copy_dict(msvc.get_working_copy(db, wid))
    except msvc.MergeError as e:
        raise _error(e, 404)


@router.put("/working-copies/{wid}")
def edit_copy(wid: int, body: WorkingCopyEditIn, db: Session = Depends(get_db)):
    try:
        wc = msvc.save_working_copy(
            db, wid, body.payload, body.expected_version)
    except msvc.MergeError as e:
        raise _error(e, 422 if "stale" not in str(e) else 409)
    return msvc.working_copy_dict(wc)


@router.delete("/working-copies/{wid}", status_code=204)
def delete_copy(wid: int, db: Session = Depends(get_db)):
    try:
        msvc.abandon_working_copy(db, wid)
    except msvc.MergeError as e:
        raise _error(e, 404)


# ------------------------------------------------------------- merge preview
@router.post("/merges/preview", status_code=201)
def preview_merge(body: MergePreviewIn, db: Session = Depends(get_db)):
    try:
        return msvc.preview_merge(
            db, body.working_copy_id, body.created_by, body.reopen_id)
    except msvc.MergeError as e:
        raise _error(e, 404 if "not found" in str(e) else 409)


@router.get("/merges/{mid}")
def get_merge(mid: int, db: Session = Depends(get_db)):
    try:
        return msvc.get_merge_dict(db, mid)
    except msvc.MergeError as e:
        raise _error(e, 404)


@router.post("/merges/{mid}/decisions")
def decide_merge(mid: int, body: MergeDecisionIn, db: Session = Depends(get_db)):
    try:
        return msvc.decide_merge(db, mid, body.resolutions)
    except msvc.MergeError as e:
        raise _error(e, 404 if "not found" in str(e) else 422)


@router.post("/merges/{mid}/commit")
def commit_merge(mid: int, body: MergeCommitIn, db: Session = Depends(get_db)):
    try:
        return msvc.commit_merge(db, mid, body.label)
    except msvc.MergeError as e:
        msg = e.args[0] if e.args else str(e)
        if isinstance(msg, dict):
            raise HTTPException(422, msg)
        text = str(e)
        if "unresolved" in text:
            raise HTTPException(409, text)
        if "not found" in text:
            raise HTTPException(404, text)
        if "abandoned" in text:
            raise HTTPException(409, text)
        raise HTTPException(409, text)


@router.post("/merges/{mid}/abandon")
def abandon_merge(mid: int, db: Session = Depends(get_db)):
    try:
        return msvc.abandon_merge(db, mid)
    except msvc.MergeError as e:
        raise _error(e, 404 if "not found" in str(e) else 409)


@router.post("/merges/{mid}/cross-validate")
def merge_cross_validate(mid: int, body: ProbesIn,
                         db: Session = Depends(get_db)):
    try:
        return msvc.cross_validate_merge(db, mid, body.probes,
                                         getattr(body, "node", "a"))
    except msvc.MergeError as e:
        raise _error(e, 404 if "not found" in str(e) else 409)


@router.get("/policies/{pid}/merges")
def list_policy_merges(pid: int, db: Session = Depends(get_db)):
    rows = db.scalars(
        select(dbmod.MergeTransaction)
        .where(dbmod.MergeTransaction.policy_id == pid)
        .order_by(dbmod.MergeTransaction.id.desc())).all()
    return [{
        "id": t.id, "working_copy_id": t.working_copy_id,
        "base_snapshot_id": t.base_snapshot_id,
        "main_snapshot_id": t.main_snapshot_id,
        "status": t.status,
        "committed_snapshot_id": t.committed_snapshot_id,
        "created_by": t.created_by,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    } for t in rows]
