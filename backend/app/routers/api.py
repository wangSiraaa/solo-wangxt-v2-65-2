"""HTTP API."""
from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import db as dbmod, service, workcopies
from ..engine import PolicyError
from ..schemas import (
    CandidateValidateIn, ClassifyIn, DiffIn, MergeCommitIn, MergeDiscardIn,
    MergePreviewIn, MergeResolutionIn, NeighborIn, PolicyIn, PolicyRulesIn,
    ProbesIn, ScenarioIn, SnapshotIn, WorkCopyIn, WorkCopyRulesIn,
)
from ..service import ValidationError
from ..treeview import policy_trie, hit_path, coverage_map
from ..validate import cross_validate_snapshot
from ..frr_bridge import FRRBridge, FRRUnavailable
from ..merge import MergeError

router = APIRouter(prefix="/api")


def get_db():
    s = dbmod.SessionLocal()
    try:
        yield s
    finally:
        s.close()


def _get_policy(db: Session, pid: int) -> dbmod.Policy:
    p = db.get(dbmod.Policy, pid)
    if p is None:
        raise HTTPException(404, f"policy {pid} not found")
    return p


@router.get("/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------- policies
@router.get("/policies")
def list_policies(db: Session = Depends(get_db)):
    ps = db.query(dbmod.Policy).order_by(dbmod.Policy.name).all()
    return [service.policy_payload(p) for p in ps]


@router.post("/policies", status_code=201)
def create_policy(body: PolicyIn, db: Session = Depends(get_db)):
    if db.query(dbmod.Policy).filter_by(name=body.name).first():
        raise HTTPException(409, f"policy {body.name!r} already exists")
    try:
        ipaddress.ip_network("0.0.0.0/0" if body.family == 4 else "::/0")
    except ValueError:
        raise HTTPException(422, "bad family")
    p = dbmod.Policy(
        name=body.name, family=body.family,
        default_action=body.default_action, description=body.description,
    )
    db.add(p)
    db.commit()
    db.refresh(p)
    return service.policy_payload(p)


@router.get("/policies/{pid}")
def get_policy(pid: int, db: Session = Depends(get_db)):
    return service.policy_payload(_get_policy(db, pid))


@router.put("/policies/{pid}")
def update_policy_meta(pid: int, body: PolicyIn, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    p.default_action = body.default_action
    p.description = body.description
    db.commit()
    db.refresh(p)
    return service.policy_payload(p)


@router.delete("/policies/{pid}", status_code=204)
def delete_policy(pid: int, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    db.delete(p)
    db.commit()


@router.put("/policies/{pid}/rules")
def set_rules(pid: int, body: PolicyRulesIn, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    if body.default_action is not None:
        p.default_action = body.default_action
    try:
        service.replace_rules(db, p, [r.model_dump() for r in body.rules])
    except (ValidationError, PolicyError, ValueError) as e:
        raise HTTPException(422, str(e))
    db.refresh(p)
    return service.policy_payload(p)


@router.get("/policies/{pid}/analyze")
def analyze(pid: int, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    try:
        return service.analyze(db, p)
    except PolicyError as e:
        raise HTTPException(422, str(e))


@router.post("/policies/{pid}/classify")
def classify(pid: int, body: ClassifyIn, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    ep = service.engine_policy(p)
    try:
        return hit_path(ep, body.prefix)
    except (PolicyError, ValueError) as e:
        raise HTTPException(422, str(e))


@router.post("/policies/{pid}/classify/batch")
def classify_batch(pid: int, body: ProbesIn, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    ep = service.engine_policy(p)
    out = []
    for i, pfx in enumerate(body.probes):
        try:
            d = ep.classify(pfx).to_dict()
            d["order"] = i
            out.append(d)
        except (PolicyError, ValueError) as e:
            out.append({"order": i, "prefix": pfx, "error": str(e)})
    return {"results": out}


@router.get("/policies/{pid}/trie")
def get_trie(pid: int, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    return policy_trie(service.engine_policy(p))


@router.get("/policies/{pid}/coverage")
def get_coverage(pid: int, depth: int = 8,
                 start: int = 0, count: int = 256,
                 db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    depth = max(0, min(depth, 12 if p.family == 4 else 40))
    count = max(1, min(count, 1024))
    return coverage_map(service.engine_policy(p), depth, (start, count))


# -------------------------------------------------------------- snapshots
@router.get("/policies/{pid}/snapshots")
def list_snapshots(pid: int, db: Session = Depends(get_db)):
    _get_policy(db, pid)
    snaps = db.query(dbmod.Snapshot).filter_by(policy_id=pid) \
        .order_by(dbmod.Snapshot.version.desc()).all()
    return [service.snapshot_dict(s) for s in snaps]


@router.post("/policies/{pid}/snapshots", status_code=201)
def take_snapshot(pid: int, body: SnapshotIn, db: Session = Depends(get_db)):
    p = _get_policy(db, pid)
    parent = None
    if body.parent_snapshot_id is not None:
        parent = db.get(dbmod.Snapshot, body.parent_snapshot_id)
        if parent is None or parent.policy_id != pid:
            raise HTTPException(404, "parent snapshot not found")
    snap = service.create_snapshot(db, p, label=body.label,
                                   created_by=body.created_by,
                                   parent_snapshot=parent)
    return service.snapshot_dict(snap)


@router.get("/snapshots/{sid}")
def get_snapshot(sid: int, db: Session = Depends(get_db)):
    s = db.get(dbmod.Snapshot, sid)
    if s is None:
        raise HTTPException(404, "snapshot not found")
    return service.snapshot_dict(s)


@router.post("/snapshots/diff")
def diff_snapshots(body: DiffIn, db: Session = Depends(get_db)):
    try:
        return service.snapshot_diff(db, body.old_snapshot_id, body.new_snapshot_id)
    except (ValidationError, PolicyError) as e:
        raise HTTPException(422, str(e))


@router.post("/snapshots/{sid}/replay")
def replay(sid: int, body: ProbesIn, db: Session = Depends(get_db)):
    try:
        return service.replay(db, sid, body.probes)
    except ValidationError as e:
        raise HTTPException(404, str(e))
    except (PolicyError, ValueError) as e:
        raise HTTPException(422, str(e))


# ----------------------------------------------------------- working copies
@router.post("/policies/{pid}/workcopies", status_code=201)
def create_workcopy(pid: int, body: WorkCopyIn, db: Session = Depends(get_db)):
    _get_policy(db, pid)
    try:
        wc = workcopies.create_workcopy(
            db, pid, body.name, body.base_snapshot_id, body.created_by)
    except workcopies.WorkCopyError as e:
        raise HTTPException(e.status, str(e))
    return workcopies.workcopy_dict(wc, db)


@router.get("/policies/{pid}/workcopies")
def list_workcopies(pid: int, db: Session = Depends(get_db)):
    _get_policy(db, pid)
    wcs = db.query(dbmod.WorkCopy).filter_by(policy_id=pid) \
        .order_by(dbmod.WorkCopy.id).all()
    return [workcopies.workcopy_dict(w, db) for w in wcs]


@router.get("/workcopies/{wid}")
def get_workcopy(wid: int, db: Session = Depends(get_db)):
    try:
        wc = workcopies.get_workcopy(db, wid)
    except workcopies.WorkCopyError as e:
        raise HTTPException(e.status, str(e))
    return workcopies.workcopy_dict(wc, db)


@router.put("/workcopies/{wid}/rules")
def edit_workcopy(wid: int, body: WorkCopyRulesIn, db: Session = Depends(get_db)):
    try:
        wc = workcopies.edit_workcopy(
            db, wid, [r.model_dump() for r in body.rules],
            body.default_action, body.expected_version, body.note)
    except workcopies.WorkCopyError as e:
        raise HTTPException(e.status, str(e))
    return workcopies.workcopy_dict(wc, db)


@router.get("/workcopies/{wid}/operations")
def list_operations(wid: int, db: Session = Depends(get_db)):
    try:
        wc = workcopies.get_workcopy(db, wid)
    except workcopies.WorkCopyError as e:
        raise HTTPException(e.status, str(e))
    return [{"id": o.id, "version": o.version, "operation": o.operation,
             "created_at": o.created_at.isoformat()} for o in wc.operations]


@router.post("/workcopies/{wid}/merge-preview", status_code=201)
def preview_workcopy_merge(wid: int, body: MergePreviewIn,
                           db: Session = Depends(get_db)):
    try:
        ms = workcopies.preview_merge(
            db, wid, body.expected_workcopy_version, body.refresh)
    except workcopies.WorkCopyError as e:
        raise HTTPException(e.status, str(e))
    except (MergeError, PolicyError, ValueError) as e:
        raise HTTPException(422, str(e))
    return workcopies.merge_session_dict(ms)


@router.get("/workcopies/{wid}/merge-sessions")
def list_merge_sessions(wid: int, db: Session = Depends(get_db)):
    try:
        wc = workcopies.get_workcopy(db, wid)
    except workcopies.WorkCopyError as e:
        raise HTTPException(e.status, str(e))
    return [workcopies.merge_session_dict(m) for m in wc.merge_sessions]


@router.get("/merge-sessions/{mid}")
def get_merge_session(mid: int, db: Session = Depends(get_db)):
    try:
        ms = workcopies.get_merge_session(db, mid)
    except workcopies.WorkCopyError as e:
        raise HTTPException(e.status, str(e))
    return workcopies.merge_session_dict(ms)


@router.post("/merge-sessions/{mid}/resolutions")
def resolve_merge_session(mid: int, body: MergeResolutionIn,
                          db: Session = Depends(get_db)):
    try:
        ms = workcopies.resolve_merge(
            db, mid, body.resolutions, body.expected_session_version)
    except workcopies.WorkCopyError as e:
        raise HTTPException(e.status, str(e))
    except (MergeError, PolicyError, ValueError) as e:
        raise HTTPException(422, str(e))
    return workcopies.merge_session_dict(ms)


@router.post("/merge-sessions/{mid}/validate")
def validate_merge_candidate(mid: int, body: CandidateValidateIn,
                             db: Session = Depends(get_db)):
    try:
        return workcopies.validate_candidate(
            db, mid, body.probes, body.node, body.run_frr)
    except workcopies.WorkCopyError as e:
        raise HTTPException(e.status, str(e))
    except (MergeError, PolicyError, ValueError) as e:
        raise HTTPException(422, str(e))


@router.post("/merge-sessions/{mid}/commit", status_code=201)
def commit_merge_session(mid: int, body: MergeCommitIn,
                         db: Session = Depends(get_db)):
    try:
        snap = workcopies.commit_merge(
            db, mid, body.expected_session_version, body.label,
            body.validate_probes, body.node, body.run_frr)
    except workcopies.WorkCopyError as e:
        raise HTTPException(e.status, str(e))
    except (MergeError, PolicyError, ValueError) as e:
        raise HTTPException(422, str(e))
    return service.snapshot_dict(snap)


@router.post("/merge-sessions/{mid}/abandon")
def abandon_merge_session(mid: int, body: MergeDiscardIn,
                          db: Session = Depends(get_db)):
    try:
        return workcopies.abandon_merge(db, mid, body.reason)
    except workcopies.WorkCopyError as e:
        raise HTTPException(e.status, str(e))


@router.delete("/workcopies/{wid}", status_code=204)
def delete_workcopy(wid: int, db: Session = Depends(get_db)):
    try:
        workcopies.delete_workcopy(db, wid)
    except workcopies.WorkCopyError as e:
        raise HTTPException(e.status, str(e))


# ----------------------------------------------------- FRR cross-validation
@router.get("/frr/status")
def frr_status():
    out = {}
    for node in ("a", "b"):
        try:
            ok = FRRBridge(node=node, timeout=4).ping()
        except Exception:
            ok = False
        out[node] = {"reachable": ok}
    return out


@router.post("/snapshots/{sid}/cross-validate")
def cross_validate(sid: int, body: ProbesIn, db: Session = Depends(get_db)):
    s = db.get(dbmod.Snapshot, sid)
    if s is None:
        raise HTTPException(404, "snapshot not found")
    try:
        return cross_validate_snapshot(db, sid, body.probes, node=body.node)
    except FRRUnavailable as e:
        raise HTTPException(503, str(e))
    except (PolicyError, ValueError) as e:
        raise HTTPException(422, str(e))


@router.get("/runs")
def list_runs(limit: int = 50, db: Session = Depends(get_db)):
    runs = db.query(dbmod.Run).order_by(dbmod.Run.created_at.desc()).limit(limit).all()
    return [{
        "id": r.id, "snapshot_id": r.snapshot_id, "node": r.node,
        "status": r.status, "detail": r.detail,
        "created_at": r.created_at.isoformat(),
    } for r in runs]


# --------------------------------------------------------------- neighbors
@router.get("/neighbors")
def list_neighbors(db: Session = Depends(get_db)):
    ns = db.query(dbmod.Neighbor).order_by(dbmod.Neighbor.name).all()
    return [{"id": n.id, "name": n.name, "ip": n.ip, "family": n.family,
             "asn": n.asn, "inbound_policy": n.inbound_policy,
             "outbound_policy": n.outbound_policy, "description": n.description}
            for n in ns]


@router.post("/neighbors", status_code=201)
def create_neighbor(body: NeighborIn, db: Session = Depends(get_db)):
    try:
        net = ipaddress.ip_network(body.ip, strict=False)
    except ValueError as e:
        raise HTTPException(422, f"bad neighbor ip: {e}")
    if net.version != body.family:
        raise HTTPException(422, f"ip family does not match family={body.family}")
    n = dbmod.Neighbor(**body.model_dump())
    db.add(n)
    db.commit()
    db.refresh(n)
    return {"id": n.id, **body.model_dump()}


# --------------------------------------------------------------- scenarios
@router.get("/scenarios")
def list_scenarios(db: Session = Depends(get_db)):
    return [{"id": s.id, "name": s.name, "description": s.description,
             "from_snapshot_id": s.from_snapshot_id,
             "to_snapshot_id": s.to_snapshot_id, "probes": s.probes,
             "results": s.results, "created_at": s.created_at.isoformat()}
            for s in db.query(dbmod.Scenario).order_by(dbmod.Scenario.id).all()]


@router.post("/scenarios", status_code=201)
def create_scenario(body: ScenarioIn, db: Session = Depends(get_db)):
    if db.query(dbmod.Scenario).filter_by(name=body.name).first():
        raise HTTPException(409, f"scenario {body.name!r} exists")
    results = {}
    if body.from_snapshot_id:
        try:
            results["from"] = service.replay(db, body.from_snapshot_id, body.probes)
        except ValidationError:
            pass
    if body.to_snapshot_id:
        try:
            results["to"] = service.replay(db, body.to_snapshot_id, body.probes)
        except ValidationError:
            pass
    sc = dbmod.Scenario(**body.model_dump(), results=results)
    db.add(sc)
    db.commit()
    db.refresh(sc)
    return {"id": sc.id, "name": sc.name, "results": sc.results}


@router.get("/scenarios/{scid}")
def get_scenario(scid: int, db: Session = Depends(get_db)):
    s = db.get(dbmod.Scenario, scid)
    if s is None:
        raise HTTPException(404, "scenario not found")
    return {"id": s.id, "name": s.name, "description": s.description,
            "from_snapshot_id": s.from_snapshot_id,
            "to_snapshot_id": s.to_snapshot_id, "probes": s.probes,
            "results": s.results}


@router.post("/scenarios/{scid}/replay")
def replay_scenario(scid: int, db: Session = Depends(get_db)):
    """Replay the stored ordered inputs against both snapshots deterministically."""
    s = db.get(dbmod.Scenario, scid)
    if s is None:
        raise HTTPException(404, "scenario not found")
    out = {"probes": s.probes, "from": None, "to": None, "diff": None}
    if s.from_snapshot_id:
        out["from"] = service.replay(db, s.from_snapshot_id, s.probes)
    if s.to_snapshot_id:
        out["to"] = service.replay(db, s.to_snapshot_id, s.probes)
    if s.from_snapshot_id and s.to_snapshot_id:
        out["diff"] = service.snapshot_diff(
            db, s.from_snapshot_id, s.to_snapshot_id)
    s.results = out
    db.commit()
    return out
