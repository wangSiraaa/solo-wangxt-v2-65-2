"""Durable working copies and atomic semantic three-way commits."""
from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import db as dbmod, service
from .engine import PolicyError, policy_from_dicts
from .merge import (
    MergeError, analyze_three_way, candidate_from_resolution, normalize_payload,
    side_from_snapshot,
)
from .validate import cross_validate


class WorkCopyError(ValueError):
    def __init__(self, message: str, status: int = 422):
        super().__init__(message)
        self.status = status


def _rule_dict(r: dbmod.Rule) -> dict:
    return {
        "rid": r.rid, "seq": r.seq, "prefix": r.prefix,
        "action": r.action, "ge": r.ge, "le": r.le, "remark": r.remark or "",
    }


def payload_from_policy(policy: dbmod.Policy) -> dict:
    return {
        "name": policy.name,
        "family": policy.family,
        "default_action": policy.default_action,
        "rules": [_rule_dict(r) for r in policy.rules],
    }


def payload_from_snapshot(snap: dbmod.Snapshot) -> dict:
    side = side_from_snapshot(snap)
    return side.payload(snap.payload["name"], snap.payload["family"])


def workcopy_dict(wc: dbmod.WorkCopy, session: Optional[Session] = None) -> dict:
    main = latest_snapshot_id(session, wc.policy_id) if session else None
    return {
        "id": wc.id,
        "policy_id": wc.policy_id,
        "name": wc.name,
        "created_by": wc.created_by,
        "base_snapshot_id": wc.base_snapshot_id,
        "latest_snapshot_id": main,
        "current_payload": wc.current_payload,
        "version": wc.version,
        "status": wc.status,
        "committed_snapshot_id": wc.committed_snapshot_id,
        "created_at": wc.created_at.isoformat(),
        "updated_at": wc.updated_at.isoformat() if wc.updated_at else None,
    }


def merge_session_dict(ms: dbmod.MergeSession) -> dict:
    return {
        "id": ms.id,
        "workcopy_id": ms.workcopy_id,
        "base_snapshot_id": ms.base_snapshot_id,
        "main_snapshot_id": ms.main_snapshot_id,
        "status": ms.status,
        "version": ms.version,
        "analysis": ms.analysis,
        "resolutions": ms.resolutions,
        "candidate_payload": ms.candidate_payload,
        "committed_snapshot_id": ms.committed_snapshot_id,
        "created_at": ms.created_at.isoformat(),
        "updated_at": ms.updated_at.isoformat() if ms.updated_at else None,
    }


def latest_snapshot(session: Session, policy_id: int,
                    lock: bool = False) -> Optional[dbmod.Snapshot]:
    stmt = select(dbmod.Snapshot).where(
        dbmod.Snapshot.policy_id == policy_id
    ).order_by(dbmod.Snapshot.version.desc())
    if lock and session.bind.dialect.name != "sqlite":
        stmt = stmt.with_for_update()
    return session.scalars(stmt).first()


def latest_snapshot_id(session: Session, policy_id: int) -> Optional[int]:
    s = latest_snapshot(session, policy_id)
    return s.id if s else None


def get_policy(session: Session, policy_id: int) -> dbmod.Policy:
    p = session.get(dbmod.Policy, policy_id)
    if p is None:
        raise WorkCopyError("policy not found", 404)
    return p


def get_workcopy(session: Session, wc_id: int,
                 lock: bool = False) -> dbmod.WorkCopy:
    wc = session.get(dbmod.WorkCopy, wc_id)
    if lock and session.bind.dialect.name != "sqlite":
        session.refresh(wc, with_for_update=True)
    if wc is None:
        raise WorkCopyError("working copy not found", 404)
    return wc


def get_merge_session(session: Session, ms_id: int,
                      lock: bool = False) -> dbmod.MergeSession:
    ms = session.get(dbmod.MergeSession, ms_id)
    if lock and session.bind.dialect.name != "sqlite":
        session.refresh(ms, with_for_update=True)
    if ms is None:
        raise WorkCopyError("merge session not found", 404)
    return ms


def create_workcopy(session: Session, policy_id: int, name: str,
                    base_snapshot_id: Optional[int],
                    created_by: str = "lab") -> dbmod.WorkCopy:
    policy = get_policy(session, policy_id)
    if session.scalar(select(dbmod.WorkCopy).where(
            dbmod.WorkCopy.policy_id == policy_id,
            dbmod.WorkCopy.name == name)):
        raise WorkCopyError("working copy name already exists", 409)

    if base_snapshot_id is None:
        base = latest_snapshot(session, policy_id)
        if base is None:
            base = service.create_snapshot(session, policy, label="baseline",
                                           created_by=created_by)
    else:
        base = session.get(dbmod.Snapshot, base_snapshot_id)
        if base is None or base.policy_id != policy_id:
            raise WorkCopyError("baseline snapshot not found", 404)

    wc = dbmod.WorkCopy(
        policy_id=policy_id, name=name, created_by=created_by,
        base_snapshot_id=base.id, current_payload=payload_from_snapshot(base),
        version=0, status="active",
    )
    session.add(wc)
    session.flush()
    session.add(dbmod.WorkCopyOp(
        workcopy_id=wc.id, version=0,
        operation={"type": "checkout", "snapshot_id": base.id,
                   "snapshot_version": base.version},
    ))
    session.commit()
    session.refresh(wc)
    return wc


def edit_workcopy(session: Session, wc_id: int, rules: list[dict],
                  default_action: Optional[str], expected_version: int,
                  note: str = "") -> dbmod.WorkCopy:
    wc = get_workcopy(session, wc_id, lock=True)
    if wc.status != "active":
        raise WorkCopyError(f"working copy is {wc.status}", 409)
    if wc.version != expected_version:
        raise WorkCopyError(
            f"stale edit: expected workcopy v{wc.version}, got v{expected_version}",
            409)
    policy = get_policy(session, wc.policy_id)
    try:
        service.validate_rule_dicts(policy.family, rules)
    except (service.ValidationError, PolicyError, ValueError) as e:
        raise WorkCopyError(str(e), 422)

    payload = dict(wc.current_payload)
    if default_action is not None:
        payload["default_action"] = default_action
    # normalize via merge side, but preserve supplied rid and seq
    side = normalize_payload(
        {"name": policy.name, "family": policy.family,
         "default_action": payload.get("default_action", policy.default_action),
         "rules": rules}, family=policy.family)
    payload = side.payload(policy.name, policy.family)

    wc.version += 1
    wc.current_payload = payload
    session.add(dbmod.WorkCopyOp(
        workcopy_id=wc.id, version=wc.version,
        operation={"type": "replace_rules", "note": note,
                   "default_action": payload["default_action"],
                   "rules": payload["rules"]},
    ))
    # Any earlier preview is now stale and cannot be committed.
    for ms in session.scalars(select(dbmod.MergeSession).where(
            dbmod.MergeSession.workcopy_id == wc.id,
            dbmod.MergeSession.status.in_(["ready", "equivalent", "conflict",
                                           "resolved"]))):
        ms.status = "stale"
    try:
        session.commit()
    except IntegrityError as e:
        session.rollback()
        raise WorkCopyError("concurrent edit rejected", 409) from e
    session.refresh(wc)
    return wc


def preview_merge(session: Session, wc_id: int,
                  expected_workcopy_version: Optional[int] = None,
                  refresh: bool = False) -> dbmod.MergeSession:
    wc = get_workcopy(session, wc_id, lock=True)
    if wc.status != "active":
        raise WorkCopyError(f"working copy is {wc.status}", 409)
    if expected_workcopy_version is not None and \
            wc.version != expected_workcopy_version:
        raise WorkCopyError("stale preview request", 409)

    existing = session.scalars(select(dbmod.MergeSession).where(
        dbmod.MergeSession.workcopy_id == wc.id,
        dbmod.MergeSession.status.in_(["ready", "equivalent", "conflict",
                                       "resolved"])
    ).order_by(dbmod.MergeSession.id.desc())).first()
    if existing is not None and not refresh and \
            existing.analysis.get("workcopy_version") == wc.version:
        return existing

    policy = get_policy(session, wc.policy_id)
    base = session.get(dbmod.Snapshot, wc.base_snapshot_id)
    main = latest_snapshot(session, wc.policy_id, lock=True)
    if base is None or main is None:
        raise WorkCopyError("baseline or mainline snapshot missing", 409)

    if existing is not None:
        # Retain human decisions only when the same merge is refreshed.
        same_lines = existing.base_snapshot_id == base.id and \
            existing.main_snapshot_id == main.id
        old_resolutions = existing.resolutions if same_lines else {}
        existing.status = "superseded"
    else:
        old_resolutions = {}

    analysis = analyze_three_way(session, policy, base, main, wc)
    ms = dbmod.MergeSession(
        workcopy_id=wc.id, base_snapshot_id=base.id, main_snapshot_id=main.id,
        status=analysis["status"], version=1, analysis=analysis,
        resolutions={}, candidate_payload=analysis.get("candidate_payload"),
    )
    session.add(ms)
    session.flush()
    if analysis["status"] == "conflict" and old_resolutions:
        try:
            cand, errors = candidate_from_resolution(policy, analysis,
                                                     old_resolutions)
        except Exception:
            errors = ["previous resolutions no longer apply"]
            cand = None
        if not errors and cand is not None:
            ms.resolutions = old_resolutions
            ms.candidate_payload = cand.payload(policy.name, policy.family)
            ms.status = "resolved"
    try:
        session.commit()
    except IntegrityError as e:
        session.rollback()
        raise WorkCopyError("concurrent preview rejected", 409) from e
    session.refresh(ms)
    return ms


def resolve_merge(session: Session, ms_id: int, resolutions: dict[str, str],
                  expected_version: int) -> dbmod.MergeSession:
    ms = get_merge_session(session, ms_id, lock=True)
    if ms.status not in ("conflict", "resolved"):
        raise WorkCopyError(f"merge session is {ms.status}", 409)
    if ms.version != expected_version:
        raise WorkCopyError("stale conflict resolution", 409)
    policy = get_policy(session, ms.workcopy.policy_id)
    candidate, errors = candidate_from_resolution(
        policy, ms.analysis, resolutions)
    if errors:
        raise WorkCopyError("; ".join(errors), 422)
    ms.resolutions = dict(resolutions)
    ms.candidate_payload = candidate.payload(policy.name, policy.family)
    ms.status = "resolved"
    ms.version += 1
    session.commit()
    session.refresh(ms)
    return ms


def _simulate_payload(policy: dbmod.Policy, payload: dict,
                      probes: list[str]) -> list[dict]:
    ep = policy_from_dicts(
        payload["name"], payload["rules"],
        default_action=payload["default_action"], family=payload["family"])
    rows = []
    for i, pfx in enumerate(probes):
        h = ep.classify(pfx).to_dict()
        rows.append({"order": i, "prefix": pfx, "action": h["final_action"],
                     "seq": h["matched_seq"], "terminal": h["terminal"],
                     "chain": h["chain"]})
    return rows


def validate_candidate(session: Session, ms_id: int, probes: list[str],
                       node: str = "a", run_frr: bool = False) -> dict:
    ms = get_merge_session(session, ms_id)
    payload = ms.candidate_payload
    if payload is None:
        raise WorkCopyError("no resolved merge candidate to validate", 409)
    policy = get_policy(session, ms.workcopy.policy_id)
    ep = policy_from_dicts(
        payload["name"], payload["rules"],
        default_action=payload["default_action"], family=payload["family"])
    simulation = _simulate_payload(policy, payload, probes)
    frr = None
    if run_frr:
        from .frr_bridge import FRRUnavailable
        try:
            frr = cross_validate(ep, probes, node=node)
        except FRRUnavailable as e:
            raise WorkCopyError(f"local FRR validation unavailable: {e}", 503)
        except Exception as e:
            # No snapshot/run was written; report temporary external failure.
            raise WorkCopyError(f"local FRR validation failed: {e}", 503)
    return {"status": "ok" if not frr or frr["status"] == "match" else "mismatch",
            "simulation": simulation, "frr": frr}


def _replace_policy_from_payload(session: Session, policy: dbmod.Policy,
                                 payload: dict) -> None:
    session.query(dbmod.Rule).filter_by(policy_id=policy.id).delete(
        synchronize_session=False)
    session.flush()
    session.expire_all()
    policy = session.get(dbmod.Policy, policy.id)
    policy.default_action = payload["default_action"]
    for d in sorted(payload["rules"], key=lambda x: int(x["seq"])):
        policy.rules.append(dbmod.Rule(
            rid=d["rid"], seq=int(d["seq"]), prefix=d["prefix"],
            action=d["action"], ge=d.get("ge"), le=d.get("le"),
            remark=d.get("remark", ""),
        ))
    policy.rules.sort(key=lambda r: r.seq)


def commit_merge(session: Session, ms_id: int, expected_version: int,
                 label: str = "", validate_probes: Optional[list[str]] = None,
                 node: str = "a", run_frr: bool = False) -> dbmod.Snapshot:
    ms = get_merge_session(session, ms_id, lock=True)
    wc = get_workcopy(session, ms.workcopy_id, lock=True)

    # Idempotent success: retries/concurrent duplicate calls return the one
    # successor already produced and never create another version.
    if ms.committed_snapshot_id is not None:
        snap = session.get(dbmod.Snapshot, ms.committed_snapshot_id)
        return snap
    if wc.committed_snapshot_id is not None:
        return session.get(dbmod.Snapshot, wc.committed_snapshot_id)
    if ms.status not in ("ready", "equivalent", "resolved"):
        raise WorkCopyError(f"merge is {ms.status}; cannot commit", 409)
    if ms.version != expected_version and ms.status != "resolved":
        raise WorkCopyError("stale merge commit", 409)
    if ms.status == "resolved" and ms.version != expected_version:
        raise WorkCopyError("stale merge commit", 409)

    policy = get_policy(session, wc.policy_id)
    main = latest_snapshot(session, policy.id, lock=True)
    if main is None or main.id != ms.main_snapshot_id:
        raise WorkCopyError("mainline changed after preview; preview again", 409)
    payload = ms.candidate_payload
    if payload is None:
        raise WorkCopyError("merge candidate missing", 409)
    try:
        candidate_policy = policy_from_dicts(
            payload["name"], payload["rules"],
            default_action=payload["default_action"], family=payload["family"])
    except (PolicyError, ValueError) as e:
        raise WorkCopyError(str(e), 422)

    validation = None
    if validate_probes:
        validation = _simulate_payload(policy, payload, validate_probes)
        if run_frr:
            from .frr_bridge import FRRUnavailable
            try:
                frr = cross_validate(candidate_policy, validate_probes,
                                     node=node)
            except FRRUnavailable as e:
                raise WorkCopyError(f"local FRR validation unavailable: {e}", 503)
            except Exception as e:
                raise WorkCopyError(f"local FRR validation failed: {e}", 503)
            if frr["status"] != "match":
                raise WorkCopyError(
                    "FRR validation failed; merge transaction not started", 422)

    try:
        _replace_policy_from_payload(session, policy, payload)
        session.flush()
        policy = session.get(dbmod.Policy, policy.id)
        ep = service.engine_policy(policy)
        latest = latest_snapshot(session, policy.id, lock=True)
        version = (latest.version + 1) if latest else 1
        snap = dbmod.Snapshot(
            policy_id=policy.id, parent_id=main.id, version=version,
            label=label or f"v{version}", payload=payload,
            frr_config=ep.to_frr_prefix_list(),
            created_by=wc.created_by, created_by_workcopy_id=wc.id,
            merge_info={
                "kind": "three_way",
                "base_snapshot_id": ms.base_snapshot_id,
                "main_snapshot_id": ms.main_snapshot_id,
                "workcopy_id": wc.id,
                "merge_session_id": ms.id,
                "resolutions": ms.resolutions,
                "validated_probes": validate_probes or [],
            },
        )
        session.add(snap)
        session.flush()
        ms.committed_snapshot_id = snap.id
        ms.status = "committed"
        wc.committed_snapshot_id = snap.id
        wc.status = "committed"
        session.commit()
    except IntegrityError as e:
        session.rollback()
        raise WorkCopyError("concurrent commit produced another version", 409) from e
    except Exception:
        session.rollback()
        raise
    session.refresh(snap)
    return snap


def abandon_merge(session: Session, ms_id: int, reason: str = "") -> dict:
    ms = get_merge_session(session, ms_id, lock=True)
    if ms.status in ("committed", "abandoned"):
        return merge_session_dict(ms)
    ms.status = "abandoned"
    ms.analysis = dict(ms.analysis or {})
    ms.analysis["abandon_reason"] = reason
    ms.candidate_payload = None
    session.commit()
    session.refresh(ms)
    return merge_session_dict(ms)


def delete_workcopy(session: Session, wc_id: int) -> None:
    wc = get_workcopy(session, wc_id)
    if wc.status == "committed" and wc.committed_snapshot_id:
        raise WorkCopyError("committed working copy is retained as history", 409)
    session.delete(wc)
    session.commit()
