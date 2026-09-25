"""
Service layer for semantic three-way merges.

Working copies fork from an immutable baseline snapshot and record a
monotonic version + append-only op log.  A MergeTransaction holds the full
BASE/MAIN/WORK payloads and the human resolutions, so a pending conflict
survives a page refresh or a server restart.  Commit is atomic and
idempotent:

  * row lock on the policy's snapshot tip (SELECT ... FOR UPDATE on Postgres,
    a write-transaction on SQLite) while the successor version is allocated;
  * (policy_id, version) unique constraint makes a concurrent double-commit
    lose -- only ONE successor snapshot is ever created;
  * the merge_transactions.committed_snapshot_id partial unique index makes
    re-committing (or two concurrent decisions on) the same transaction
    return the already-created snapshot instead of making a second one.

Neither a failed verification nor an abandon mutates any branch: snapshots
are immutable and the working copy payload is only rewritten on commit
success (or left untouched on abandon).
"""
from __future__ import annotations

import datetime as dt
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import db as dbmod, merge3
from .engine import PolicyError
from .merge3 import build_plan, normalize_payload, render_frr, verify_commit


class MergeError(Exception):
    """User-facing merge error (HTTP 4xx)."""


def _utcnow():
    return dt.datetime.now(dt.timezone.utc)


# ---------------------------------------------------------------------------
# Payload helpers
# ---------------------------------------------------------------------------

def snapshot_body(snap: dbmod.Snapshot) -> dict:
    """A merge-side payload from an immutable snapshot."""
    return snap.payload


def working_body(wc: dbmod.WorkingCopy) -> dict:
    return wc.payload


def policy_tip_snapshot(session: Session, policy_id: int,
                        for_update: bool = False) -> Optional[dbmod.Snapshot]:
    q = select(dbmod.Snapshot).where(
        dbmod.Snapshot.policy_id == policy_id).order_by(
        dbmod.Snapshot.version.desc())
    if for_update:
        q = q.with_for_update()
    return session.scalar(q)


# ---------------------------------------------------------------------------
# Working copies
# ---------------------------------------------------------------------------

def create_working_copy(session: Session, policy_id: int, name: str,
                        base_snapshot_id: Optional[int] = None,
                        editor: str = "lab") -> dbmod.WorkingCopy:
    pol = session.get(dbmod.Policy, policy_id)
    if pol is None:
        raise MergeError("policy not found")
    if session.scalar(select(dbmod.WorkingCopy).where(
            dbmod.WorkingCopy.policy_id == policy_id,
            dbmod.WorkingCopy.name == name,
            dbmod.WorkingCopy.abandoned.is_(False))):
        raise MergeError(f"working copy {name!r} already exists")

    base = (session.get(dbmod.Snapshot, base_snapshot_id)
            if base_snapshot_id else None)
    if base is None:
        base = policy_tip_snapshot(session, policy_id)
    if base is None:
        raise MergeError("policy has no snapshot to fork from")
    if base.policy_id != policy_id:
        raise MergeError("base snapshot belongs to another policy")

    # validate the payload through the merge normalizer once
    body = normalize_payload(base.payload)
    wc = dbmod.WorkingCopy(
        policy_id=policy_id, name=name, editor=editor,
        base_snapshot_id=base.id, version=0,
        payload=body, ops=[{
            "op": "fork", "at": _utcnow().isoformat(),
            "base_snapshot_id": base.id, "base_version": base.version,
        }],
    )
    session.add(wc)
    session.commit()
    session.refresh(wc)
    return wc


def list_working_copies(session: Session, policy_id: int):
    return session.scalars(
        select(dbmod.WorkingCopy)
        .where(dbmod.WorkingCopy.policy_id == policy_id)
        .order_by(dbmod.WorkingCopy.id)).all()


def get_working_copy(session: Session, wc_id: int) -> dbmod.WorkingCopy:
    wc = session.get(dbmod.WorkingCopy, wc_id)
    if wc is None:
        raise MergeError("working copy not found")
    return wc


def _ops_for_replace(old_payload: dict, new_payload: dict) -> List[dict]:
    """Compact structural op record for one whole-body edit save."""
    return [{
        "op": "replace",
        "at": _utcnow().isoformat(),
        "rule_count": len(new_payload.get("rules", [])),
        "before_rule_count": len(old_payload.get("rules", [])),
    }]


def save_working_copy(session: Session, wc_id: int, payload: dict,
                      expected_version: Optional[int] = None,
                      ) -> dbmod.WorkingCopy:
    """
    Apply one edit to the working copy.  Validates through the exact engine
    (ipaddress, family isolation, ge/le) and bumps the monotonic version.
    Optimistic concurrency: callers may require expected_version.
    """
    wc = get_working_copy(session, wc_id)
    if wc.abandoned:
        raise MergeError("working copy has been abandoned")
    if expected_version is not None and expected_version != wc.version:
        raise MergeError(
            f"stale working copy: expected version {expected_version}, "
            f"current is {wc.version}")
    try:
        body = normalize_payload(payload)
    except (PolicyError, ValueError, KeyError) as e:
        raise MergeError(str(e))

    wc.ops = list(wc.ops) + _ops_for_replace(wc.payload, body)
    wc.payload = body
    wc.version = (wc.version or 0) + 1
    session.commit()
    session.refresh(wc)
    return wc


def abandon_working_copy(session: Session, wc_id: int) -> None:
    """Give up a copy.  Never touches a snapshot or another branch."""
    wc = get_working_copy(session, wc_id)
    wc.abandoned = True
    wc.ops = list(wc.ops) + [{
        "op": "abandon", "at": _utcnow().isoformat()}]
    # close any still-open merge transactions for this copy (no snapshot made)
    for tx in session.scalars(select(dbmod.MergeTransaction).where(
            dbmod.MergeTransaction.working_copy_id == wc_id,
            dbmod.MergeTransaction.status == "open")):
        tx.status = "abandoned"
    session.commit()


def working_copy_dict(wc: dbmod.WorkingCopy) -> dict:
    main = None
    return {
        "id": wc.id, "policy_id": wc.policy_id, "name": wc.name,
        "editor": wc.editor,
        "base_snapshot_id": wc.base_snapshot_id,
        "version": wc.version,
        "payload": wc.payload,
        "ops": wc.ops,
        "abandoned": wc.abandoned,
        "main_snapshot_id": main,
        "created_at": wc.created_at.isoformat() if wc.created_at else None,
        "updated_at": wc.updated_at.isoformat() if wc.updated_at else None,
    }


# ---------------------------------------------------------------------------
# Merge transactions
# ---------------------------------------------------------------------------

def _plan_snapshot_dict(tx: dbmod.MergeTransaction, plan_dict: dict) -> dict:
    return {
        "id": tx.id,
        "policy_id": tx.policy_id,
        "working_copy_id": tx.working_copy_id,
        "base_snapshot_id": tx.base_snapshot_id,
        "main_snapshot_id": tx.main_snapshot_id,
        "status": tx.status,
        "resolutions": tx.resolutions,
        "committed_snapshot_id": tx.committed_snapshot_id,
        "created_by": tx.created_by,
        "created_at": tx.created_at.isoformat() if tx.created_at else None,
        "updated_at": tx.updated_at.isoformat() if tx.updated_at else None,
        **plan_dict,
    }


def preview_merge(session: Session, wc_id: int,
                  create_by: str = "lab",
                  reopen_id: Optional[int] = None) -> dict:
    """
    Compute (or reload) the three-way semantic merge for a working copy.

    If the mainline tip advanced since the transaction was opened the plan
    is recomputed against the NEW tip; previously stored human resolutions
    that still apply are preserved.  Open transactions persist across
    restarts (the whole plan is stored).
    """
    wc = get_working_copy(session, wc_id)
    if wc.abandoned:
        raise MergeError("working copy has been abandoned")

    base = session.get(dbmod.Snapshot, wc.base_snapshot_id)
    if base is None:
        raise MergeError("base snapshot disappeared")
    tip = policy_tip_snapshot(session, wc.policy_id)
    if tip is None:
        raise MergeError("mainline has no snapshot")

    tx = None
    prior_resolutions: Dict[str, str] = {}
    if reopen_id is not None:
        tx = session.get(dbmod.MergeTransaction, reopen_id)
        if tx is None or tx.working_copy_id != wc_id:
            raise MergeError("merge transaction not found")
        prior_resolutions = dict(tx.resolutions or {})
        if tx.status == "committed":
            # idempotent re-open: return the already-committed result
            snap = session.get(dbmod.Snapshot, tx.committed_snapshot_id)
            plan = build_plan(tx.base_payload, tx.main_payload,
                              tx.work_payload, snap.payload.get("name", "m"))
            return _plan_snapshot_dict(tx, plan.to_dict(tx.resolutions))

    body_b = normalize_payload(snapshot_body(base))
    body_m = normalize_payload(snapshot_body(tip))
    body_w = normalize_payload(working_body(wc))
    pol = session.get(dbmod.Policy, wc.policy_id)
    plan = build_plan(body_b, body_m, body_w, pol.name)

    # carry over still-valid human choices
    valid_ids = {h["id"] for h in plan.to_dict({})["hunks"]}
    resolutions = {k: v for k, v in prior_resolutions.items()
                   if k in valid_ids and v in ("main", "work")}
    plan_dict = plan.to_dict(resolutions)

    if tx is None:
        tx = dbmod.MergeTransaction(
            policy_id=wc.policy_id, working_copy_id=wc.id,
            base_snapshot_id=base.id, main_snapshot_id=tip.id,
            status="open",
            base_payload=body_b, main_payload=body_m, work_payload=body_w,
            plan=plan_dict, resolutions=resolutions,
            created_by=create_by,
        )
        session.add(tx)
        session.commit()
        session.refresh(tx)
        plan_dict = _with_ids(plan_dict, tx)
    else:
        tx.base_snapshot_id = base.id
        tx.main_snapshot_id = tip.id
        tx.base_payload, tx.main_payload, tx.work_payload = body_b, body_m, body_w
        tx.resolutions = resolutions
        tx.plan = plan_dict
        if tx.status == "abandoned":
            tx.status = "open"
        session.commit()
        session.refresh(tx)
        plan_dict = _with_ids(plan_dict, tx)
    return plan_dict


def _with_ids(plan_dict: dict, tx: dbmod.MergeTransaction) -> dict:
    out = dict(plan_dict)
    out.update({
        "id": tx.id,
        "policy_id": tx.policy_id,
        "working_copy_id": tx.working_copy_id,
        "base_snapshot_id": tx.base_snapshot_id,
        "main_snapshot_id": tx.main_snapshot_id,
        "status": tx.status,
        "committed_snapshot_id": tx.committed_snapshot_id,
        "resolutions": tx.resolutions,
    })
    return out


def get_merge(session: Session, tx_id: int) -> tuple:
    tx = session.get(dbmod.MergeTransaction, tx_id)
    if tx is None:
        raise MergeError("merge transaction not found")
    pol = session.get(dbmod.Policy, tx.policy_id)
    plan = build_plan(tx.base_payload, tx.main_payload,
                      tx.work_payload, pol.name)
    return tx, plan


def get_merge_dict(session: Session, tx_id: int) -> dict:
    tx, plan = get_merge(session, tx_id)
    return _with_ids(plan.to_dict(tx.resolutions or {}), tx)


def decide_merge(session: Session, tx_id: int, resolutions: Dict[str, str]
                 ) -> dict:
    """
    Record human decisions item-by-item (idempotent, per-item).  Two
    concurrent decide calls just overwrite the same key; neither creates a
    snapshot.  Returns the updated plan preview.
    """
    tx, plan = get_merge(session, tx_id)
    if tx.status == "committed":
        return _with_ids(plan.to_dict(tx.resolutions or {}), tx)
    if tx.status == "abandoned":
        raise MergeError("merge transaction has been abandoned")

    valid = {h["id"] for h in plan.to_dict({})["hunks"]}
    current = dict(tx.resolutions or {})
    for hid, side in (resolutions or {}).items():
        if hid not in valid:
            raise MergeError(f"unknown conflict id {hid!r}")
        if side not in ("main", "work"):
            raise MergeError(f"resolution for {hid!r} must be main|work")
        current[hid] = side
    tx.resolutions = current
    plan_dict = plan.to_dict(current)
    tx.plan = plan_dict
    session.commit()
    session.refresh(tx)
    return _with_ids(plan_dict, tx)


def abandon_merge(session: Session, tx_id: int) -> dict:
    """Give up the merge; no snapshot is made, no branch is mutated."""
    tx = session.get(dbmod.MergeTransaction, tx_id)
    if tx is None:
        raise MergeError("merge transaction not found")
    if tx.status == "committed":
        raise MergeError("cannot abandon a committed merge")
    tx.status = "abandoned"
    session.commit()
    session.refresh(tx)
    return {"id": tx.id, "status": tx.status}


# ---------------------------------------------------------------------------
# Atomic commit
# ---------------------------------------------------------------------------

def commit_merge(session: Session, tx_id: int,
                 label: str = "") -> dict:
    """
    Atomically turn a fully-resolved merge into ONE new mainline snapshot.

    Guarantees:
      * every human conflict must be resolved and the WHOLE merged policy
        must satisfy the semantic verifier, otherwise nothing is written;
      * the successor version is allocated under a row lock with a unique
        (policy_id, version) constraint;
      * repeating commit (or two concurrent commits) returns the SAME
        snapshot -- the partial unique index on committed_snapshot_id
        prevents a second successor.
    """
    tx = session.get(dbmod.MergeTransaction, tx_id)
    if tx is None:
        raise MergeError("merge transaction not found")

    # idempotent fast path: already committed -> return the same snapshot
    if tx.status == "committed" and tx.committed_snapshot_id:
        snap = session.get(dbmod.Snapshot, tx.committed_snapshot_id)
        return {
            "id": tx.id, "status": "committed",
            "snapshot": _snapshot_brief(snap),
            "idempotent": True,
        }
    if tx.status == "abandoned":
        raise MergeError("merge transaction has been abandoned")

    pol = session.get(dbmod.Policy, tx.policy_id)
    plan = build_plan(tx.base_payload, tx.main_payload,
                      tx.work_payload, pol.name)
    resolutions = dict(tx.resolutions or {})

    missing = plan.required_resolution_ids()
    missing = [hid for hid in missing if resolutions.get(hid) not in
               ("main", "work")]
    if missing:
        raise MergeError("unresolved conflicts: " + ", ".join(sorted(missing)))

    violations = verify_commit(plan, resolutions)
    if violations:
        raise MergeError({
            "message": "merged policy fails semantic verification",
            "violations": violations,
        })

    merged = normalize_payload(plan.merged_payload(resolutions))
    # one last engine-level validation of the exact assembled body
    for fam, ep in merge3.policies_of_payload(merged, pol.name).items():
        if ep.family is None:
            continue

    # ---- atomic successor allocation under a tip lock -------------------
    tip = (session.query(dbmod.Snapshot)
           .filter_by(policy_id=tx.policy_id)
           .order_by(dbmod.Snapshot.version.desc())
           .with_for_update().first())
    # mainline may have advanced AFTER this preview: the snapshot stored is
    # the merge base's successor; refuse if a different commit landed and
    # the merge was computed against an older tip (caller must re-preview).
    if tip is not None and tip.id != tx.main_snapshot_id and tip.id != tx.base_snapshot_id:
        raise MergeError(
            "mainline advanced while resolving; please re-preview and "
            "re-confirm the decisions")

    frr_config = render_frr(merged, pol.name)
    snap = dbmod.Snapshot(
        policy_id=tx.policy_id,
        version=(tip.version + 1) if tip else 1,
        label=label or f"merge-v{((tip.version + 1) if tip else 1)}",
        payload=_snapshot_payload(pol, merged),
        frr_config=frr_config,
        created_by=tx.created_by,
    )
    session.add(snap)
    try:
        session.flush()              # trips (policy_id, version) on collision
    except IntegrityError:
        session.rollback()
        raise MergeError("concurrent commit: mainline version already taken")

    tx.status = "committed"
    tx.committed_snapshot_id = snap.id
    tx.committed_at = _utcnow()
    tx.plan = plan.to_dict(resolutions)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        # unique committed_snapshot_id won't occur here (fresh tx), but the
        # version collision can: report the lost race
        raise MergeError("concurrent commit: mainline version already taken")
    session.refresh(snap)
    session.refresh(tx)

    # advance the working copy baseline so a later re-merge is incremental,
    # but do NOT delete its in-flight edits payload (it now matches tip).
    wc = session.get(dbmod.WorkingCopy, tx.working_copy_id)
    if wc is not None and not wc.abandoned:
        wc.base_snapshot_id = snap.id
        wc.ops = list(wc.ops) + [{
            "op": "commit", "at": _utcnow().isoformat(),
            "snapshot_id": snap.id, "version": snap.version,
            "merge_transaction_id": tx.id,
        }]
        session.commit()

    return {"id": tx.id, "status": "committed",
            "snapshot": _snapshot_brief(snap), "idempotent": False}


def cross_validate_merge(session: Session, tx_id: int, probes: List[str],
                         node: str = "a",
                         resolutions: Optional[Dict[str, str]] = None) -> dict:
    """
    Run the EXISTING probe/FRR cross-validation harness against the current
    merged preview (or a committed merge result).  Live FRR is used when a
    container is reachable; otherwise the call fails only on the live path.
    """
    from .validate import cross_validate as _cv

    tx, plan = get_merge(session, tx_id)
    res = dict(tx.resolutions or {})
    if resolutions:
        res.update(resolutions)
    merged = normalize_payload(plan.merged_payload(res))
    pol_obj = session.get(dbmod.Policy, tx.policy_id)
    result = {"id": tx.id, "status": tx.status, "frr_available": False,
              "planes": []}
    for fam, pol in merge3.policies_of_payload(merged, pol_obj.name).items():
        fam_probes = [p for p in probes
                      if merge3.canon_prefix(p)[1] == fam]
        if not fam_probes:
            continue
        try:
            from .validate import cross_validate as _cv
            cv = _cv(pol, fam_probes, node=node)
            result["frr_available"] = cv.get("status") != "error"
        except Exception as e:  # live FRR unreachable: return simulation only
            from .validate import _simulate
            sim = _simulate(pol, fam_probes)
            cv = {"node": node, "status": "sim-only",
                  "frr_unavailable": str(e),
                  "probes": fam_probes,
                  "rows": [{"order": s["order"], "prefix": s["prefix"],
                            "sim_action": s["action"], "sim_seq": s["seq"],
                            "frr_action": None, "frr_seq": None,
                            "action_match": None, "seq_match": None}
                           for s in sim],
                  "mismatch_count": 0, "setup_error": None}
        result["planes"].append({"family": fam, **cv})
    return result


def _snapshot_payload(pol: dbmod.Policy, merged: dict) -> dict:
    """Persist the merged body in the snapshot payload format."""
    if merged.get("family") in (4, 6):
        return {
            "name": pol.name, "family": merged["family"],
            "default_action": merged["default_action"],
            "rules": merged["rules"],
        }
    return {
        "name": pol.name, "family": 0,
        "defaults": merged.get("defaults", {}),
        "rules": merged["rules"],
    }


def _snapshot_brief(snap: dbmod.Snapshot) -> dict:
    return {
        "id": snap.id, "policy_id": snap.policy_id,
        "version": snap.version, "label": snap.label,
        "frr_config": snap.frr_config,
        "created_at": snap.created_at.isoformat() if snap.created_at else None,
    }
