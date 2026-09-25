"""Semantic three-way merge for immutable first-match prefix-list policies.

The merge never compares rendered text to decide conflicts.  It uses the
existing exact trie witness algorithm on the permit/deny functions of base,
mainline and a private working copy.  Stable rule identities make ordinary
disjoint edits auto-mergeable; remarks and other behavior-preserving rewrites
are classified as semantic equivalents rather than conflicts.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from sqlalchemy.orm import Session

from . import db as dbmod
from .engine import Action, Policy, PolicyError, Rule, policy_from_dicts
from .trie import minimal_witness_set


class MergeError(ValueError):
    pass


@dataclass(frozen=True)
class SideRule:
    rid: str
    seq: int
    prefix: str
    action: str
    ge: Optional[int]
    le: Optional[int]
    remark: str

    def dict(self) -> dict[str, Any]:
        return {
            "rid": self.rid, "seq": self.seq, "prefix": self.prefix,
            "action": self.action, "ge": self.ge, "le": self.le,
            "remark": self.remark,
        }

    def engine_dict(self) -> dict[str, Any]:
        d = self.dict()
        d.pop("rid")
        d["id"] = self.rid
        return d

    @property
    def semantic_key(self) -> tuple:
        return (self.prefix, self.action, self.ge, self.le)

    @property
    def text_key(self) -> tuple:
        return (self.prefix, self.action, self.ge, self.le, self.remark)


@dataclass
class Side:
    snapshot_id: Optional[int]
    version: Optional[int]
    label: str
    default_action: str
    rules: list[SideRule]

    @property
    def order(self) -> list[str]:
        return [r.rid for r in self.rules]

    def by_id(self) -> dict[str, SideRule]:
        return {r.rid: r for r in self.rules}

    def policy(self, name: str, family: int) -> Policy:
        return policy_from_dicts(
            name, [r.engine_dict() for r in self.rules],
            default_action=self.default_action, family=family,
        )

    def payload(self, name: str, family: int) -> dict:
        return {
            "name": name,
            "family": family,
            "default_action": self.default_action,
            "rules": [r.dict() for r in self.rules],
        }


def _stable_legacy_rid(rule: dict, occurrence: int) -> str:
    raw = "|".join(str(x) for x in (
        rule.get("prefix"), rule.get("action"), rule.get("ge"), rule.get("le"),
        occurrence,
    ))
    return "legacy-" + hashlib.sha1(raw.encode()).hexdigest()[:16]


def normalize_payload(payload: dict, family: Optional[int] = None,
                      snapshot_id: Optional[int] = None,
                      version: Optional[int] = None,
                      label: str = "") -> Side:
    """Validate a payload and make every rule carry a stable rid."""
    fam = payload.get("family", family)
    if family is not None and fam != family:
        raise MergeError("address family mismatch")
    rules_in = list(payload.get("rules", []))

    # Engine validation happens before assigning synthetic ids.
    policy_from_dicts(
        payload.get("name", "candidate"), rules_in,
        default_action=payload.get("default_action", "deny"), family=fam,
    )

    legacy_counts: dict[tuple, int] = {}
    seen_rids: set[str] = set()
    out: list[SideRule] = []
    for d in rules_in:
        rid = d.get("rid")
        if not rid:
            key = (d.get("prefix"), d.get("action"), d.get("ge"), d.get("le"))
            occurrence = legacy_counts.get(key, 0)
            legacy_counts[key] = occurrence + 1
            rid = _stable_legacy_rid(d, occurrence)
        if rid in seen_rids:
            raise MergeError(f"duplicate stable rule identity {rid}")
        seen_rids.add(rid)
        out.append(SideRule(
            rid=str(rid), seq=int(d["seq"]), prefix=d["prefix"],
            action=Action(d["action"]).value, ge=d.get("ge"), le=d.get("le"),
            remark=d.get("remark", "") or "",
        ))
    return Side(
        snapshot_id=snapshot_id, version=version, label=label,
        default_action=Action(payload.get("default_action", "deny")).value,
        rules=out,
    )


def side_from_snapshot(snap: dbmod.Snapshot) -> Side:
    return normalize_payload(
        snap.payload, snapshot_id=snap.id, version=snap.version, label=snap.label)


def _witness_dict(pol_old: Policy, pol_new: Policy) -> dict[str, Witness]:
    return {w.prefix: w for w in minimal_witness_set(pol_old, pol_new)}


def _chain_for(policy: Policy, prefix: str) -> dict:
    return policy.classify(prefix).to_dict()


def _hit(policy: Policy, prefix: str) -> dict:
    h = policy.classify(prefix)
    return {
        "prefix": prefix,
        "action": h.final_action.value,
        "seq": h.rule.seq if h.rule else None,
        "rid": getattr(h.rule, "id", None) if h.rule else None,
        "chain": h.to_dict()["chain"],
    }


# Decision markers
UNCHANGED = "unchanged"
EQUIVALENT = "semantic_equivalent"
ADOPT_MAIN = "adopt_main"
ADOPT_COPY = "adopt_copy"
ADOPT_BOTH = "adopt_both"
CONFLICT = "conflict"
ADDED_MAIN = "added_main"
ADDED_COPY = "added_copy"
ADDED_BOTH = "added_both"
DELETED_MAIN = "deleted_main"
DELETED_COPY = "deleted_copy"


def _rule_entry(rule: Optional[SideRule]) -> Optional[dict]:
    return rule.dict() if rule else None


def _structural_analysis(base: Side, main: Side, copy: Side) -> tuple[list[dict], list[dict], set[str], bool]:
    b, m, c = base.by_id(), main.by_id(), copy.by_id()
    decisions: list[dict] = []
    conflicts: list[dict] = []
    conflict_rids: set[str] = set()

    def add_conflict(key: str, kind: str, br: Optional[SideRule],
                     mr: Optional[SideRule], cr: Optional[SideRule]) -> None:
        conflicts.append({
            "key": key, "kind": kind,
            "base": _rule_entry(br), "main": _rule_entry(mr),
            "copy": _rule_entry(cr), "options": ["main", "copy"],
        })

    all_ids = list(dict.fromkeys(base.order + main.order + copy.order))
    paired_new_main: set[str] = set()
    paired_new_copy: set[str] = set()

    # Pair independently-added rules that have identical semantics.  This is
    # deliberately done by semantic content; a remark difference is equivalent.
    new_m = [m[i] for i in main.order if i not in b and i not in c]
    new_c = [c[i] for i in copy.order if i not in b and i not in m]
    paired_adds: list[tuple[SideRule, SideRule]] = []
    used_c: set[str] = set()
    for mr in new_m:
        for cr in new_c:
            if cr.rid in used_c:
                continue
            if mr.semantic_key == cr.semantic_key:
                paired_adds.append((mr, cr))
                paired_new_main.add(mr.rid)
                paired_new_copy.add(cr.rid)
                used_c.add(cr.rid)
                break

    for rid in all_ids:
        br, mr, cr = b.get(rid), m.get(rid), c.get(rid)
        if br is not None:
            if mr is not None and cr is not None:
                if mr.text_key == cr.text_key == br.text_key:
                    decision = UNCHANGED
                elif mr.text_key == br.text_key and cr.text_key == br.text_key:
                    decision = UNCHANGED
                elif mr.semantic_key == cr.semantic_key == br.semantic_key:
                    decision = EQUIVALENT
                elif mr.text_key == br.text_key:
                    decision = ADOPT_COPY
                elif cr.text_key == br.text_key:
                    decision = ADOPT_MAIN
                elif mr.text_key == cr.text_key:
                    # Both made the same textual/semantic edit.
                    decision = ADOPT_MAIN
                elif mr.semantic_key == cr.semantic_key:
                    decision = EQUIVALENT
                else:
                    decision = CONFLICT
                    conflict_rids.add(rid)
                    add_conflict(f"rule:{rid}", "rule", br, mr, cr)
                decisions.append({"key": f"rule:{rid}", "kind": "rule",
                                  "decision": decision,
                                  "base": _rule_entry(br), "main": _rule_entry(mr),
                                  "copy": _rule_entry(cr)})
            elif mr is None and cr is not None:
                if cr.text_key == br.text_key:
                    decision = DELETED_MAIN
                else:
                    decision = CONFLICT
                    conflict_rids.add(rid)
                    add_conflict(f"rule:{rid}", "delete-modify", br, None, cr)
                decisions.append({"key": f"rule:{rid}", "kind": "rule",
                                  "decision": decision,
                                  "base": _rule_entry(br), "main": None,
                                  "copy": _rule_entry(cr)})
            elif mr is not None and cr is None:
                if mr.text_key == br.text_key:
                    decision = DELETED_COPY
                else:
                    decision = CONFLICT
                    conflict_rids.add(rid)
                    add_conflict(f"rule:{rid}", "modify-delete", br, mr, None)
                decisions.append({"key": f"rule:{rid}", "kind": "rule",
                                  "decision": decision,
                                  "base": _rule_entry(br), "main": _rule_entry(mr),
                                  "copy": None})
            else:
                decisions.append({"key": f"rule:{rid}", "kind": "rule",
                                  "decision": "deleted_both",
                                  "base": _rule_entry(br), "main": None,
                                  "copy": None})
        elif mr is not None and cr is not None:
            if rid in paired_new_main:
                # Entry is recorded below exactly once per content pair.
                continue
            if mr.rid != rid and cr.rid != rid:
                continue
            decisions.append({
                "key": f"rule:{mr.rid}", "kind": "rule",
                "decision": ADDED_BOTH,
                "base": None, "main": _rule_entry(mr), "copy": _rule_entry(cr),
            })
        elif mr is not None:
            decisions.append({
                "key": f"rule:{rid}", "kind": "rule", "decision": ADDED_MAIN,
                "base": None, "main": _rule_entry(mr), "copy": None,
            })
        elif cr is not None:
            decisions.append({
                "key": f"rule:{rid}", "kind": "rule", "decision": ADDED_COPY,
                "base": None, "main": None, "copy": _rule_entry(cr),
            })

    for mr, cr in paired_adds:
        # Remark-only or any other behavior-preserving difference must not
        # produce a textual conflict; identities differ but semantics match.
        decision = EQUIVALENT if mr.semantic_key == cr.semantic_key else CONFLICT
        if decision == CONFLICT:
            conflict_rids.add(mr.rid)
            conflict_rids.add(cr.rid)
            add_conflict(f"rule:{mr.rid}", "add-add", None, mr, cr)
        decisions.append({
            "key": f"rule:{mr.rid}", "kind": "rule", "decision": decision,
            "base": None, "main": _rule_entry(mr), "copy": _rule_entry(cr),
        })

    default_conflict = False
    if main.default_action != copy.default_action and (
            main.default_action != base.default_action or
            copy.default_action != base.default_action):
        # One side may have left default untouched: that side is not an edit.
        if (main.default_action != base.default_action and
                copy.default_action != base.default_action):
            default_conflict = True
            conflicts.append({
                "key": "rule:__default__", "kind": "default",
                "base": {"action": base.default_action},
                "main": {"action": main.default_action},
                "copy": {"action": copy.default_action},
                "options": ["main", "copy"],
            })
        else:
            decisions.append({
                "key": "rule:__default__", "kind": "default",
                "decision": ADOPT_MAIN if main.default_action != base.default_action
                else ADOPT_COPY,
                "base": {"action": base.default_action},
                "main": {"action": main.default_action},
                "copy": {"action": copy.default_action},
            })
    elif main.default_action == copy.default_action and \
            main.default_action != base.default_action:
        decisions.append({
            "key": "rule:__default__", "kind": "default",
            "decision": EQUIVALENT,
            "base": {"action": base.default_action},
            "main": {"action": main.default_action},
            "copy": {"action": copy.default_action},
        })

    def retained_reordered(side: Side) -> bool:
        common = [rid for rid in side.order if rid in b]
        base_pos = {rid: i for i, rid in enumerate(base.order)}
        return common != sorted(common, key=lambda x: base_pos.get(x, 10**9))

    main_reordered = retained_reordered(main)
    copy_reordered = retained_reordered(copy)
    order_conflict = main_reordered and copy_reordered
    if order_conflict:
        conflicts.append({
            "key": "order:global", "kind": "order",
            "base": [r.dict() for r in base.rules],
            "main": [r.dict() for r in main.rules],
            "copy": [r.dict() for r in copy.rules],
            "options": ["main", "copy"],
        })
    return decisions, conflicts, conflict_rids, order_conflict


def _merge_orders(anchor: Side, other: Side, include_other: bool = True) -> list[str]:
    """Stable topological placement of the other side's additions/reordering."""
    order = list(anchor.order)
    pos = {rid: i for i, rid in enumerate(order)}
    if not include_other:
        return order
    other_index = {rid: i for i, rid in enumerate(other.order)}
    for rid in other.order:
        if rid in pos:
            continue
        ids = list(other.order)
        pred = None
        for x in ids[:other_index[rid]][::-1]:
            if x in pos:
                pred = x
                break
        succ = None
        for x in ids[other_index[rid] + 1:]:
            if x in pos:
                succ = x
                break
        if pred is not None:
            insert_at = pos[pred] + 1
        elif succ is not None:
            insert_at = pos[succ]
        else:
            insert_at = len(order)
        order.insert(insert_at, rid)
        pos = {x: i for i, x in enumerate(order)}
    return order


def _build_candidate(base: Side, main: Side, copy: Side,
                     decisions: list[dict], conflicts: list[dict],
                     order_conflict: bool, choice: str,
                     resolutions: Optional[dict[str, str]] = None,
                     conflict_rids: Optional[set[str]] = None) -> Side:
    conflict_rids = conflict_rids or set()
    resolutions = resolutions or {}
    selected: dict[str, SideRule] = {}
    m, c = main.by_id(), copy.by_id()

    def chosen(key: str, fallback: str) -> str:
        val = resolutions.get(key)
        if val in ("main", "copy"):
            return val
        return fallback

    for d in decisions:
        dec, key = d["decision"], d["key"]
        if dec in (UNCHANGED, DELETED_MAIN, DELETED_COPY, "deleted_both"):
            continue
        if dec == EQUIVALENT and d.get("main"):
            # Semantics are identical; choosing main is canonical and avoids
            # duplicate IDs from independently inserted equivalent lines.
            selected[d["main"]["rid"]] = SideRule(**d["main"])
        elif dec == ADOPT_MAIN and d.get("main"):
            selected[d["main"]["rid"]] = SideRule(**d["main"])
        elif dec == ADOPT_COPY and d.get("copy"):
            selected[d["copy"]["rid"]] = SideRule(**d["copy"])
        elif dec == ADDED_MAIN and d.get("main"):
            selected[d["main"]["rid"]] = SideRule(**d["main"])
        elif dec == ADDED_COPY and d.get("copy"):
            selected[d["copy"]["rid"]] = SideRule(**d["copy"])
        elif dec == ADDED_BOTH and d.get("main"):
            selected[d["main"]["rid"]] = SideRule(**d["main"])

    for conf in conflicts:
        key = conf["key"]
        if key == "order:global":
            continue
        side = chosen(key, choice)
        item = conf[side]
        if item and "rid" in item:
            selected[item["rid"]] = SideRule(**item)

    # All rules explicitly selected as unchanged/equivalent still survive.
    excluded_rids = set(conflict_rids)
    for d in decisions:
        if d["decision"] == EQUIVALENT and d.get("main") and d.get("copy") and \
                d["main"]["rid"] != d["copy"]["rid"]:
            excluded_rids.add(d["copy"]["rid"])

    def surviving_from(side: Side) -> None:
        ids_deleted = {
            d["key"].split(":", 1)[1]
            for d in decisions
            if d["decision"] in (DELETED_MAIN, DELETED_COPY, "deleted_both")
        }
        for r in side.rules:
            if r.rid in ids_deleted or r.rid in excluded_rids:
                continue
            # A conflict losing side is omitted unless selected above.
            if any(cf["key"] == f"rule:{r.rid}" for cf in conflicts):
                continue
            selected.setdefault(r.rid, r)

    surviving_from(base)
    surviving_from(main)
    surviving_from(copy)

    effective_order_conflict = order_conflict or any(
        cf["key"] == "order:global" for cf in conflicts)
    if effective_order_conflict:
        anchor = main if chosen("order:global", choice) == "main" else copy
        other = copy if anchor is main else main
        order = _merge_orders(anchor, other)
    else:
        # Use the side that reordered; otherwise preserve base and add both.
        base_common = set(base.order)
        m_reordered = [r.rid for r in main.rules if r.rid in base_common] != \
            [rid for rid in base.order if rid in m]
        c_reordered = [r.rid for r in copy.rules if r.rid in base_common] != \
            [rid for rid in base.order if rid in c]
        if c_reordered and not m_reordered:
            order = _merge_orders(copy, main)
        elif m_reordered:
            order = _merge_orders(main, copy)
        else:
            order = _merge_orders(base, main)
            tmp = Side(None, None, "union", base.default_action,
                       [selected[r] for r in order if r in selected])
            order = _merge_orders(tmp, copy)
    order = [rid for rid in dict.fromkeys(order) if rid in selected]

    # Include any additions whose placement did not have an anchor (defensive).
    for rid in selected:
        if rid not in order:
            order.append(rid)

    default_choice = base.default_action
    default_conf = next((x for x in conflicts if x["key"] == "rule:__default__"), None)
    if default_conf:
        default_choice = default_conf[chosen(default_conf["key"], choice)]["action"]
    else:
        if main.default_action == copy.default_action:
            default_choice = main.default_action
        elif main.default_action == base.default_action:
            default_choice = copy.default_action
        else:
            default_choice = main.default_action

    rules = []
    for i, rid in enumerate(order, start=1):
        r = selected[rid]
        rules.append(SideRule(
            rid=r.rid, seq=i * 10, prefix=r.prefix, action=r.action,
            ge=r.ge, le=r.le, remark=r.remark,
        ))
    return Side(None, None, f"candidate-{choice}", default_choice, rules)


def _semantic_witnesses(base_pol: Policy, main_pol: Policy, copy_pol: Policy,
                        name: str, family: int,
                        both_reordered: bool = False) -> list[dict]:
    bm = _witness_dict(base_pol, main_pol)
    bc = _witness_dict(base_pol, copy_pol)
    mc = _witness_dict(main_pol, copy_pol)
    prefixes = sorted(
        set(bm) | set(bc) | set(mc),
        key=lambda p: (int(__import__("ipaddress").ip_network(p).network_address),
                       __import__("ipaddress").ip_network(p).prefixlen),
    )
    out = []
    for pfx in prefixes:
        bh, mh, ch = _hit(base_pol, pfx), _hit(main_pol, pfx), _hit(copy_pol, pfx)
        m_changed = mh["action"] != bh["action"]
        c_changed = ch["action"] != bh["action"]
        if both_reordered and mh["action"] != ch["action"] and (
                mh["action"] != bh["action"] or ch["action"] != bh["action"]):
            classification = "conflict"
            desired = None
        elif m_changed and c_changed and mh["action"] == ch["action"]:
            classification = "equivalent"
            desired = mh["action"]
        elif m_changed:
            classification = "auto_main"
            desired = mh["action"]
        elif c_changed:
            classification = "auto_copy"
            desired = ch["action"]
        elif mh["action"] == ch["action"]:
            classification = "equivalent" if pfx in mc else "unchanged"
            desired = mh["action"]
        else:
            # Defensive: should be in MC and one side must differ from B above.
            classification = "conflict"
            desired = None
        out.append({
            "prefix": pfx,
            "classification": classification,
            "desired_action": desired,
            "base": bh, "main": mh, "copy": ch,
            "witness_of": {
                "base_main": pfx in bm,
                "base_copy": pfx in bc,
                "main_copy": pfx in mc,
            },
        })
    return out


def _candidate_matches(candidate_pol: Policy, witnesses: list[dict],
                       contested_choice: Optional[dict[str, str]] = None) -> list[str]:
    """Return human-readable violations. Empty list means semantically valid."""
    errors = []
    for w in witnesses:
        got = candidate_pol.classify(w["prefix"]).final_action.value
        cls = w["classification"]
        if cls == "auto_main":
            want = w["main"]["action"]
        elif cls == "auto_copy":
            want = w["copy"]["action"]
        elif cls == "equivalent":
            want = w["main"]["action"]
        elif cls == "unchanged":
            want = w["base"]["action"]
        else:
            # During fully-automatic probing contested regions cannot pass.
            if contested_choice is None:
                errors.append(f"conflict at {w['prefix']}: "
                              f"main={w['main']['action']} copy={w['copy']['action']}")
                continue
            wanted = set()
            for side in ("main", "copy"):
                key = f"witness:{w['prefix']}:{side}"
                if contested_choice.get(key) == side:
                    wanted.add(w[side]["action"])
            # Manual validation primarily maps structural/order choices below.
            m_sel = contested_choice.get("order:global") == "main"
            c_sel = contested_choice.get("order:global") == "copy"
            if m_sel:
                wanted.add(w["main"]["action"])
            if c_sel:
                wanted.add(w["copy"]["action"])
            for conflict in contested_choice.get("_conflicts", []):
                key, side = conflict
                winner = w[side]
                if side == "main" and key.startswith("rule:") and \
                        winner.get("rid") == _rid_of_conflict(key):
                    wanted.add(winner["action"])
            if len(wanted) != 1:
                errors.append(f"conflict at {w['prefix']}: choose main or copy decision")
                continue
            want = next(iter(wanted))
        if got != want:
            errors.append(f"{w['prefix']}: candidate {got}, wanted {want}")
    return errors


def _rid_of_conflict(key: str) -> str:
    return key.split(":", 1)[1]


def analyze_three_way(session: Session, policy: dbmod.Policy,
                      base_snap: dbmod.Snapshot,
                      main_snap: dbmod.Snapshot,
                      workcopy: dbmod.WorkCopy) -> dict:
    base = side_from_snapshot(base_snap)
    main = side_from_snapshot(main_snap)
    copy = normalize_payload(workcopy.current_payload, family=policy.family)

    decisions, structural_conflicts, conflict_rids, order_conflict = \
        _structural_analysis(base, main, copy)

    family = policy.family
    base_pol = base.policy(policy.name, family)
    main_pol = main.policy(policy.name, family)
    copy_pol = copy.policy(policy.name, family)
    witnesses = _semantic_witnesses(base_pol, main_pol, copy_pol,
                                    policy.name, family, order_conflict)

    semantic_conflicts = [w for w in witnesses if w["classification"] == "conflict"]
    # A reorder-only conflict needs an explicit order resolution.
    conflicts = list(structural_conflicts)
    if order_conflict and semantic_conflicts:
        # The order item already exists; attach minimal witness/chain evidence.
        for cf in conflicts:
            if cf["key"] == "order:global":
                cf["witnesses"] = semantic_conflicts
    elif order_conflict:
        for cf in conflicts:
            if cf["key"] == "order:global":
                cf["witnesses"] = []

    # Attach witnesses to the specific structural item they explain.
    for cf in conflicts:
        cf.setdefault("witnesses", [])
        if cf["kind"] == "rule":
            rid = cf["key"].split(":", 1)[1]
            for w in semantic_conflicts:
                if w["main"].get("rid") == rid or w["copy"].get("rid") == rid:
                    cf["witnesses"].append(w)
        elif cf["kind"] == "default":
            for w in semantic_conflicts:
                if w["main"]["seq"] is None or w["copy"]["seq"] is None:
                    cf["witnesses"].append(w)

    # If there is a true action conflict but no line/default item owns it,
    # present it as an ordering decision between the two complete policies.
    if semantic_conflicts and not any(
            cf["kind"] in ("rule", "default") and cf["witnesses"]
            for cf in conflicts):
        order_item = next((cf for cf in conflicts if cf["key"] == "order:global"), None)
        if order_item is None:
            order_item = {
                "key": "order:global", "kind": "order",
                "base": [r.dict() for r in base.rules],
                "main": [r.dict() for r in main.rules],
                "copy": [r.dict() for r in copy.rules],
                "options": ["main", "copy"],
                "witnesses": [],
            }
            conflicts.append(order_item)
        order_item.setdefault("witnesses", [])
        existing = {w["prefix"] for w in order_item["witnesses"]}
        for w in semantic_conflicts:
            if w["prefix"] not in existing:
                order_item["witnesses"].append(w)

    candidates = {}
    candidate_errors = {}
    auto_candidate = None
    if not semantic_conflicts:
        for side in ("main", "copy"):
            cand = _build_candidate(base, main, copy, decisions, conflicts,
                                    order_conflict, side, conflict_rids=conflict_rids)
            cand_pol = cand.policy(policy.name, family)
            errs = _candidate_matches(cand_pol, witnesses)
            candidates[side] = cand.payload(policy.name, family)
            candidate_errors[side] = errs
            if not errs and auto_candidate is None:
                auto_candidate = cand

    semantic_equivalent = [d for d in decisions if d["decision"] == EQUIVALENT]
    auto_items = [d for d in decisions if d["decision"] in (
        ADOPT_MAIN, ADOPT_COPY, ADDED_MAIN, ADDED_COPY, ADDED_BOTH,
        DELETED_MAIN, DELETED_COPY,
    )]

    if auto_candidate is not None and not semantic_conflicts:
        # Textual structural disagreements that still yield a verified
        # behavior-preserving union are semantic equivalents, not conflicts.
        for cf in conflicts:
            semantic_equivalent.append({
                "key": cf["key"], "kind": cf["kind"],
                "decision": EQUIVALENT,
                "base": cf.get("base"), "main": cf.get("main"),
                "copy": cf.get("copy"),
            })
        final_conflicts: list[dict] = []
        status = "equivalent" if not any(
            w["witness_of"]["base_main"] or w["witness_of"]["base_copy"]
            for w in witnesses
        ) and not any(d.get("decision") in (
            ADOPT_MAIN, ADOPT_COPY, ADDED_MAIN, ADDED_COPY, ADDED_BOTH,
            DELETED_MAIN, DELETED_COPY) for d in auto_items) else "ready"
    else:
        final_conflicts = conflicts
        status = "conflict"

    return {
        "status": status,
        "family": family,
        "base_snapshot_id": base_snap.id,
        "main_snapshot_id": main_snap.id,
        "workcopy_version": workcopy.version,
        "base_version": base_snap.version,
        "main_version": main_snap.version,
        "base": base.payload(policy.name, family),
        "main": main.payload(policy.name, family),
        "copy": copy.payload(policy.name, family),
        "auto_merges": auto_items,
        "semantic_equivalences": semantic_equivalent,
        "conflicts": final_conflicts,
        "witnesses": witnesses,
        "semantic_conflict_count": len(semantic_conflicts),
        "candidate_payload": auto_candidate.payload(policy.name, family)
        if auto_candidate is not None else None,
        "candidate_errors": candidate_errors,
    }


def candidate_from_resolution(policy: dbmod.Policy, analysis: dict,
                              resolutions: dict[str, str]) -> tuple[Side, list[str]]:
    base = normalize_payload(analysis["base"], family=policy.family)
    main = normalize_payload(analysis["main"], family=policy.family)
    copy = normalize_payload(analysis["copy"], family=policy.family)
    decisions, structural_conflicts, conflict_rids, order_conflict = _structural_analysis(base, main, copy)
    conflicts = list(structural_conflicts)

    semantic_conflicts = [
        w for w in analysis["witnesses"] if w["classification"] == "conflict"]
    owned_prefixes = set()
    for cf in conflicts:
        if cf["kind"] == "rule":
            rid = cf["key"].split(":", 1)[1]
            for w in semantic_conflicts:
                if w["main"].get("rid") == rid or w["copy"].get("rid") == rid:
                    owned_prefixes.add(w["prefix"])
        elif cf["kind"] == "default":
            for w in semantic_conflicts:
                if w["main"]["seq"] is None or w["copy"]["seq"] is None:
                    owned_prefixes.add(w["prefix"])
    unowned = [w for w in semantic_conflicts if w["prefix"] not in owned_prefixes]
    if unowned:
        order_item = next((cf for cf in conflicts if cf["key"] == "order:global"), None)
        if order_item is None:
            order_item = {
                "key": "order:global", "kind": "order",
                "base": [r.dict() for r in base.rules],
                "main": [r.dict() for r in main.rules],
                "copy": [r.dict() for r in copy.rules],
                "options": ["main", "copy"],
                "witnesses": [],
            }
            conflicts.append(order_item)
        order_item.setdefault("witnesses", [])
        existing = {w["prefix"] for w in order_item["witnesses"]}
        order_item["witnesses"].extend(
            w for w in unowned if w["prefix"] not in existing)

    allowed = {cf["key"] for cf in conflicts}
    bad = sorted(set(resolutions) - allowed)
    missing = sorted(allowed - set(resolutions))
    errors = []
    if bad:
        errors.append("unknown conflict decision: " + ", ".join(bad))
    if missing:
        errors.append("unresolved conflict: " + ", ".join(missing))
    for key, val in resolutions.items():
        if key in allowed and val not in ("main", "copy"):
            errors.append(f"{key}: resolution must be main or copy")
    if errors:
        dummy = _build_candidate(base, main, copy, decisions, conflicts,
                                 order_conflict, "main", resolutions, conflict_rids)
        return dummy, errors

    cand = _build_candidate(base, main, copy, decisions, conflicts,
                            order_conflict, "main", resolutions, conflict_rids)
    cand_pol = cand.policy(policy.name, policy.family)
    witnesses = analysis["witnesses"]

    # Manual validation: contested action must agree with every owning
    # structural/order decision. This catches mixed choices that cannot be
    # realized without adding an even more-specific guard.
    for w in witnesses:
        if w["classification"] != "conflict":
            continue
        chosen_actions = set()
        for side in ("main", "copy"):
            hit = w[side]
            rid = hit.get("rid")
            owner_keys = []
            if rid is not None and f"rule:{rid}" in resolutions:
                owner_keys.append(f"rule:{rid}")
            if hit["seq"] is None and "rule:__default__" in resolutions:
                owner_keys.append("rule:__default__")
            if "order:global" in resolutions and \
                    not any(k != "order:global" for k in owner_keys):
                owner_keys.append("order:global")
            if any(resolutions[k] == side for k in owner_keys):
                chosen_actions.add(hit["action"])
        if len(chosen_actions) != 1:
            errors.append(
                f"{w['prefix']}: decisions do not determine one action "
                f"(main={w['main']['action']}, copy={w['copy']['action']})"
            )
        elif cand_pol.classify(w["prefix"]).final_action.value != next(iter(chosen_actions)):
            errors.append(
                f"{w['prefix']}: candidate does not implement selected action"
            )

    # All non-contested semantic regions must still preserve the auto union.
    for w in witnesses:
        if w["classification"] == "conflict":
            continue
        want = {"auto_main": w["main"]["action"],
                "auto_copy": w["copy"]["action"]}.get(
            w["classification"], w["base"]["action"])
        got = cand_pol.classify(w["prefix"]).final_action.value
        if got != want:
            errors.append(f"{w['prefix']}: candidate {got}, wanted {want}")
    return cand, errors
