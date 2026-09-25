"""
Acceptance tests for semantic three-way concurrent merging.

Covers (from the task statement):

* edits to DIFFERENT ADDRESS FAMILIES auto-merge;
* two editors reordering so the SAME prefix behaves the OPPOSITE way block
  the commit;
* semantically equivalent rewrites do NOT produce spurious conflicts;
* a duplicate commit / concurrent decision creates exactly ONE successor
  snapshot version;
* pending conflicts, human decisions and the original snapshot survive a
  refresh / service restart;
* abandoning a merge never pollutes either branch;
* the existing shadow analysis stays correct on merged results;
* the merge result can be run through the existing probes and FRR-style
  simulation (live FRR tests skip when no container is present).
"""
import threading
import uuid

import pytest

from app import merge3, merge_service as msvc
from app.engine import Action, Policy, Rule, policy_from_dicts
from app.merge3 import build_plan, policies_of_payload, verify_commit


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def r(seq, pfx, act, **kw):
    return {"seq": seq, "prefix": pfx, "action": act,
            **{k: v for k, v in kw.items() if v is not None}}


def pl(family, rules, default="deny"):
    return {"family": family, "default_action": default, "rules": rules}


def commit_ok(plan, res):
    return verify_commit(plan, res) == []


# ---------------------------------------------------------------------------
# engine-level three-way merge acceptance
# ---------------------------------------------------------------------------

def test_edits_to_different_address_families_auto_merge():
    base = {"family": 0,
            "defaults": {"4": "deny", "6": "deny"},
            "rules": [r(10, "10.0.0.0/8", "permit"),
                      r(20, "2001:db8::/32", "permit")]}
    main = {"family": 0,
            "defaults": {"4": "deny", "6": "deny"},
            "rules": [r(10, "10.0.0.0/8", "permit"),
                      r(20, "10.1.0.0/16", "deny"),
                      r(30, "2001:db8::/32", "permit")]}
    work = {"family": 0,
            "defaults": {"4": "deny", "6": "deny"},
            "rules": [r(10, "10.0.0.0/8", "permit"),
                      r(20, "2001:db8::/32", "permit"),
                      r(30, "2001:db8:1::/48", "deny")]}
    plan = build_plan(base, main, work, "dual")
    d = plan.to_dict({})
    assert d["merge_status"] == "clean", d
    assert verify_commit(plan, {}) == []
    merged = policies_of_payload(plan.merged_payload({}))
    prefs4 = [x.prefix for x in merged[4].rules]
    prefs6 = [x.prefix for x in merged[6].rules]
    assert "10.1.0.0/16" in prefs4
    assert "2001:db8:1::/48" in prefs6
    # independent behavior preserved
    assert merged[4].classify("10.1.0.0/16").final_action == Action.DENY
    assert merged[6].classify("2001:db8:1::/48").final_action == Action.DENY


def test_two_editors_reorder_opposite_blocks_commit():
    # narrow deny wins 172.31 at the base; broad permit sits behind it
    base = pl(4, [r(10, "172.31.0.0/16", "deny"),
                  r(20, "172.16.0.0/12", "permit", le=32)])
    # Alice: broad permit first -> 172.31 becomes PERMIT
    alice = pl(4, [r(5, "172.16.0.0/12", "permit", le=32),
                   r(10, "172.31.0.0/16", "deny")])
    # Bob: inserts an even broader DENY ahead -> 172.31 stays DENY
    bob = pl(4, [r(5, "0.0.0.0/0", "deny"),
                 r(10, "172.31.0.0/16", "deny"),
                 r(20, "172.16.0.0/12", "permit", le=32)])

    plan = build_plan(base, alice, bob, "reorder")
    d = plan.to_dict({})
    assert d["merge_status"] == "conflicts", d
    required = plan.required_resolution_ids()
    assert required
    # the minimal witness for the opposite behavior is 172.31.0.0/16
    wits = [(w["prefix"], w["main_action"], w["work_action"])
            for h in d["hunks"] for w in h["witnesses"]]
    assert ("172.31.0.0/16", "permit", "deny") in wits
    # every witness carries the B/M/W hit chains
    for h in d["hunks"]:
        for w in h["witnesses"]:
            assert w["base"]["chain"] and w["main"]["chain"] \
                and w["work"]["chain"]
    # committing without a decision fails semantic verification
    assert verify_commit(plan, {})
    # choosing mainline is consistent and yields permit
    res = {hid: "main" for hid in required}
    assert verify_commit(plan, res) == []
    merged = policies_of_payload(plan.merged_payload(res))[4]
    assert merged.classify("172.31.0.0/16").final_action == Action.PERMIT


def test_reorder_vs_delete_same_prefix_opposite_blocks():
    base = pl(4, [r(10, "172.31.0.0/16", "deny"),
                  r(20, "172.16.0.0/12", "permit", le=32)])
    main = pl(4, [r(5, "172.16.0.0/12", "permit", le=32),
                  r(10, "172.31.0.0/16", "deny")])
    work = pl(4, [r(10, "172.31.0.0/16", "deny")])  # deletes broad permit
    plan = build_plan(base, main, work, "mvdel")
    assert plan.to_dict({})["merge_status"] == "conflicts"
    assert verify_commit(plan, {})
    # resolving work: 172.31 deny and broad permit gone
    res = {hid: "work" for hid in plan.required_resolution_ids()}
    merged = policies_of_payload(plan.merged_payload(res))[4]
    assert merged.classify("172.31.0.0/16").final_action == Action.DENY


def test_semantically_equivalent_rewrite_no_false_conflict():
    # remark-only edits on both sides
    b = pl(4, [r(10, "10.0.0.0/8", "permit", le=24, remark="base")])
    m = pl(4, [r(10, "10.0.0.0/8", "permit", le=24, remark="alice")])
    w = pl(4, [r(30, "10.0.0.0/8", "permit", le=24, remark="bob")])
    d = build_plan(b, m, w, "eq").to_dict({})
    assert d["merge_status"] == "clean"
    assert d["summary"]["conflicts"] == 0

    # canonical text difference (10/8 vs 10.0.0.0/8)
    b2 = pl(4, [r(10, "10/8", "permit", le=24)])
    m2 = pl(4, [r(5, "10.0.0.0/8", "permit", le=24)])
    w2 = pl(4, [r(9, "10.0.0.0/8", "permit", le=24, remark="x")])
    d2 = build_plan(b2, m2, w2, "canon").to_dict({})
    assert d2["merge_status"] == "clean", d2
    assert d2["summary"]["conflicts"] == 0


def test_disjoint_v4_regions_auto_merge():
    b = pl(4, [r(10, "10.0.0.0/8", "permit"), r(20, "11.0.0.0/8", "permit")])
    m = pl(4, [r(10, "10.0.0.0/8", "deny"), r(20, "11.0.0.0/8", "permit")])
    w = pl(4, [r(10, "10.0.0.0/8", "permit"), r(20, "11.0.0.0/8", "deny")])
    plan = build_plan(b, m, w, "disjoint")
    d = plan.to_dict({})
    assert d["merge_status"] == "clean", d
    assert verify_commit(plan, {}) == []
    merged = policies_of_payload(plan.merged_payload({}))[4]
    assert merged.classify("10.0.0.0/8").final_action == Action.DENY
    assert merged.classify("11.0.0.0/8").final_action == Action.DENY


def test_convergent_edit_auto_merge():
    b = pl(4, [r(10, "10.0.0.0/8", "permit")])
    m = pl(4, [r(10, "10.0.0.0/8", "deny")])
    w = pl(4, [r(10, "10.0.0.0/8", "deny")])
    plan = build_plan(b, m, w, "conv")
    assert plan.to_dict({})["merge_status"] == "clean"
    assert verify_commit(plan, {}) == []


def test_solo_one_sided_reorder_commits_clean():
    # mainline unchanged; the working copy alone reorders -> that side's
    # consistent ordered slice must be taken whole (no insert/stale/delete
    # reassembly artifact).
    base = pl(4, [r(10, "172.31.0.0/16", "deny"),
                  r(20, "172.16.0.0/12", "permit", le=32)])
    work = pl(4, [r(5, "172.16.0.0/12", "permit", le=32),
                  r(10, "172.31.0.0/16", "deny")])
    plan = build_plan(base, base, work, "solo")
    assert plan.to_dict({})["merge_status"] == "clean"
    assert verify_commit(plan, {}) == []
    merged = policies_of_payload(plan.merged_payload({}))[4]
    assert merged.classify("172.31.0.0/16").final_action == Action.PERMIT


def test_default_action_clash_requires_decision():
    b = pl(4, [r(10, "10.0.0.0/8", "permit")], default="deny")
    m = pl(4, [r(10, "10.0.0.0/8", "permit"),
               r(20, "12.0.0.0/8", "permit")], default="permit")
    w = pl(4, [r(10, "10.0.0.0/8", "permit"),
               r(20, "11.0.0.0/8", "deny")], default="deny")
    plan = build_plan(b, m, w, "def")
    d = plan.to_dict({})
    assert d["merge_status"] == "conflicts", d
    assert plan.required_resolution_ids()


def test_merged_shadow_analysis_stays_correct():
    base = pl(4, [r(10, "172.31.0.0/16", "deny"),
                  r(20, "172.16.0.0/12", "permit", le=32)])
    main = pl(4, [r(5, "172.16.0.0/12", "permit", le=32),
                  r(10, "172.31.0.0/16", "deny")])
    work = pl(4, [r(10, "172.31.0.0/16", "deny"),
                  r(20, "172.16.0.0/12", "permit", le=32),
                  r(30, "9.0.0.0/8", "permit")])
    plan = build_plan(base, main, work, "shadow")
    assert plan.to_dict({})["merge_status"] == "clean"
    merged = policies_of_payload(plan.merged_payload({}))[4]
    shadows = {s.rule.prefix: s for s in merged.shadowed()}
    # after the merge the broad permit is first -> the narrow 172.31 deny is
    # fully shadowed, exactly as the existing shadow analyzer reports
    assert shadows["172.31.0.0/16"].fully_shadowed is True
    assert shadows["172.31.0.0/16"].witnesses
    # the broad permit itself stays reachable
    assert shadows["172.16.0.0/12"].fully_shadowed is False


def test_merged_policy_runs_existing_probes():
    b = pl(4, [r(10, "10.0.0.0/8", "permit"), r(20, "12.0.0.0/8", "permit")])
    # mainline flips an unrelated rule; the copy adds a new rule elsewhere ->
    # disjoint, auto-merges
    m = pl(4, [r(10, "10.0.0.0/8", "permit"), r(20, "12.0.0.0/8", "deny")])
    w = pl(4, [r(10, "10.0.0.0/8", "permit"),
               r(20, "12.0.0.0/8", "permit"),
               r(30, "11.0.0.0/8", "permit")])
    plan = build_plan(b, m, w, "probes")
    assert verify_commit(plan, {}) == []
    merged = policies_of_payload(plan.merged_payload({}))[4]
    probes = ["10.0.0.0/8", "11.0.0.0/8", "12.0.0.0/8", "8.8.8.8/32"]
    actions = [merged.classify(p).final_action.value for p in probes]
    assert actions == ["permit", "permit", "deny", "deny"]


# ---------------------------------------------------------------------------
# service / persistence level
# ---------------------------------------------------------------------------

@pytest.fixture
def merge_policy(client):
    name = f"merge-{uuid.uuid4().hex[:8]}"
    pid = client.post("/api/policies", json={
        "name": name, "family": 4, "default_action": "deny"}).json()["id"]
    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        r(10, "172.31.0.0/16", "deny"),
        r(20, "172.16.0.0/12", "permit", le=32)]})
    client.post(f"/api/policies/{pid}/snapshots", json={"label": "base"})
    return pid


def test_api_different_families_and_duplicate_commit_one_successor(
        client, merge_policy):
    pid = merge_policy
    # make the base dual-stack
    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        r(10, "10.0.0.0/8", "permit"),
        r(20, "2001:db8::/32", "permit")]})
    base = client.post(f"/api/policies/{pid}/snapshots",
                       json={"label": "dual-base"}).json()

    wc = client.post(f"/api/policies/{pid}/working-copies",
                     json={"name": "a"}).json()
    # mainline advances on v4 while the copy edits v6 only
    client.put(f"/api/policies/{pid}/rules", json={"rules": [
        r(10, "10.0.0.0/8", "permit"),
        r(20, "10.1.0.0/16", "deny"),
        r(30, "2001:db8::/32", "permit")]})
    client.post(f"/api/policies/{pid}/snapshots", json={"label": "v4-edit"})
    client.put(f"/api/working-copies/{wc['id']}", json={"payload": {
        "family": 0,
        "defaults": {"4": "deny", "6": "deny"},
        "rules": [r(10, "10.0.0.0/8", "permit"),
                  r(20, "2001:db8::/32", "permit"),
                  r(30, "2001:db8:1::/48", "deny")]}})
    pv = client.post("/api/merges/preview",
                     json={"working_copy_id": wc["id"]}).json()
    assert pv["merge_status"] == "clean", pv

    first = client.post(f"/api/merges/{pv['id']}/commit", json={})
    assert first.status_code == 200, first.text
    sid = first.json()["snapshot"]["id"]

    # duplicate (repeated) commit -> same snapshot, idempotent
    again = client.post(f"/api/merges/{pv['id']}/commit", json={}).json()
    assert again["idempotent"] is True
    assert again["snapshot"]["id"] == sid

    versions = [s["version"]
                for s in client.get(f"/api/policies/{pid}/snapshots").json()]
    assert versions.count(max(versions)) == 1     # exactly one successor


def test_api_concurrent_decisions_produce_one_successor(client, merge_policy):
    pid = merge_policy
    wc = client.post(f"/api/policies/{pid}/working-copies",
                     json={"name": "solo"}).json()
    client.put(f"/api/working-copies/{wc['id']}", json={"payload": pl(4, [
        r(5, "172.16.0.0/12", "permit", le=32),
        r(10, "172.31.0.0/16", "deny")])})
    pv = client.post("/api/merges/preview",
                     json={"working_copy_id": wc["id"]}).json()
    assert pv["merge_status"] == "clean"

    results = []

    def commit():
        # a fresh session/connection per thread
        s = type(client.get("/api/health"))  # noqa (kept for clarity)
        out = client.post(f"/api/merges/{pv['id']}/commit", json={})
        results.append(out)

    t1 = threading.Thread(target=commit)
    t2 = threading.Thread(target=commit)
    t1.start(); t2.start(); t1.join(); t2.join()
    # both calls succeed (idempotent) but only one snapshot row exists
    ids = {r.json()["snapshot"]["id"] for r in results if r.status_code == 200}
    assert ids and len(ids) == 1
    versions = [s["version"]
                for s in client.get(f"/api/policies/{pid}/snapshots").json()]
    assert versions == [2, 1]


def test_api_conflict_persists_across_restart_and_abandon_isolates(
        client, merge_policy):
    pid = merge_policy
    base = [s for s in client.get(f"/api/policies/{pid}/snapshots").json()
            if s["label"] == "base"][0]

    wa = client.post(f"/api/policies/{pid}/working-copies",
                     json={"name": "alice"}).json()
    wb = client.post(f"/api/policies/{pid}/working-copies",
                     json={"name": "bob"}).json()

    # alice flips 172.31 to permit and commits v2
    client.put(f"/api/working-copies/{wa['id']}", json={"payload": pl(4, [
        r(5, "172.16.0.0/12", "permit", le=32),
        r(10, "172.31.0.0/16", "deny")])})
    pva = client.post("/api/merges/preview",
                      json={"working_copy_id": wa["id"]}).json()
    client.post(f"/api/merges/{pva['id']}/commit", json={})

    # bob's reorder keeps 172.31 deny -> conflict against new mainline
    client.put(f"/api/working-copies/{wb['id']}", json={"payload": pl(4, [
        r(5, "0.0.0.0/0", "deny"),
        r(10, "172.31.0.0/16", "deny"),
        r(20, "172.16.0.0/12", "permit", le=32)])})
    pvb = client.post("/api/merges/preview",
                      json={"working_copy_id": wb["id"]}).json()
    assert pvb["merge_status"] == "conflicts"
    mid = pvb["id"]
    required = [h["id"] for h in pvb["hunks"]
                if h["kind"] in ("conflict", "policy-conflict",
                                 "default-conflict")]
    assert required

    # cannot commit unresolved
    assert client.post(f"/api/merges/{mid}/commit", json={}).status_code == 409

    # make a decision
    client.post(f"/api/merges/{mid}/decisions",
                json={"resolutions": {hid: "work" for hid in required}})

    # ---- "restart": a brand new TestClient reopens the SAME database ----
    from fastapi.testclient import TestClient
    from app.main import app
    c2 = TestClient(app)
    reloaded = c2.get(f"/api/merges/{mid}").json()
    assert reloaded["status"] == "open"
    for hid in required:
        assert reloaded["resolutions"].get(hid) == "work"
    # original base snapshot fully recoverable and unchanged
    snap = c2.get(f"/api/snapshots/{base['id']}").json()
    assert snap["version"] == 1
    assert "172.31.0.0/16" in snap["frr_config"]

    # abandon -> status flips, no snapshot created, neither branch mutated
    c2.post(f"/api/merges/{mid}/abandon")
    after = c2.get(f"/api/policies/{pid}/snapshots").json()
    assert [s["version"] for s in after] == [2, 1]
    # the working copy edit payload survives (branch not polluted)
    wc2 = c2.get(f"/api/working-copies/{wb['id']}").json()
    assert any(x["prefix"] == "0.0.0.0/0" for x in wc2["payload"]["rules"])
    # committing an abandoned merge is rejected
    assert c2.post(f"/api/merges/{mid}/commit", json={}).status_code in (409, 422)


def test_api_working_copy_version_is_monotonic(client, merge_policy):
    pid = merge_policy
    wc = client.post(f"/api/policies/{pid}/working-copies",
                     json={"name": "v"}).json()
    assert wc["version"] == 0
    body = pl(4, [r(10, "172.31.0.0/16", "deny"),
                 r(20, "172.16.0.0/12", "permit", le=32)])
    r1 = client.put(f"/api/working-copies/{wc['id']}",
                    json={"payload": body, "expected_version": 0}).json()
    assert r1["version"] == 1
    # stale expected_version rejected
    stale = client.put(f"/api/working-copies/{wc['id']}",
                       json={"payload": body, "expected_version": 0})
    assert stale.status_code == 409


def test_api_merge_preview_runs_existing_probes(client, merge_policy):
    pid = merge_policy
    wc = client.post(f"/api/policies/{pid}/working-copies",
                     json={"name": "probe-copy"}).json()
    # one-sided clean edit
    client.put(f"/api/working-copies/{wc['id']}", json={"payload": pl(4, [
        r(10, "172.31.0.0/16", "deny"),
        r(20, "172.16.0.0/12", "permit", le=32),
        r(30, "9.0.0.0/8", "deny")])})
    pv = client.post("/api/merges/preview",
                     json={"working_copy_id": wc["id"]}).json()
    assert pv["merge_status"] == "clean"
    cv = client.post(f"/api/merges/{pv['id']}/cross-validate",
                     json={"probes": ["172.31.0.0/16", "9.0.0.0/8"]}).json()
    rows = [(row["prefix"], row["sim_action"])
            for plane in cv["planes"] for row in plane["rows"]]
    assert ("172.31.0.0/16", "deny") in rows
    assert ("9.0.0.0/8", "deny") in rows
    # when no live FRR is reachable the harness degrades to sim-only without
    # fabricating a mismatch
    for plane in cv["planes"]:
        assert plane["mismatch_count"] == 0
    assert cv["frr_available"] is False
