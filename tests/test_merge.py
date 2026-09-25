"""Acceptance tests for semantic workcopies and three-way merges."""
from fastapi.testclient import TestClient


def _make(client, name="merge-policy", family=4, default="deny"):
    r = client.post("/api/policies", json={
        "name": name, "family": family, "default_action": default})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _rules(client, pid, rules, default=None):
    r = client.put(f"/api/policies/{pid}/rules",
                   json={"rules": rules, "default_action": default})
    assert r.status_code == 200, r.text
    return r.json()["rules"]


def _snapshot(client, pid, label="s"):
    r = client.post(f"/api/policies/{pid}/snapshots", json={"label": label})
    assert r.status_code == 201, r.text
    return r.json()


def _wc(client, pid, name, base=None):
    r = client.post(f"/api/policies/{pid}/workcopies", json={
        "name": name, "base_snapshot_id": base, "created_by": name})
    assert r.status_code == 201, r.text
    return r.json()


def _wc_edit(client, wc, rules=None, default_action=None):
    payload = wc["current_payload"]
    body = {
        "rules": rules if rules is not None else payload["rules"],
        "default_action": default_action if default_action is not None
        else payload["default_action"],
        "expected_version": wc["version"],
    }
    r = client.put(f"/api/workcopies/{wc['id']}/rules", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _preview(client, wc, refresh=False):
    r = client.post(f"/api/workcopies/{wc['id']}/merge-preview", json={
        "expected_workcopy_version": wc["version"], "refresh": refresh})
    assert r.status_code == 201, r.text
    return r.json()


def _commit(client, merge, **kw):
    body = {"expected_session_version": merge["version"], **kw}
    return client.post(f"/api/merge-sessions/{merge['id']}/commit", json=body)


def test_disjoint_prefix_edits_auto_merge(client):
    pid = _make(client, "disjoint")
    base_rules = [{"seq": 10, "prefix": "10.0.0.0/8", "action": "deny"}]
    _rules(client, pid, base_rules)
    s1 = _snapshot(client, pid, "base")

    wc = _wc(client, pid, "alice", s1["id"])
    main_rules = base_rules + [
        {"seq": 20, "prefix": "192.0.2.0/24", "action": "permit"}]
    _rules(client, pid, main_rules)
    s2 = _snapshot(client, pid, "main-add")

    wc = client.get(f"/api/workcopies/{wc['id']}").json()
    copy_rules = base_rules + [
        {"seq": 30, "prefix": "198.51.100.0/24", "action": "permit"}]
    wc = _wc_edit(client, wc, copy_rules)

    merge = _preview(client, wc)
    assert merge["status"] == "ready"
    assert len(merge["analysis"]["conflicts"]) == 0
    assert len(merge["analysis"]["auto_merges"]) >= 2
    merged = merge["candidate_payload"]["rules"]
    assert {r["prefix"] for r in merged} == {
        "10.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24"}

    validate = client.post(f"/api/merge-sessions/{merge['id']}/validate", json={
        "probes": ["192.0.2.0/24", "198.51.100.0/24", "10.0.0.0/8"],
        "node": "a", "run_frr": False})
    assert validate.status_code == 200, validate.text
    assert [r["action"] for r in validate.json()["simulation"]] == \
        ["permit", "permit", "deny"]

    r = _commit(client, merge, label="merged",
                validate_probes=["192.0.2.0/24", "198.51.100.0/24"])
    assert r.status_code == 201, r.text
    snap = r.json()
    assert snap["version"] == s2["version"] + 1
    assert snap["parent_snapshot_id"] == s2["id"]
    # Existing shadow analysis still works on the new mainline policy state.
    analysis = client.get(f"/api/policies/{pid}/analyze")
    assert analysis.status_code == 200


def test_optimistic_version_rejects_lost_update(client):
    pid = _make(client, "optimistic")
    rule = {"rid": "r1", "seq": 10, "prefix": "10/8", "action": "deny"}
    _rules(client, pid, [rule])
    s = _snapshot(client, pid, "base")
    wc = _wc(client, pid, "grace", s["id"])
    first = _wc_edit(client, wc, [{**rule, "remark": "first"}])
    assert first["version"] == 1
    r = client.put(f"/api/workcopies/{wc['id']}/rules", json={
        "rules": [{**rule, "remark": "lost"}],
        "default_action": "deny", "expected_version": 0})
    assert r.status_code == 409


def test_mainline_change_invalidates_old_preview(client):
    pid = _make(client, "stale-preview")
    base = [{"rid": "r1", "seq": 10, "prefix": "10/8", "action": "deny"}]
    _rules(client, pid, base)
    s1 = _snapshot(client, pid, "base")
    wc = _wc(client, pid, "heidi", s1["id"])
    _rules(client, pid, base + [
        {"rid": "r2", "seq": 20, "prefix": "192.0.2.0/24", "action": "permit"}])
    s2 = _snapshot(client, pid, "main1")
    wc = client.get(f"/api/workcopies/{wc['id']}").json()
    wc = _wc_edit(client, wc, base + [
        {"rid": "r3", "seq": 30, "prefix": "198.51.100.0/24", "action": "permit"}])
    merge = _preview(client, wc)
    _rules(client, pid, base + [
        {"rid": "r4", "seq": 40, "prefix": "203.0.113.0/24", "action": "permit"}])
    _snapshot(client, pid, "main2")
    r = _commit(client, merge)
    assert r.status_code == 409


def test_opposite_reorder_is_blocked_until_manual_choice(client):
    pid = _make(client, "reorder-conflict")
    outside = {"rid": "outside", "seq": 10, "prefix": "8.0.0.0/8", "action": "permit"}
    narrow = {"rid": "narrow", "seq": 20, "prefix": "172.31.0.0/16", "action": "deny"}
    broad = {"rid": "broad", "seq": 30, "prefix": "172.16.0.0/12",
             "action": "permit", "le": 32}
    base = [narrow, broad, outside]
    _rules(client, pid, base)
    s1 = _snapshot(client, pid, "base")

    wc = _wc(client, pid, "bob", s1["id"])

    # Main moves broad first: 172.31/16 now permits.
    _rules(client, pid, [
        {"rid": "broad", "seq": 5, "prefix": "172.16.0.0/12",
         "action": "permit", "le": 32},
        {"rid": "outside", "seq": 10, "prefix": "8.0.0.0/8", "action": "permit"},
        {"rid": "narrow", "seq": 20, "prefix": "172.31.0.0/16", "action": "deny"},
    ])
    _snapshot(client, pid, "main-broad-first")

    # Copy moves the outside rule after narrow, but keeps narrow before broad:
    # the same witness prefix still denies.
    wc = client.get(f"/api/workcopies/{wc['id']}").json()
    wc = _wc_edit(client, wc, [
        {"rid": "narrow", "seq": 10, "prefix": "172.31.0.0/16", "action": "deny"},
        {"rid": "outside", "seq": 20, "prefix": "8.0.0.0/8", "action": "permit"},
        {"rid": "broad", "seq": 30, "prefix": "172.16.0.0/12",
         "action": "permit", "le": 32},
    ])
    merge = _preview(client, wc)
    assert merge["status"] == "conflict"
    assert merge["analysis"]["semantic_conflict_count"] >= 1
    witness = next(w for w in merge["analysis"]["witnesses"]
                   if w["classification"] == "conflict")
    assert witness["prefix"] == "172.31.0.0/16"
    assert witness["main"]["action"] == "permit"
    assert witness["copy"]["action"] == "deny"
    assert witness["main"]["chain"] and witness["copy"]["chain"]
    assert client.post(f"/api/merge-sessions/{merge['id']}/commit", json={
        "expected_session_version": merge["version"]}).status_code == 409

    r = client.post(f"/api/merge-sessions/{merge['id']}/resolutions", json={
        "expected_session_version": merge["version"],
        "resolutions": {"order:global": "copy"},
    })
    assert r.status_code == 200, r.text
    resolved = r.json()
    assert resolved["status"] == "resolved"
    stale = client.post(f"/api/merge-sessions/{merge['id']}/resolutions", json={
        "expected_session_version": merge["version"],
        "resolutions": {"order:global": "main"},
    })
    assert stale.status_code == 409
    commit = _commit(client, resolved)
    assert commit.status_code == 201, commit.text
    result = client.post(f"/api/snapshots/{commit.json()['id']}/replay", json={
        "probes": ["172.31.0.0/16"]}).json()
    assert result["results"][0]["final_action"] == "deny"


def test_semantic_equivalent_rewrite_is_not_conflict(client):
    pid = _make(client, "equiv")
    rule = {"rid": "same", "seq": 10, "prefix": "10.0.0.0/8",
            "action": "permit", "le": 24, "remark": "base"}
    _rules(client, pid, [rule])
    s1 = _snapshot(client, pid, "base")
    wc = _wc(client, pid, "carol", s1["id"])

    _rules(client, pid, [{**rule, "remark": "mainline note"}])
    _snapshot(client, pid, "main-note")
    wc = client.get(f"/api/workcopies/{wc['id']}").json()
    wc = _wc_edit(client, wc, [{**rule, "remark": "copy note"}])
    merge = _preview(client, wc)
    assert merge["status"] in ("ready", "equivalent")
    assert merge["analysis"]["conflicts"] == []
    assert merge["analysis"]["semantic_equivalences"]
    assert merge["candidate_payload"] is not None


def test_repeated_commit_and_concurrent_resolution_have_one_successor(client):
    pid = _make(client, "idempotent")
    base = [{"rid": "a", "seq": 10, "prefix": "10.0.0.0/8", "action": "deny"}]
    _rules(client, pid, base)
    s1 = _snapshot(client, pid, "base")
    wc = _wc(client, pid, "dave", s1["id"])
    _rules(client, pid, base + [
        {"rid": "m", "seq": 20, "prefix": "192.0.2.0/24", "action": "permit"}])
    s2 = _snapshot(client, pid, "main")
    wc = client.get(f"/api/workcopies/{wc['id']}").json()
    wc = _wc_edit(client, wc, base + [
        {"rid": "c", "seq": 30, "prefix": "198.51.100.0/24", "action": "permit"}])
    merge = _preview(client, wc)
    first = _commit(client, merge)
    assert first.status_code == 201
    second = _commit(client, merge)
    assert second.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    snaps = client.get(f"/api/policies/{pid}/snapshots").json()
    assert [s["id"] for s in snaps if s["version"] == s2["version"] + 1] == [first.json()["id"]]


def test_pending_merge_and_original_snapshots_survive_restart(client):
    pid = _make(client, "restart")
    outside = {"rid": "outside", "seq": 10, "prefix": "8.0.0.0/8", "action": "permit"}
    narrow = {"rid": "narrow", "seq": 20, "prefix": "172.31.0.0/16", "action": "deny"}
    broad = {"rid": "broad", "seq": 30, "prefix": "172.16.0.0/12",
             "action": "permit", "le": 32}
    _rules(client, pid, [narrow, broad, outside])
    s1 = _snapshot(client, pid, "base")
    wc = _wc(client, pid, "erin", s1["id"])
    _rules(client, pid, [
        {**broad, "seq": 5}, {**outside, "seq": 10}, {**narrow, "seq": 20}])
    _snapshot(client, pid, "main")
    wc = client.get(f"/api/workcopies/{wc['id']}").json()
    wc = _wc_edit(client, wc, [
        {**narrow, "seq": 10}, {**outside, "seq": 20}, {**broad, "seq": 30}])
    merge = _preview(client, wc)
    assert merge["status"] == "conflict"

    # A fresh service/client simulates process restart; SQLite data is durable.
    from app.main import app
    with TestClient(app) as client2:
        got = client2.get(f"/api/merge-sessions/{merge['id']}")
        assert got.status_code == 200
        restarted = got.json()
        assert restarted["status"] == "conflict"
        assert restarted["analysis"]["base_snapshot_id"] == s1["id"]
        assert restarted["analysis"]["copy"]["rules"]
        assert client2.get(f"/api/snapshots/{s1['id']}").status_code == 200
        r = client2.post(f"/api/merge-sessions/{merge['id']}/resolutions", json={
            "expected_session_version": restarted["version"],
            "resolutions": {"order:global": "main"},
        })
        assert r.status_code == 200, r.text


def test_abandon_leaves_branches_untouched(client):
    pid = _make(client, "abandon")
    base = [{"rid": "a", "seq": 10, "prefix": "10/8", "action": "deny"}]
    _rules(client, pid, base)
    s1 = _snapshot(client, pid, "base")
    wc = _wc(client, pid, "frank", s1["id"])
    _rules(client, pid, base + [
        {"rid": "m", "seq": 20, "prefix": "192.0.2.0/24", "action": "permit"}])
    s2 = _snapshot(client, pid, "main")
    wc = client.get(f"/api/workcopies/{wc['id']}").json()
    wc = _wc_edit(client, wc, base + [
        {"rid": "c", "seq": 30, "prefix": "198.51.100.0/24", "action": "permit"}])
    merge = _preview(client, wc)
    r = client.post(f"/api/merge-sessions/{merge['id']}/abandon", json={"reason": "nope"})
    assert r.status_code == 200
    assert r.json()["status"] == "abandoned"
    assert client.get(f"/api/snapshots/{s1['id']}").status_code == 200
    assert client.get(f"/api/snapshots/{s2['id']}").status_code == 200
    latest = client.get(f"/api/policies/{pid}/snapshots").json()[0]
    assert latest["id"] == s2["id"]
