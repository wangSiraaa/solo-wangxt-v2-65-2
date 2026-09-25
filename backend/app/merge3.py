"""
Semantic three-way merge for ordered first-match prefix policies.

Three sides participate:

    B  base      -- the immutable snapshot the working copy was forked from
    M  mainline  -- the current policy tip at commit time (may have advanced)
    W  work      -- the working copy's edited rules

A plain text / last-writer-wins merge is WRONG for this domain: rules are an
ordered first-match list, so moving lines around changes the actual
permit/deny sets even when no token changes, and two editors can produce
opposite behavior for the same prefix.

The merge therefore runs in two layers:

1. STRUCTURAL (diff3 on the ordered rule lists).  Rule identity is a
   canonical content key (prefix, action, ge, le) -- seq is just an ordering
   and remark text is intentionally excluded, so cosmetic renumbering /
   remark-only edits never create spurious hunks.  The list is split at base
   ranges that are unchanged ("equal") on BOTH sides; every other chunk is a
   hunk:

       stable           kept as-is
       change(side)     only one side rewrote it            -> auto
       both-identical   both sides made the SAME rewrite     -> auto
       conflict         sides rewrote it differently        -> semantic check

2. SEMANTIC (exact prefix-space adjudication).  Prefix space is partitioned
   into uniform cells (reusing trie.py's exact enumeration) and every maximal
   region is classified by the ACTION the three sides produce there:

       unchanged    B == M == W
       main-only    only mainline changed the decision      -> auto (take M)
       work-only    only the copy changed the decision      -> auto (take W)
       both-same    both changed it, to the SAME result     -> auto
       conflict     the two sides produce DIFFERENT actions
                    and BOTH sides structurally edited rules
                    participating at that prefix            -> HUMAN DECISION

   A structural conflict hunk whose possible resolutions produce no action
   difference anywhere is *text-different but semantically equivalent* and
   resolves automatically (the mainline text is kept).  Structural conflict
   hunks that only touch auto-decidable regions are resolved by the verifier
   (the combination that reproduces every expected per-region action wins).

Every human conflict carries the MINIMAL witness prefix set that
distinguishes the two resolutions plus the full hit chains on B/M/W.

The merged rule list is assembled from the hunk resolutions and then fully
re-verified against the expected per-region action: a resolution that only
works in isolation but interacts badly with another hunk is rejected with
witnesses, instead of silently producing a wrong snapshot.

The whole module is pure (no DB) so merge plans are deterministic and can be
recomputed / persisted verbatim.
"""
from __future__ import annotations

import copy
import difflib
import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .engine import Action, Policy, PolicyError, Rule, MAXLEN
from . import trie as triemod


# ---------------------------------------------------------------------------
# Rule normalization
# ---------------------------------------------------------------------------

def canon_prefix(prefix: str, family: Optional[int] = None) -> Tuple[str, int]:
    """Normalize shorthand prefixes; return (canonical, family)."""
    raw = prefix.strip()
    if "/" in raw:
        addr, _, plen = raw.partition("/")
        if ":" not in addr and addr.count(".") < 3:
            octets = addr.split(".") if addr else []
            addr = ".".join(octets + ["0"] * (4 - len(octets)))
            raw = f"{addr}/{plen}"
    net = ipaddress.ip_network(raw, strict=True)
    if family is not None and net.version != family:
        raise PolicyError(f"{raw} is IPv{net.version}, expected IPv{family}")
    return str(net), net.version


def rule_key(rd: dict) -> tuple:
    """Identity of a rule's MATCHING behavior (seq/remark excluded)."""
    prefix, fam = canon_prefix(rd["prefix"])
    return (fam, prefix, rd["action"], rd.get("ge"), rd.get("le"))


def _same_list(a: List[dict], b: List[dict]) -> bool:
    return [rule_key(x) for x in a] == [rule_key(x) for x in b]


def normalize_plane(rules: List[dict], family: int) -> List[dict]:
    """
    Validate every rule against one family and renumber by position
    (10, 20, ..) so seq differences are expressed purely as list ORDER.
    Input order is authoritative; identical content duplicates are removed
    keeping the first (first-match makes later copies dead).
    """
    out: List[dict] = []
    seen = set()
    for rd in rules:
        pfx, fam = canon_prefix(rd["prefix"], family)
        if rd["action"] not in ("permit", "deny"):
            raise PolicyError(f"{pfx}: bad action {rd['action']!r}")
        key = (fam, pfx, rd["action"], rd.get("ge"), rd.get("le"))
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "seq": (len(out) + 1) * 10,
            "prefix": pfx,
            "action": rd["action"],
            "ge": rd.get("ge"),
            "le": rd.get("le"),
            "remark": rd.get("remark", "") or "",
            "family": fam,
        })
    return out


# ---------------------------------------------------------------------------
# Payload <-> engine Policy(ies)
# ---------------------------------------------------------------------------

def planes_of(payload: dict) -> Dict[int, dict]:
    """
    Normalize any snapshot/working-copy payload to::

        {4: {"default_action": "deny", "rules": [...]}, 6: {...}}

    Legacy single-family payloads map to one plane; dual-stack payloads
    (family == 0, {"defaults": {..}, "rules": [..with family..]}) map to two.
    Within a dual-stack payload the planes are contiguous blocks (v4 then
    v6); the position inside a block -- never a possibly-offset global seq --
    is the within-plane order.
    """
    if payload.get("family") in (4, 6):
        fam = payload["family"]
        return {fam: {
            "default_action": payload.get("default_action", "deny"),
            "rules": [dict(r, family=fam) for r in payload.get("rules", [])],
        }}
    rules = payload.get("rules", [])
    defaults = payload.get("defaults") or {}
    grouped: Dict[int, List[dict]] = {}
    for rd in rules:
        fam = rd.get("family") or canon_prefix(rd["prefix"])[1]
        grouped.setdefault(fam, []).append(
            {k: v for k, v in rd.items() if k != "family"})
    planes: Dict[int, dict] = {}
    for fam, fam_rules in grouped.items():
        planes[fam] = {
            "default_action": defaults.get(str(fam),
                                           defaults.get(fam, "deny")),
            "rules": [
                dict(rd, family=fam, seq=(i + 1) * 10)
                for i, rd in enumerate(fam_rules)
            ],
        }
    for fam_str, action in (defaults or {}).items():
        fam = int(fam_str)
        planes.setdefault(fam, {"default_action": action, "rules": []})
    return planes


def plane_policy(name: str, plane: dict) -> Policy:
    """Build an engine Policy for one normalized plane (may have 0 rules)."""
    declared = plane.get("family")
    fam = declared
    rules = []
    for rd in plane["rules"]:
        pfx, f = canon_prefix(rd["prefix"], fam)
        fam = fam or f
        rules.append(Rule(
            seq=int(rd["seq"]), prefix=pfx, action=Action(rd["action"]),
            ge=rd.get("ge"), le=rd.get("le"), remark=rd.get("remark", "") or "",
        ))
    fam = fam or declared
    return Policy(
        name=name, rules=rules,
        default_action=Action(plane["default_action"]), family=fam,
    )


def policies_of_payload(payload: dict, name: str = "merged") -> Dict[int, Policy]:
    out = {}
    for fam, plane in planes_of(payload).items():
        p = plane_policy(name, {**plane, "family": fam})
        if p.family is None:
            p.family = fam          # empty plane: family declared explicitly
        out[fam] = p
    return out


def classify_dispatch(policies: Dict[int, Policy], prefix: str):
    net = ipaddress.ip_network(prefix.strip(), strict=True)
    pol = policies.get(net.version)
    if pol is None:
        raise PolicyError(
            f"{prefix} is IPv{net.version} but the policy has no "
            f"IPv{net.version} plane"
        )
    return pol.classify(str(net))


def normalize_payload(payload: dict) -> dict:
    """Validate + renumber every plane; returns canonical combined payload."""
    planes = planes_of(payload)
    out_rules: List[dict] = []
    defaults: Dict[str, str] = {}
    for fam, plane in sorted(planes.items()):
        norm = normalize_plane(plane["rules"], fam)
        out_rules.extend(norm)
        defaults[str(fam)] = plane["default_action"]
    family = next(iter(planes)) if len(planes) == 1 else 0
    if family in (4, 6):
        return {"family": family,
                "default_action": defaults[str(family)],
                "rules": out_rules}
    return {"family": 0, "defaults": defaults, "rules": out_rules}


def render_frr(payload: dict, name: str) -> str:
    lines: List[str] = []
    for _fam, pol in sorted(policies_of_payload(payload, name).items()):
        if pol.rules:
            lines.append(pol.to_frr_prefix_list())
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Structural three-way diff (diff3 on ordered canonical rule lists)
# ---------------------------------------------------------------------------

@dataclass
class Chunk:
    lo: int
    hi: int
    base: List[dict]
    main: List[dict]
    work: List[dict]
    stable: bool = False
    aligned: bool = False      # single-slot in-place action merge (refined)

    @property
    def changed_sides(self) -> str:
        m = not _same_list(self.base, self.main)
        w = not _same_list(self.base, self.work)
        if m and w:
            return "both"
        return "main" if m else "work" if w else "none"


def _equal_ranges(keys_b, keys_s):
    sm = difflib.SequenceMatcher(None, keys_b, keys_s, autojunk=False)
    return [(b1, b2) for tag, b1, b2, _s1, _s2 in sm.get_opcodes()
            if tag == "equal"]


def _intersect_ranges(a_ranges, b_ranges):
    out, i, j = [], 0, 0
    while i < len(a_ranges) and j < len(b_ranges):
        lo = max(a_ranges[i][0], b_ranges[j][0])
        hi = min(a_ranges[i][1], b_ranges[j][1])
        if lo < hi:
            out.append((lo, hi))
        if a_ranges[i][1] < b_ranges[j][1]:
            i += 1
        else:
            j += 1
    return out


def _side_index_at(opcodes, base_idx: int, after: bool) -> int:
    """
    Side-list index corresponding to a boundary in the base list.

    Boundaries are shared by two adjacent opcode ranges; unequal ranges are
    consulted first so a cut that is both an insert position and an
    equal-range edge is attributed to the insert, not to the equal block.
    """
    for tag, b1, b2, s1, s2 in opcodes:
        if tag == "equal":
            continue
        if b1 == b2:                                  # pure insert at b1
            if base_idx == b1:
                return s2 if after else s1
        elif b1 < base_idx < b2:
            return s2 if after else s1
        elif base_idx == b1 and not after:
            return s1
        elif base_idx == b2 and after:
            return s2
    for tag, b1, b2, s1, s2 in opcodes:
        if tag == "equal" and b1 <= base_idx <= b2:
            return s1 + (base_idx - b1)
    if not opcodes:
        return 0
    return opcodes[-1][4]


def _equal_slice_map(opcodes, base_lo: int, base_hi: int):
    """Side-list index range exactly covering the base-equal range [lo,hi)."""
    for tag, b1, b2, s1, s2 in opcodes:
        if tag != "equal":
            continue
        qlo, qhi = max(base_lo, b1), min(base_hi, b2)
        if qlo < qhi:
            return s1 + (qlo - b1), s1 + (qhi - b1)
    return 0, 0


def _equal_side(side_rules, opcodes, lo: int, hi: int) -> List[dict]:
    i, j = _equal_slice_map(opcodes, lo, hi)
    return side_rules[i:j]


def diff3_chunks(b: List[dict], m: List[dict], w: List[dict]) -> List[Chunk]:
    """
    Split the three ordered lists at ranges that are base-equal on both
    sides; the gaps between sync ranges are the merge hunks.

    Identity for alignment is the *geometry slot* (prefix, ge, le): the
    action is an attribute carried by the slot and merged separately.  That
    keeps two editors changing the ACTION of two adjacent, different rules
    from collapsing into one opaque both-differ hunk, while a genuine
    both-side action change to the SAME slot stays a conflict.
    """
    def slot(rd):
        pfx, fam = canon_prefix(rd["prefix"])
        return (fam, pfx, rd.get("ge"), rd.get("le"))

    kb, km, kw = [slot(r) for r in b], [slot(r) for r in m], [slot(r) for r in w]
    om = difflib.SequenceMatcher(None, kb, km, autojunk=False).get_opcodes()
    ow = difflib.SequenceMatcher(None, kb, kw, autojunk=False).get_opcodes()
    sync = _intersect_ranges(_equal_ranges(kb, km), _equal_ranges(kb, kw))

    raw: List[Chunk] = []
    prev = 0

    def add(lo: int, hi: int, stable: bool):
        if stable:
            # map each side's equal opcode range EXACTLY to [lo,hi), so a
            # pure insert at the boundary is never absorbed into the block
            ms = _equal_side(m, om, lo, hi)
            ws = _equal_side(w, ow, lo, hi)
            bs = b[lo:hi]
            if bs:
                raw.append(Chunk(lo, hi, bs, ms, ws, stable=True))
            return
        ms = m[_side_index_at(om, lo, after=False):
               _side_index_at(om, hi, after=True)]
        ws = w[_side_index_at(ow, lo, after=False):
               _side_index_at(ow, hi, after=True)]
        if lo == hi and not ms and not ws:
            return
        raw.append(Chunk(lo, hi, b[lo:hi], ms, ws, stable=False))

    for lo, hi in sync:
        add(prev, lo, False)
        add(lo, hi, True)
        prev = hi
    add(prev, len(b), False)

    # Refine chunks where BOTH sides differ from base (by full rule identity
    # incl. action) at SLOT granularity so adjacent independent edits never
    # share a hunk.  Note diff3 alignment is by geometry slot, so such a chunk
    # may be flagged stable even though actions changed on both sides.
    # Single-sided chunks (incl. a pure reorder diff3 fragments internally)
    # are taken WHOLE: that side's slice is already a consistent ordered list.
    # Refine EVERY chunk at geometry-slot granularity so independent edits
    # (incl. a single-sided action edit sitting next to an unchanged rule)
    # never collapse into one opaque piece.  The refinement preserves a pure
    # one-sided reorder as a single whole-slice chunk (its anchor slots move,
    # so there are no position-stable anchors to split on).
    return [pc for c in raw for pc in _refine_chunk(c, slot)]


def _slot_eq(a: dict, b: dict) -> bool:
    return _geom(a) == _geom(b)


def _geom(rd: dict) -> tuple:
    pfx, fam = canon_prefix(rd["prefix"])
    return (fam, pfx, rd.get("ge"), rd.get("le"))


def _action_sig(rd: dict) -> tuple:
    return (rd["action"], rd.get("ge"), rd.get("le"))


def _refine_chunk(c: Chunk, slot) -> List[Chunk]:
    """
    Split one diff3 chunk at individual slot boundaries.

    * A slot present at the same aligned position on B/M/W with identical
      action is stable; with one side changing action it is a one-sided
      change; with both sides changing action differently it is a conflict.
    * A run of pure inserts/deletes is kept as one sub-chunk (its ordering
      interaction is adjudicated semantically by the feasibility search).
    """
    if c.stable:
        # possibly several aligned slots; split per slot when actions differ
        pieces: List[Chunk] = []
        run_b, run_m, run_w = [], [], []

        def flush():
            nonlocal run_b, run_m, run_w
            if run_b or run_m or run_w:
                pieces.append(Chunk(0, 0, run_b, run_m, run_w,
                                    stable=_same_list(run_b, run_m)
                                    and _same_list(run_b, run_w)))
                run_b, run_m, run_w = [], [], []

        for bb, mm, ww in zip(c.base, c.main, c.work):
            same_m = rule_key(bb) == rule_key(mm)
            same_w = rule_key(bb) == rule_key(ww)
            # an in-place aligned slot requires the SAME geometry on all
            # three sides; a moved/different slot is a regular (non-aligned)
            # decision piece
            same_geom = (_geom(bb) == _geom(mm) == _geom(ww))
            if not (same_m and same_w):
                flush()
                pieces.append(Chunk(0, 0, [bb], [mm], [ww], stable=False,
                                    aligned=same_geom))
            else:
                run_b.append(bb)
                run_m.append(mm)
                run_w.append(ww)
        flush()
        if len(pieces) == 1 and pieces[0].stable:
            return [c]
        return pieces

    # non-stable chunk: try to align inner slots common to all three sides.
    # For a SINGLE-SIDED chunk (only one side differs) a slot is an anchor
    # only if its position relative to the unchanged side is preserved; a
    # slot that merely EXISTS on both sides but MOVED is not -- otherwise a
    # pure one-sided reorder would fragment into insert/stale/delete pieces.
    sides = c.changed_sides
    common = [s for s in (slot(r) for r in c.base)
              if any(slot(r) == s for r in c.main)
              and any(slot(r) == s for r in c.work)]
    if not common:
        return [c]

    def index_map(rules):
        return {slot(r): i for i, r in enumerate(rules)}

    mb, mm, mw = index_map(c.base), index_map(c.main), index_map(c.work)
    anchor_slots = []
    if sides in ("main", "work"):
        # A single-sided chunk is taken WHOLE unless every slot on the
        # changed side is present at the SAME position (same length and same
        # per-position geometry) as on the unchanged side.  A move changes a
        # position -> whole changed slice (already a consistent list).  Only
        # pure in-place action/remark edits get split per slot.
        def same_positions():
            if sides == "main":
                changed_rules = c.main
            else:
                changed_rules = c.work
            if len(changed_rules) != len(c.base):
                return False
            return all(slot(a) == slot(b)
                       for a, b in zip(changed_rules, c.base))
        if same_positions():
            anchor_slots = [slot(x) for x in c.base]
        else:
            return [c]
    else:
        last = (-1, -1, -1)
        for s in common:
            pos = (mb[s], mm[s], mw[s])
            if all(pos[k] > last[k] for k in range(3)):
                anchor_slots.append(s)
                last = pos
    if not anchor_slots:
        return [c]

    bdict = {slot(r): r for r in c.base}
    mdict = {slot(r): r for r in c.main}
    wdict = {slot(r): r for r in c.work}

    # walk the three lists, emitting gap sub-chunks between anchors; an
    # anchor slot itself becomes an in-place chunk (action 3-way merge).
    result: List[Chunk] = []
    bi = mi = wi = 0
    for s in anchor_slots:
        abi, ami, awi = mb[s], mm[s], mw[s]
        gap_b, gap_m, gap_w = (c.base[bi:abi], c.main[mi:ami], c.work[wi:awi])
        if gap_b or gap_m or gap_w:
            result.append(Chunk(0, 0, gap_b, gap_m, gap_w, stable=False))
        ab, am, aw = bdict[s], mdict[s], wdict[s]
        piece = Chunk(0, 0, [ab], [am], [aw],
                      stable=(rule_key(ab) == rule_key(am)
                              and rule_key(ab) == rule_key(aw)),
                      aligned=True)
        result.append(piece)
        bi, mi, wi = abi + 1, ami + 1, awi + 1
    gap_b, gap_m, gap_w = c.base[bi:], c.main[mi:], c.work[wi:]
    if gap_b or gap_m or gap_w:
        result.append(Chunk(0, 0, gap_b, gap_m, gap_w, stable=False))

    # only accept the refinement if it actually separated decisions; a
    # single surviving both-differ gap means the anchor split bought nothing
    nontrivial = [ch for ch in result if not ch.stable]
    if len(result) == 1 and not result[0].stable:
        return [c]
    return result


# ---------------------------------------------------------------------------
# Exact three-way semantic region partition
# ---------------------------------------------------------------------------

@dataclass
class SRegion:
    family: int
    prefix: str
    depth: int
    b_key: Optional[tuple]
    m_key: Optional[tuple]
    w_key: Optional[tuple]
    b_action: str
    m_action: str
    w_action: str
    category: str
    m_touch: bool
    w_touch: bool


def _net(family: int, addr: int, depth: int):
    """ipaddress.ip_network((addr, depth)) but family-explicit (an integer 0
    address otherwise resolves to IPv4 even on the v6 axis)."""
    cls = ipaddress.IPv4Network if family == 4 else ipaddress.IPv6Network
    return cls((addr, depth))


def _winner_key(depth: int, active: List[Rule]) -> Optional[tuple]:
    for r in active:
        if r.min_len <= depth <= r.max_len:
            return (r.prefix, r.action.value, r.ge, r.le)
    return None


def _winner_rule(depth: int, active: List[Rule]) -> Optional[Rule]:
    for r in active:
        if r.min_len <= depth <= r.max_len:
            return r
    return None


def _enumerate_segments(family: int, pb: Policy, pm: Policy, pw: Policy):
    """
    Exact tiling of prefix space.  Each segment carries the winning rule key
    on all three sides.  Mirrors the enumeration in trie.minimal_witness_set
    but over three policies at once.

    Returns items [depth, start, end, rep_addr, kb, km, kw, ab, am, aw, idx].
    """
    maxlen = MAXLEN[family]
    root = triemod.build_trie(family, pb.rules, pm.rules, pw.rules)
    rows: List[list] = [[] for _ in range(maxlen + 1)]

    def dfs(node: triemod.TrieNode, ab: List[Rule], am: List[Rule],
            aw: List[Rule]):
        rb = sorted(ab + node.rules_a, key=lambda r: r.seq)
        rm = sorted(am + node.rules_b, key=lambda r: r.seq)
        rw = sorted(aw + node.rules_c, key=lambda r: r.seq)
        node_int = int(node.net.network_address)
        children = node.children()

        def winners(k):
            wb = _winner_rule(k, rb)
            wm = _winner_rule(k, rm)
            ww = _winner_rule(k, rw)
            kb = (wb.prefix, wb.action.value, wb.ge, wb.le) if wb else None
            km = (wm.prefix, wm.action.value, wm.ge, wm.le) if wm else None
            kw = (ww.prefix, ww.action.value, ww.ge, ww.le) if ww else None
            return (kb, km, kw,
                    (wb.action if wb else pb.default_action).value,
                    (wm.action if wm else pm.default_action).value,
                    (ww.action if ww else pw.default_action).value)

        k = node.depth
        vals = winners(k)
        idx = node_int >> (maxlen - k)
        rows[k].append([idx, idx + 1, node_int, *vals])

        for gk in range(k + 1, maxlen + 1):
            scale = 1 << (gk - k)
            covered: List[Tuple[int, int]] = []
            for ch in children:
                if ch.depth > gk:
                    continue
                cs = (int(ch.net.network_address) - node_int) >> (maxlen - gk)
                span = 1 << max(0, gk - ch.depth)
                covered.append((cs, cs + span))
            covered.sort()
            gaps, cur = [], 0
            for cs, ce in covered:
                if cs > cur:
                    gaps.append((cur, cs))
                cur = max(cur, ce)
            if cur < scale:
                gaps.append((cur, scale))
            vals = winners(gk)
            base_idx = node_int >> (maxlen - gk)
            for gs, ge2 in gaps:
                rep = node_int + (gs << (maxlen - gk))
                rows[gk].append([base_idx + gs, base_idx + ge2, rep, *vals])

        for ch in children:
            dfs(ch, rb, rm, rw)

    dfs(root, [], [], [])

    items: List[list] = []
    for k in range(maxlen + 1):
        row = sorted(rows[k], key=lambda x: x[0])
        cursor = 0
        for seg in row:
            assert seg[0] == cursor, ("tiling gap", family, k, seg[0], cursor)
            cursor = seg[1]
            items.append([k, *seg, len(items)])
        assert cursor == (1 << k), ("tiling incomplete", family, k)
    return items


def _maximal_regions(family: int, items: List[list]):
    """DSU-merge adjacent / nesting blocks with identical 3-side signature."""
    import bisect

    parent = list(range(len(items)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    # item layout: [depth, start, end, rep, kb, km, kw, ab, am, aw, id]
    by_depth: Dict[int, List[list]] = {}
    for it in items:
        by_depth.setdefault(it[0], []).append(it)
    for k in by_depth:
        by_depth[k].sort(key=lambda x: x[1])

    def sig(it):
        return it[4], it[5], it[6]

    for k, row in by_depth.items():
        for a, b in zip(row, row[1:]):
            if a[2] == b[1] and sig(a) == sig(b):
                union(a[-1], b[-1])

    def window_ok(key, depth_a, depth_b):
        if key is None:
            return True
        net = ipaddress.ip_network(key[0])
        base = net.prefixlen
        ge, le = key[2], key[3]
        mn = ge if ge is not None else base
        mx = le if le is not None else (
            base if ge is None else MAXLEN[net.version])
        return mn <= depth_a <= mx and mn <= depth_b <= mx

    for k in range(1, max(by_depth) + 1):
        if k not in by_depth or k - 1 not in by_depth:
            continue
        up = by_depth[k - 1]
        up_starts = [u[1] for u in up]
        for it in by_depth[k]:
            ps, pe = it[1] >> 1, ((it[2] - 1) >> 1) + 1
            t = max(0, bisect.bisect_right(up_starts, ps) - 1)
            covering = []
            u = t
            while u < len(up) and up[u][1] < pe:
                if up[u][2] > ps:
                    covering.append(up[u])
                u += 1
            if not covering:
                continue
            ok = all(sig(p) == sig(it) for p in covering)
            if ok:
                for key in (it[4], it[5], it[6]):
                    if not all(window_ok(key, k, p[0]) for p in covering):
                        ok = False
                        break
            if ok:
                for p in covering:
                    union(it[-1], p[-1])

    rep: Dict[int, list] = {}
    for it in items:
        r = find(it[-1])
        cur = rep.get(r)
        if cur is None or it[0] < cur[0] or (it[0] == cur[0]
                                             and it[1] < cur[1]):
            rep[r] = it
    return list(rep.values())


def _active_keys(pol: Policy, net) -> List[tuple]:
    """Canonical keys of rules whose base contains the cell (rule ORDER kept).

    A side structurally 'touches' a prefix iff this ordered containment list
    differs from base: that captures edits to order, geometry or identity of
    every rule that could participate there, while ignoring edits elsewhere.
    """
    return [(r.prefix, r.action.value, r.ge, r.le)
            for r in pol.rules if r.contains(net)]


def _categorize(ab: str, am: str, aw: str, m_touch: bool, w_touch: bool) -> str:
    if ab == am == aw:
        return "unchanged"
    if am == aw:
        return "both_same"                       # convergent change -> auto
    # actions on the two sides differ
    if am == ab and not m_touch:
        return "work_only" if w_touch else "unchanged"
    if aw == ab and not w_touch:
        return "main_only" if m_touch else "unchanged"
    if m_touch and w_touch:
        return "conflict"
    return "main_only" if m_touch else "work_only" if w_touch else "unchanged"


def _regions_from_items(family: int, items: List[list],
                        pb: Policy, pm: Policy, pw: Policy,
                        only_changed: bool) -> List[SRegion]:
    # an edit to the implicit default action is an edit that participates in
    # every region decided by the default (winner key is None)
    m_default_edited = pm.default_action != pb.default_action
    w_default_edited = pw.default_action != pb.default_action
    out: List[SRegion] = []
    for it in _maximal_regions(family, items):
        depth, _s, _e, rep_addr, kb, km, kw, ab, am, aw = it[:10]
        net = _net(family, rep_addr, depth)
        m_touch = (_active_keys(pm, net) != _active_keys(pb, net)
                   or (m_default_edited and km is None))
        w_touch = (_active_keys(pw, net) != _active_keys(pb, net)
                   or (w_default_edited and kw is None))
        cat = _categorize(ab, am, aw, m_touch, w_touch)
        if only_changed and cat == "unchanged":
            continue
        out.append(SRegion(family, str(net), depth, kb, km, kw,
                           ab, am, aw, cat, m_touch, w_touch))
    out.sort(key=lambda r: (r.depth,
                            int(ipaddress.ip_network(r.prefix).network_address)))
    return out


def three_way_regions(family: int, pb: Policy, pm: Policy, pw: Policy,
                      only_changed: bool = True) -> List[SRegion]:
    items = _enumerate_segments(family, pb, pm, pw)
    return _regions_from_items(family, items, pb, pm, pw, only_changed)


def _expected_action(region: SRegion) -> Optional[str]:
    """Action the merged policy MUST show in an auto-decidable region."""
    return {"unchanged": region.b_action,
            "main_only": region.m_action,
            "work_only": region.w_action,
            "both_same": region.m_action}.get(region.category)


# ---------------------------------------------------------------------------
# Merged assembly
# ---------------------------------------------------------------------------

def _rule_dicts(chunk_rules: List[dict]) -> List[dict]:
    return [{k: v for k, v in r.items()} for r in chunk_rules]


def assemble_plane(chunks: List[Chunk], resolutions: Dict[int, str],
                   ) -> List[dict]:
    """
    Build the merged ordered rules of one plane from chunks.

    resolutions maps the chunk INDEX to 'main'/'work' for structural
    conflict chunks; unresolved ones fall back to the BASE slice (neutral)
    so previews still classify everywhere.
    """
    out: List[dict] = []
    for i, c in enumerate(chunks):
        if c.stable:
            out.extend(_rule_dicts(c.base))
            continue
        sides = c.changed_sides
        if sides == "none":
            out.extend(_rule_dicts(c.base))
        elif sides == "main":
            out.extend(_rule_dicts(c.main))
        elif sides == "work":
            out.extend(_rule_dicts(c.work))
        else:
            choice = resolutions.get(i)
            if choice == "work":
                out.extend(_rule_dicts(c.work))
            elif choice == "main":
                out.extend(_rule_dicts(c.main))
            elif _same_list(c.main, c.work):
                out.extend(_rule_dicts(c.main))          # identical rewrites
            else:
                out.extend(_rule_dicts(c.base))          # unresolved -> neutral
    # assembled order is authoritative; seqs are positional
    for k, rd in enumerate(out):
        rd["seq"] = (k + 1) * 10
    return out


def merge_default_action(b: str, m: str, w: str) -> Tuple[str, Optional[str]]:
    """Scalar 3-way merge of the implicit default; returns (action, side)."""
    if m == w:
        return m, None if m == b else "both"
    if m == b:
        return w, "work"
    if w == b:
        return m, "main"
    return b, "conflict"


# ---------------------------------------------------------------------------
# Hit chains for witnesses
# ---------------------------------------------------------------------------

def _chain_brief(hit) -> dict:
    d = hit.to_dict()
    return {
        "action": d["final_action"],
        "seq": d["matched_seq"],
        "terminal": d["terminal"],
        "chain": d["chain"],
    }


def _witness_record(pb: Policy, pm: Policy, pw: Policy, prefix: str,
                    main_action: str, work_action: str,
                    main_seq=None, work_seq=None) -> dict:
    return {
        "prefix": prefix,
        "main_action": main_action,
        "work_action": work_action,
        "main_seq": main_seq,
        "work_seq": work_seq,
        "base": _chain_brief(pb.classify(prefix)),
        "main": _chain_brief(pm.classify(prefix)),
        "work": _chain_brief(pw.classify(prefix)),
    }


# ---------------------------------------------------------------------------
# Per-plane adjudication
# ---------------------------------------------------------------------------

@dataclass
class PlaneDecision:
    hunks: List[dict]                 # per-chunk records (kind/side/witnesses)
    auto_resolutions: Dict[int, str]  # structural conflict idx -> side
    regions: List[SRegion]
    merged_default: str
    default_clash: Optional[dict]
    policy_conflict: Optional[dict]   # plane-level leftover conflict
    policies: Tuple[Policy, Policy, Policy]
    auto_default_side: Optional[str] = None  # forced default-action choice


def _plane_from_rules(name: str, fam: int, default_action: str,
                      rules: List[dict]) -> Policy:
    p = plane_policy(name, {"family": fam, "default_action": default_action,
                            "rules": rules})
    if p.family is None:
        p.family = fam
    return p


def _sig_at(pol: Policy, prefix: str):
    hit = pol.classify(prefix)
    return (hit.final_action.value,
            (hit.rule.prefix, hit.rule.action.value, hit.rule.ge, hit.rule.le)
            if hit.rule else None)


def _same_region(pb: Policy, pm: Policy, pw: Policy, a: str, b: str) -> bool:
    return (_sig_at(pb, a) == _sig_at(pb, b)
            and _sig_at(pm, a) == _sig_at(pm, b)
            and _sig_at(pw, a) == _sig_at(pw, b))


def _assemble_decision_plane(name: str, fam: int, chunks: List[Chunk],
                             decisions: Dict[int, str],
                             default_action: str,
                             default_choice: Optional[str] = None,
                             default_spec: Optional[dict] = None) -> Policy:
    """
    Assemble one plane with an explicit choice for every decision variable.

    Every non-stable chunk offers a two-valued choice between the two slices
    that actually exist on the three sides:

        both-differ : 'main' -> main slice, 'work' -> work slice
        main-only   : 'main' -> main slice, 'work' -> BASE slice
        work-only   : 'main' -> BASE slice, 'work' -> work slice
        identical   : same text either way

    The implicit default action is a scalar decision: default_choice
    'main'/'work' picks that side; default_spec supplies the already-3-way-
    merged value otherwise.
    """
    if default_choice == "main" and default_spec:
        default_action = default_spec["main"]
    elif default_choice == "work" and default_spec:
        default_action = default_spec["work"]
    out: List[dict] = []
    for i, c in enumerate(chunks):
        if c.stable:
            out.extend(_rule_dicts(c.base))
            continue
        sides = c.changed_sides
        if sides == "none":
            out.extend(_rule_dicts(c.base))
        elif sides == "main":
            out.extend(_rule_dicts(c.main)
                       if decisions.get(i, "main") == "main"
                       else _rule_dicts(c.base))
        elif sides == "work":
            out.extend(_rule_dicts(c.work)
                       if decisions.get(i, "work") == "work"
                       else _rule_dicts(c.base))
        elif c.aligned and c.main and c.work and \
                c.main[0]["action"] == c.work[0]["action"]:
            # convergent in-place action edit: both sides set the same value
            out.extend(_rule_dicts(c.main))
        elif _same_list(c.main, c.work):
            out.extend(_rule_dicts(c.main))
        else:
            out.extend(_rule_dicts(c.main)
                       if decisions.get(i, "main") == "main"
                       else _rule_dicts(c.work))
    for k, rd in enumerate(out):
        rd["seq"] = (k + 1) * 10
    return _plane_from_rules(name, fam, default_action,
                             normalize_plane(out, fam))


def _adjudicate_plane(name: str, fam: int,
                      bplane: dict, mplane: dict, wplane: dict,
                      ) -> PlaneDecision:
    b = normalize_plane(bplane["rules"], fam)
    m = normalize_plane(mplane["rules"], fam)
    w = normalize_plane(wplane["rules"], fam)
    pb = _plane_from_rules(name, fam, bplane["default_action"], b)
    pm = _plane_from_rules(name, fam, mplane["default_action"], m)
    pw = _plane_from_rules(name, fam, wplane["default_action"], w)

    chunks = diff3_chunks(b, m, w)
    items = _enumerate_segments(fam, pb, pm, pw)
    regions_all = _regions_from_items(fam, items, pb, pm, pw,
                                      only_changed=False)
    changed = [r for r in regions_all if r.category != "unchanged"]
    conflict_regions = [r for r in regions_all if r.category == "conflict"]
    auto_expect = [(r.prefix, _expected_action(r))
                   for r in regions_all if r.category != "conflict"]

    # scalar 3-way merge of the implicit default action
    merged_default, dside = merge_default_action(
        bplane["default_action"], mplane["default_action"],
        wplane["default_action"])
    default_spec = {"base": bplane["default_action"],
                    "main": mplane["default_action"],
                    "work": wplane["default_action"]}
    default_is_var = dside == "conflict"
    default_action = (mplane["default_action"] if default_is_var
                      else merged_default)

    # Decision variables: every non-stable hunk offering two different
    # slices.  Single-sided hunks participate because rejecting that side
    # (keeping BASE) is a real merge alternative.
    vars_idx = [
        i for i, c in enumerate(chunks)
        if not c.stable and c.changed_sides != "none" and not (
            c.changed_sides == "both" and (
                _same_list(c.main, c.work) or
                (c.aligned and c.main and c.work and
                 c.main[0]["action"] == c.work[0]["action"])))
    ]

    DEF_KEY = "__default__"

    def assemble(dec: Dict) -> Policy:
        rule_dec = {k: v for k, v in dec.items() if k != DEF_KEY}
        dchoice = dec.get(DEF_KEY) if default_is_var else None
        return _assemble_decision_plane(
            name, fam, chunks, rule_dec, default_action,
            default_choice=dchoice, default_spec=default_spec)

    def auto_violations(pol: Policy):
        return [pfx for pfx, want in auto_expect
                if pol.classify(pfx).final_action.value != want]

    # decision variables: rule-hunk indices plus (when the implicit default
    # is a genuine 3-way clash) the default-action choice.
    var_keys = list(vars_idx) + ([DEF_KEY] if default_is_var else [])

    # ------------------------------------------------------------------
    # Decision policy (acceptance contract):
    #
    #   * A CONFLICT region is, by definition, a prefix where BOTH sides
    #     touched the participating rules AND the two sides produce
    #     opposite actions.  Such a region ALWAYS needs a human -- the merge
    #     never silently picks a side even when only one global assignment
    #     satisfies the non-conflicting auto regions.  This implements the
    #     "two editors reorder -> the same prefix flips the opposite way ->
    #     block the commit" requirement.
    #
    #   * The bounded feasibility search below only FIXES structural hunks
    #     that cannot affect any conflict region (their value is forced by
    #     the unchanged / main-only / work-only / both-same regions), and
    #     distinguishes text-different-but-semantically-equivalent hunks.
    # ------------------------------------------------------------------
    human: Dict[int, List[dict]] = {}
    fixed: Dict = {}
    canonical: Dict = {key: "main" for key in var_keys}
    default_human = False

    conflict_pfx = {r.prefix: r for r in conflict_regions}

    def outcomes(pol):
        return {pfx: pol.classify(pfx).final_action.value
                for pfx in conflict_pfx}

    # Per rule decision variable: human iff flipping it changes the action
    # at ANY conflict region (witness = minimal set of such prefixes).
    for key in var_keys:
        if key == DEF_KEY:
            continue
        a = assemble({**canonical, key: "main"})
        bpol = assemble({**canonical, key: "work"})
        sa, sb = outcomes(a), outcomes(bpol)
        hits = []
        for pfx in conflict_pfx:
            if sa.get(pfx) != sb.get(pfx):
                hits.append(_witness_record(
                    pb, pm, pw, pfx, sa[pfx], sb[pfx],
                    a.classify(pfx).rule.seq if a.classify(pfx).rule else None,
                    bpol.classify(pfx).rule.seq if bpol.classify(pfx).rule else None))
        if hits:
            human[key] = hits

    covered = {
        pfx for hs in human.values() for w in hs for pfx in conflict_pfx
        if _same_region(pb, pm, pw, w["prefix"], pfx)}
    plane_conflict_regions = [
        r for r in conflict_regions if r.prefix not in covered]

    if default_is_var:
        a = assemble({**canonical, DEF_KEY: "main"})
        bpol = assemble({**canonical, DEF_KEY: "work"})
        sa, sb = outcomes(a), outcomes(bpol)
        if any(sa.get(pfx) != sb.get(pfx) for pfx in conflict_pfx):
            default_human = True

    # Fix every NON-human variable with a bounded feasibility search,
    # holding human variables at their canonical (main) value.
    free_nonhuman = [k for k in var_keys if k not in human]
    SOLUTION_CAP = 4096
    feasible: List[Dict] = []

    def dfs(k: int, dec: Dict):
        if len(feasible) >= SOLUTION_CAP:
            return
        if k == len(free_nonhuman):
            full = {**{key: "main" for key in human}, **dec}
            if not auto_violations(assemble(full)):
                feasible.append(dict(dec))
            return
        key = free_nonhuman[k]
        dec[key] = "main"
        dfs(k + 1, dec)
        dec[key] = "work"
        dfs(k + 1, dec)
        del dec[key]

    dfs(0, {})

    if feasible:
        val_sets = {key: {d.get(key) for d in feasible}
                    for key in free_nonhuman}
        for key in free_nonhuman:
            vals = val_sets[key]
            fixed[key] = next(iter(vals)) if len(vals) == 1 else "main"
    else:
        # no combination of the non-human hunks satisfies every auto region;
        # hold them at main and let commit verification surface the residual
        for key in free_nonhuman:
            fixed[key] = "main"

    undecidable_regions = plane_conflict_regions

    # ---- per-chunk records ------------------------------------------------
    rule_fixed = {i: v for i, v in fixed.items() if i != DEF_KEY}
    hunk_records: List[dict] = []
    for i, c in enumerate(chunks):
        sides = c.changed_sides
        if c.stable or sides == "none":
            kind, side, note, merged = "stable", None, None, c.base
        elif i in human:
            kind, side, note = "conflict", None, None
            merged = c.base
        elif sides == "both" and (_same_list(c.main, c.work) or (
                c.aligned and c.main and c.work and
                c.main[0]["action"] == c.work[0]["action"])):
            kind, side, note, merged = "both-identical", "both", None, c.main
        elif sides in ("main", "work"):
            kind, side, note = "change", sides, None
            merged = c.main if sides == "main" else c.work
        else:
            chosen = rule_fixed.get(i, "main")
            a = assemble({**fixed, i: "main"})
            bpol = assemble({**fixed, i: "work"})
            if not triemod.minimal_witness_set(a, bpol):
                kind = "equivalent"
                side = "both"
                note = "两侧文本不同但在整个前缀空间上行为完全等价；采用主线文本"
                merged = c.main
            else:
                kind = "auto"
                side = chosen
                note = "语义验证：该选择是满足全部自动区域约束的唯一可行决议"
                merged = c.main if chosen == "main" else c.work
        hunk_records.append({
            "chunk": c, "kind": kind, "side": side, "note": note,
            "merged": merged, "witnesses": human.get(i, []),
        })

    default_clash = None
    if default_is_var:
        # a genuine scalar 3-way clash of the implicit default ALWAYS needs a
        # human choice (it is itself a conflict on the unmatched space)
        clash_wits = []
        a = assemble({**canonical, DEF_KEY: "main"})
        bpol = assemble({**canonical, DEF_KEY: "work"})
        for wt in triemod.minimal_witness_set(a, bpol):
            clash_wits.append(_witness_record(
                pb, pm, pw, wt.prefix,
                wt.old_action.value, wt.new_action.value,
                wt.old_seq, wt.new_seq))
        if not clash_wits:
            root = "0.0.0.0/0" if fam == 4 else "::/0"
            clash_wits = [_witness_record(
                pb, pm, pw, root,
                pm.classify(root).final_action.value,
                pw.classify(root).final_action.value)]
        default_clash = {
            "family": fam,
            "base": bplane["default_action"],
            "main": mplane["default_action"],
            "work": wplane["default_action"],
            "witnesses": clash_wits,
        }
    if default_is_var and feasible and not default_human:
        merged_default = default_spec[forced[DEF_KEY]]

    policy_conflict = None
    if undecidable_regions:
        policy_conflict = {
            "family": fam,
            "witnesses": [
                _witness_record(pb, pm, pw, r.prefix,
                                r.m_action, r.w_action)
                for r in undecidable_regions
            ],
        }

    # only BOTH-differ hunks are decision variables the assembler needs an
    # explicit side for; single-sided change hunks always take their one
    # changed side by default and must never appear in auto_resolutions (a
    # stray 'main' there would wrongly reject a work-only insert).
    both_differ_idx = {
        i for i, c in enumerate(chunks)
        if not c.stable and c.changed_sides == "both"
        and not (c.aligned and c.main and c.work
                 and c.main[0]["action"] == c.work[0]["action"])}
    return PlaneDecision(
        hunks=hunk_records,
        auto_resolutions={i: v for i, v in fixed.items()
                          if i != DEF_KEY and i in both_differ_idx},
        regions=changed,
        merged_default=merged_default,
        default_clash=default_clash,
        policy_conflict=policy_conflict,
        policies=(pb, pm, pw),
        auto_default_side=None,
    )


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------

@dataclass
class MergePlan:
    base_payload: dict
    main_payload: dict
    work_payload: dict
    name: str
    planes: Dict[int, PlaneDecision] = field(default_factory=dict)

    # -- hunk id helpers ----------------------------------------------------

    @staticmethod
    def hunk_id(fam: int, idx: int) -> str:
        return f"{fam}:{idx}"

    @staticmethod
    def policy_hunk_id(fam: int) -> str:
        return f"{fam}:policy"

    @staticmethod
    def default_hunk_id(fam: int) -> str:
        return f"d:{fam}"

    # -- resolutions ---------------------------------------------------------

    def required_resolution_ids(self) -> List[str]:
        out = []
        for fam, pd in self.planes.items():
            for i, h in enumerate(pd.hunks):
                if h["kind"] == "conflict":
                    out.append(self.hunk_id(fam, i))
            if pd.policy_conflict:
                out.append(self.policy_hunk_id(fam))
            if pd.default_clash:
                out.append(self.default_hunk_id(fam))
        return out

    def auto_resolutions(self) -> Dict[str, str]:
        out = {}
        for fam, pd in self.planes.items():
            for i, side in pd.auto_resolutions.items():
                out[self.hunk_id(fam, i)] = side
        return out

    def _plane_resolution_map(self, fam: int,
                              resolutions: Dict[str, str]) -> Dict[int, str]:
        pd = self.planes[fam]
        out = dict(pd.auto_resolutions)
        for i, h in enumerate(pd.hunks):
            r = resolutions.get(self.hunk_id(fam, i))
            if r in ("main", "work"):
                out[i] = r
        return out

    def merged_payload(self, resolutions: Optional[Dict[str, str]] = None
                       ) -> dict:
        resolutions = resolutions or {}
        per_plane: Dict[int, List[dict]] = {}
        defaults: Dict[str, str] = {}
        for fam in sorted(self.planes):
            pd = self.planes[fam]
            choice = resolutions.get(self.default_hunk_id(fam))
            if pd.default_clash:
                default_action = (pd.default_clash[choice]
                                  if choice in ("main", "work")
                                  else pd.default_clash["base"])
            else:
                default_action = pd.merged_default
            defaults[str(fam)] = default_action

            policy_side = resolutions.get(self.policy_hunk_id(fam))
            if pd.policy_conflict and policy_side in ("main", "work"):
                # explicit whole-plane choice: take that side's slice of
                # every decision variable
                raw = [h["chunk"] for h in pd.hunks]
                dec = {i: policy_side for i in range(len(raw))
                       if not raw[i].stable}
                pol = _assemble_decision_plane(
                    self.name, fam, raw, dec, default_action)
                per_plane[fam] = normalize_plane(
                    [r.to_dict() for r in pol.rules], fam)
                continue

            res = self._plane_resolution_map(fam, resolutions)
            raw = [h["chunk"] for h in pd.hunks]
            pol = _assemble_decision_plane(
                self.name, fam, raw, res, default_action)
            per_plane[fam] = normalize_plane(
                [r.to_dict() for r in pol.rules], fam)
        if len(self.planes) == 1:
            fam = next(iter(self.planes))
            return {"family": fam, "default_action": defaults[str(fam)],
                    "rules": per_plane[fam]}
        # planes stay independent ordered blocks (v4 then v6); the engine
        # always evaluates one plane at a time.
        combined: List[dict] = []
        for fam in sorted(per_plane):
            for rd in per_plane[fam]:
                combined.append({**rd, "family": fam})
        return {"family": 0, "defaults": defaults, "rules": combined}

    def all_regions(self) -> List[SRegion]:
        out: List[SRegion] = []
        for fam in sorted(self.planes):
            out.extend(self.planes[fam].regions)
        return out

    # -- serialization -------------------------------------------------------

    def to_dict(self, resolutions: Optional[Dict[str, str]] = None) -> dict:
        resolutions = resolutions or {}
        hunk_dicts: List[dict] = []
        auto_count = 0
        equiv_count = 0
        conflict_count = 0
        for fam in sorted(self.planes):
            pd = self.planes[fam]
            for i, h in enumerate(pd.hunks):
                hid = self.hunk_id(fam, i)
                c = h["chunk"]
                kind = h["kind"]
                if kind == "conflict":
                    conflict_count += 1
                elif kind in ("change", "both-identical", "auto"):
                    auto_count += 1
                elif kind == "equivalent":
                    equiv_count += 1
                hunk_dicts.append({
                    "id": hid,
                    "family": fam,
                    "kind": kind,
                    "side": h["side"],
                    "auto_resolved": kind != "conflict",
                    "base_rules": _public_rules(c.base),
                    "main_rules": _public_rules(c.main),
                    "work_rules": _public_rules(c.work),
                    "merged_rules": _public_rules(h["merged"]),
                    "witnesses": h["witnesses"],
                    "resolution": resolutions.get(hid) or (
                        pd.auto_resolutions.get(i)),
                    "note": h["note"],
                })
            if pd.policy_conflict:
                conflict_count += 1
                hid = self.policy_hunk_id(fam)
                hunk_dicts.append({
                    "id": hid, "family": fam, "kind": "policy-conflict",
                    "side": None, "auto_resolved": False,
                    "base_rules": [], "main_rules": [], "work_rules": [],
                    "merged_rules": [],
                    "witnesses": pd.policy_conflict["witnesses"],
                    "resolution": resolutions.get(hid),
                    "note": "冲突区域不能被任何单一规则块解释；"
                            "需整体选择主线或副本一侧",
                })
            if pd.default_clash:
                conflict_count += 1
                hid = self.default_hunk_id(fam)
                d = pd.default_clash
                hunk_dicts.append({
                    "id": hid, "family": fam, "kind": "default-conflict",
                    "side": None, "auto_resolved": False,
                    "base_rules": [], "main_rules": [], "work_rules": [],
                    "merged_rules": [],
                    "witnesses": d["witnesses"],
                    "resolution": resolutions.get(hid),
                    "note": f"隐式默认动作分歧：基线 {d['base']} / "
                            f"主线 {d['main']} / 副本 {d['work']}",
                })

        regions = [{
            "family": r.family, "prefix": r.prefix,
            "base_action": r.b_action, "main_action": r.m_action,
            "work_action": r.w_action, "category": r.category,
            "main_touched": r.m_touch, "work_touched": r.w_touch,
        } for r in self.all_regions()]

        status = "clean" if conflict_count == 0 else "conflicts"
        return {
            "merge_status": status,
            "name": self.name,
            "families": sorted(self.planes),
            "hunks": hunk_dicts,
            "regions": regions,
            "merged_preview": self.merged_payload(resolutions),
            "summary": {
                "hunks": sum(1 for h in hunk_dicts
                             if h["kind"] not in ("stable",)),
                "auto": auto_count,
                "equivalent": equiv_count,
                "conflicts": conflict_count,
                "changed_regions": len(regions),
                "conflict_regions": sum(1 for r in regions
                                        if r["category"] == "conflict"),
            },
        }


def _public_rules(rules: List[dict]) -> List[dict]:
    return [{k: r.get(k) for k in
             ("seq", "prefix", "action", "ge", "le", "remark", "family")}
            for r in rules]


def build_plan(base_payload: dict, main_payload: dict, work_payload: dict,
               name: str = "merged") -> MergePlan:
    """Compute the full three-way merge plan for all address families."""
    bp = planes_of(base_payload)
    mp = planes_of(main_payload)
    wp = planes_of(work_payload)
    fams = sorted(set(bp) | set(mp) | set(wp))

    plan = MergePlan(
        base_payload=copy.deepcopy(base_payload),
        main_payload=copy.deepcopy(main_payload),
        work_payload=copy.deepcopy(work_payload),
        name=name,
    )
    for fam in fams:
        plan.planes[fam] = _adjudicate_plane(
            name, fam,
            bp.get(fam, {"default_action": "deny", "rules": []}),
            mp.get(fam, {"default_action": "deny", "rules": []}),
            wp.get(fam, {"default_action": "deny", "rules": []}),
        )
    return plan


# ---------------------------------------------------------------------------
# Final verification of a resolved merge
# ---------------------------------------------------------------------------

def verify_commit(plan: MergePlan, resolutions: Dict[str, str]) -> List[dict]:
    """
    Assemble the final policies and verify the WHOLE prefix space:

    * auto regions (unchanged / main-only / work-only / both-same) MUST
      equal their unique required action -- the merge cannot silently
      override a side the other side did not touch;
    * a conflict region that the hard constraints uniquely force (no
      required decision id) MUST be consistent with the assembled policy --
      its action is then just checked to be one of the two sides';
    * a conflict region that genuinely needs a human MUST equal the chosen
      side (hunk decision, plane-level decision, or default-action choice).

    Returns violation witnesses (empty == merge is semantically consistent
    and all human decisions have been made).
    """
    required = set(plan.required_resolution_ids())
    policies = policies_of_payload(plan.merged_payload(resolutions),
                                   plan.name)
    violations: List[dict] = []
    for fam, pd in plan.planes.items():
        pb, pm, pw = pd.policies
        pol = policies[fam]
        items = _enumerate_segments(fam, pb, pm, pw)
        regions = _regions_from_items(fam, items, pb, pm, pw,
                                      only_changed=False)
        dres = resolutions.get(MergePlan.default_hunk_id(fam))
        pres = resolutions.get(MergePlan.policy_hunk_id(fam))
        for r in regions:
            got = pol.classify(r.prefix).final_action.value
            if r.category == "conflict":
                choice = _region_resolution(plan, resolutions, fam, r)
                if choice is None and pres in ("main", "work"):
                    choice = pres
                if choice is None and dres in ("main", "work") and (
                        r.b_key is None or r.m_key is None
                        or r.w_key is None):
                    choice = dres
                if choice is None:
                    if _region_needs_human(plan, fam, r):
                        violations.append({
                            "family": fam, "prefix": r.prefix,
                            "category": r.category,
                            "expected": "resolved", "actual": got,
                            "base_action": r.b_action,
                            "main_action": r.m_action,
                            "work_action": r.w_action,
                            "error": "conflict region without resolution",
                        })
                        continue
                    # forced region: must agree with one side's action
                    if got not in (r.m_action, r.w_action):
                        violations.append({
                            "family": fam, "prefix": r.prefix,
                            "category": r.category,
                            "expected": f"{r.m_action}|{r.w_action}",
                            "actual": got, "base_action": r.b_action,
                            "main_action": r.m_action,
                            "work_action": r.w_action,
                        })
                    continue
                want = r.m_action if choice == "main" else r.w_action
            else:
                want = _expected_action(r)
            if want is not None and got != want:
                violations.append({
                    "family": fam, "prefix": r.prefix, "category": r.category,
                    "expected": want, "actual": got,
                    "base_action": r.b_action, "main_action": r.m_action,
                    "work_action": r.w_action,
                })
    return violations


def _region_needs_human(plan: MergePlan, fam: int,
                        region: SRegion) -> bool:
    """True iff some REQUIRED (human) decision id covers this region."""
    pd = plan.planes[fam]
    pb, pm, pw = pd.policies
    required = set(plan.required_resolution_ids())
    if MergePlan.policy_hunk_id(fam) in required:
        if any(_same_region(pb, pm, pw, w["prefix"], region.prefix)
               for w in (pd.policy_conflict or {}).get("witnesses", [])):
            return True
    if MergePlan.default_hunk_id(fam) in required:
        if any(_same_region(pb, pm, pw, w["prefix"], region.prefix)
               for w in (pd.default_clash or {}).get("witnesses", [])):
            return True
    for i, h in enumerate(pd.hunks):
        if h["kind"] != "conflict":
            continue
        if MergePlan.hunk_id(fam, i) not in required:
            continue
        if any(_same_region(pb, pm, pw, w["prefix"], region.prefix)
               for w in h["witnesses"]):
            return True
    return False


def _region_resolution(plan: MergePlan, resolutions: Dict[str, str],
                       fam: int, region: SRegion) -> Optional[str]:
    """Resolve one conflict region via the hunk whose witnesses cover it."""
    pd = plan.planes[fam]
    pb, pm, pw = pd.policies
    for i, h in enumerate(pd.hunks):
        if h["kind"] != "conflict":
            continue
        r = resolutions.get(MergePlan.hunk_id(fam, i))
        if r not in ("main", "work"):
            continue
        for wit in h["witnesses"]:
            if _same_region(pb, pm, pw, wit["prefix"], region.prefix):
                return r
    return None
