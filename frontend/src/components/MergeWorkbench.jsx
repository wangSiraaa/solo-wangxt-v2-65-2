import React, { useEffect, useMemo, useState } from 'react'
import { api } from '../api.js'

const KIND_LABEL = {
  stable: '未改变',
  change: '单边变更（自动合并）',
  'both-identical': '双方相同改写（自动）',
  equivalent: '文本不同但语义等价（自动）',
  auto: '语义验证自动决议',
  conflict: '语义冲突 — 需人工决议',
  'policy-conflict': '整体策略冲突 — 需选择一侧',
  'default-conflict': '隐式默认动作冲突 — 需选择一侧',
}

function RulePile({ rules, tone = '' }) {
  if (!rules || rules.length === 0) return <em className="muted">（空）</em>
  return rules.map((r, i) => (
    <div key={i} className={`ruleline ${r.action} ${tone}`}>
      <b>#{r.seq}</b> <code>{r.prefix}</code> {r.action}
      {r.ge != null && <em> ge {r.ge}</em>}
      {r.le != null && <em> le {r.le}</em>}
      {r.remark && <span className="muted"> · {r.remark}</span>}
    </div>
  ))
}

function HitChain({ title, data, cls }) {
  if (!data) return null
  return (
    <div className={`chaincol ${cls}`}>
      <div className="chainhead">
        {title}：<b className={data.action}>{data.action}</b>
        {data.seq == null ? '（默认）' : ` #${data.seq}`}
      </div>
      <table className="mini-chain">
        <tbody>
          {data.chain.map((c, i) => (
            <tr key={i} className={c.matched ? 'matched'
              : c.contained ? 'contained' : c.seq == null ? 'defaultrow' : ''}>
              <td>{c.seq ?? '默认'}</td>
              <td><code>{c.prefix}</code></td>
              <td className={c.action}>{c.action}</td>
              <td>{c.contained ? '含' : '—'}{c.length_ok ? '/窗✓' : '/窗✗'}</td>
              <td className="muted">{c.reason}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ConflictCard({ hunk, value, onChoose }) {
  const conflict = ['conflict', 'policy-conflict', 'default-conflict']
    .includes(hunk.kind)
  return (
    <div className={`hunk ${hunk.kind}`}>
      <div className="hunk-head">
        <span className="hunk-id">{hunk.id}</span>
        <span className={`hunk-kind k-${hunk.kind}`}>
          {KIND_LABEL[hunk.kind] || hunk.kind}
        </span>
        {hunk.note && <span className="muted">— {hunk.note}</span>}
        {conflict && (
          <span className="decide-btns">
            <button className={value === 'main' ? 'pick mainpick' : ''}
              onClick={() => onChoose(hunk.id, 'main')}>采用主线</button>
            <button className={value === 'work' ? 'pick workpick' : ''}
              onClick={() => onChoose(hunk.id, 'work')}>采用副本</button>
            {value && <button className="mini"
              onClick={() => onChoose(hunk.id, null)}>清除</button>}
          </span>
        )}
      </div>

      <div className="sides-grid">
        <div><h5>基线 B</h5><RulePile rules={hunk.base_rules} /></div>
        <div><h5 className="maintext">主线 M</h5><RulePile rules={hunk.main_rules} /></div>
        <div><h5 className="worktext">工作副本 W</h5><RulePile rules={hunk.work_rules} /></div>
      </div>

      {hunk.witnesses?.length > 0 && (
        <div className="witnesses">
          <h5>最小见证前缀（决议两侧在此前缀上放行/拒绝相反）与命中链</h5>
          {hunk.witnesses.map((w, i) => (
            <div key={i} className="witness">
              <div className="witness-prefix">
                <code className="chip big">{w.prefix}</code>
                <span className="maintext">主线 → <b className={w.main_action}>{w.main_action}</b>{w.main_seq != null && ` #${w.main_seq}`}</span>
                <span className="worktext">副本 → <b className={w.work_action}>{w.work_action}</b>{w.work_seq != null && ` #${w.work_seq}`}</span>
              </div>
              <div className="chains">
                <HitChain title="基线" data={w.base} cls="" />
                <HitChain title="主线" data={w.main} cls="mchain" />
                <HitChain title="副本" data={w.work} cls="wchain" />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function MergeWorkbench({ policy }) {
  const [copies, setCopies] = useState([])
  const [wcId, setWcId] = useState('')
  const [merge, setMerge] = useState(null)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')
  const [editorRules, setEditorRules] = useState('')
  const [probesText, setProbesText] = useState(
    policy.family === 4 ? '172.31.0.0/16\n10.0.0.0/8\n8.8.8.8/32'
      : '2001:db8::/32\n2001:db8:1::/48')
  const [cv, setCv] = useState(null)

  const loadCopies = () => api.workingCopies(policy.id).then(setCopies)
  useEffect(() => { loadCopies() }, [policy.id])

  const wc = useMemo(() => copies.find((c) => c.id === Number(wcId)),
    [copies, wcId])

  useEffect(() => {
    if (wc) setEditorRules(JSON.stringify(wc.payload, null, 2))
  }, [wcId]) // eslint-disable-line

  async function fork() {
    setErr(''); setMsg('')
    const name = `copy-${Date.now().toString(36)}`
    try {
      const c = await api.createWorkingCopy(policy.id, { name })
      setWcId(c.id)
      setMsg(`已从基线快照创建工作副本 #${c.id}（${name}）`)
      loadCopies()
    } catch (e) { setErr(e.message) }
  }

  async function saveCopy() {
    setErr(''); setMsg('')
    try {
      const payload = JSON.parse(editorRules)
      const c = await api.saveWorkingCopy(
        wcId, payload, wc ? wc.version : null)
      setMsg(`已保存，工作副本版本 v${c.version}（共 ${c.ops.length} 个操作）`)
      loadCopies()
    } catch (e) { setErr('保存失败：' + e.message) }
  }

  async function preview() {
    setErr(''); setMsg(''); setCv(null); setBusy(true)
    try {
      const mid = merge?.id
      const m = await api.mergePreview(Number(wcId), mid ?? undefined)
      setMerge(m)
      setMsg(m.merge_status === 'clean'
        ? '三方合并干净，可直接提交'
        : `检测到 ${m.summary.conflicts} 处需人工决议的语义冲突`)
    } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }

  async function decide(id, side) {
    const next = { ...(merge.resolutions || {}) }
    if (side) next[id] = side
    else delete next[id]
    try {
      setMerge(await api.mergeDecide(merge.id, next))
    } catch (e) { setErr(e.message) }
  }

  async function commit() {
    setErr(''); setMsg(''); setBusy(true)
    try {
      const r = await api.mergeCommit(merge.id, '')
      const s = r.snapshot
      setMsg(r.idempotent
        ? `幂等返回：后继快照 v${s.version}（未重复创建）`
        : `✓ 已原子生成唯一后继快照 v${s.version}`)
      setMerge(await api.mergeGet(merge.id))
    } catch (e) { setErr('提交被阻止：' + e.message) }
    finally { setBusy(false) }
  }

  async function abandon() {
    setErr(''); setMsg('')
    await api.mergeAbandon(merge.id)
    setMsg('已放弃合并；未创建快照，主线与工作副本均未改变')
    setMerge(await api.mergeGet(merge.id))
  }

  async function runProbes() {
    setErr(''); setCv(null)
    try {
      const probes = probesText.split(/[\s,]+/).filter(Boolean)
      setCv(await api.mergeCrossValidate(merge.id, probes))
    } catch (e) { setErr(e.message) }
  }

  const unresolved = (merge?.hunks || []).filter((h) =>
    ['conflict', 'policy-conflict', 'default-conflict'].includes(hunkKind(h))
    && !merge.resolutions?.[h.id])
  function hunkKind(h) { return h.kind }

  return (
    <div className="merge-bench">
      <div className="bar">
        <span>并发语义三方合并工作台 · 策略 <b>{policy.name}</b></span>
        <select value={wcId} onChange={(e) => setWcId(e.target.value)}>
          <option value="">— 选择工作副本 —</option>
          {copies.map((c) => (
            <option key={c.id} value={c.id}>
              #{c.id} {c.name} v{c.version}{c.abandoned ? '（已放弃）' : ''}
            </option>
          ))}
        </select>
        <button onClick={fork}>从当前主线快照新建副本</button>
        {wc && <button onClick={preview} disabled={busy}>
          {merge ? '重新预览（主线可能已前进）' : '预览三方合并'}
        </button>}
      </div>

      {err && <div className="error">{err}</div>}
      {msg && <div className="ok">{msg}</div>}

      {wc && (
        <div className="wc-panel">
          <div className="wc-meta">
            <span>副本 #{wc.id} {wc.name}</span>
            <span>基线快照 #{wc.base_snapshot_id}</span>
            <span>编辑版本 v{wc.version}</span>
            <span>操作日志 {wc.ops.length} 条</span>
            <button className="small danger"
              onClick={() => api.abandonWorkingCopy(wc.id).then(loadCopies)}>
              放弃副本（不影响主线）
            </button>
          </div>
          <textarea rows={8} value={editorRules}
            onChange={(e) => setEditorRules(e.target.value)} spellCheck={false} />
          <div><button onClick={saveCopy}>保存编辑（版本+1）</button></div>
        </div>
      )}

      {merge && (
        <>
          <div className={`merge-status ${merge.merge_status}`}>
            <span>三方合并：{merge.merge_status === 'clean'
              ? '✓ 干净，可自动合并' : '⛔ 存在语义冲突'}</span>
            <span>自动 {merge.summary.auto}</span>
            <span>语义等价 {merge.summary.equivalent}</span>
            <span>冲突 {merge.summary.conflicts}</span>
            <span>变更区域 {merge.summary.changed_regions}</span>
            <span>未决议 {unresolved.length}</span>
          </div>

          <div className="hunks">
            {merge.hunks.map((h) => (
              <ConflictCard key={h.id} hunk={h}
                value={merge.resolutions?.[h.id]} onChoose={decide} />
            ))}
          </div>

          <div className="regions-strip">
            <h5>三方语义区域（精确枚举的放行/拒绝集合差异）</h5>
            <div className="region-chips">
              {merge.regions.length === 0 && <span className="muted">无行为变化区域</span>}
              {merge.regions.map((r, i) => (
                <span key={i} className={`regionchip cat-${r.category}`}
                  title={`B=${r.base_action} M=${r.main_action} W=${r.work_action}`}>
                  <code>{r.prefix}</code>
                  <i>{r.category}</i>
                  <b className={r.base_action}>{r.base_action}</b>→
                  <b className={r.main_action}>{r.main_action}</b>/
                  <b className={r.work_action}>{r.work_action}</b>
                </span>
              ))}
            </div>
          </div>

          <div className="commit-bar">
            <button className="primary" onClick={commit}
              disabled={busy || merge.merge_status !== 'clean' && unresolved.length > 0}>
              原子提交（生成唯一后继快照）
            </button>
            <button onClick={abandon}
              disabled={merge.status !== 'open'}>
              放弃合并
            </button>
            {merge.status !== 'open' && <span className="muted">
              事务状态：{merge.status}
              {merge.committed_snapshot_id ? `（快照 #${merge.committed_snapshot_id}）` : ''}
            </span>}
            {merge.merge_status !== 'clean' && unresolved.length > 0 &&
              <span className="error">仍有 {unresolved.length} 处冲突未决议，提交已锁定</span>}
          </div>

          <div className="merge-probes">
            <h5>对合并结果运行现有探针 / FRR 交叉验证</h5>
            <div className="bar">
              <textarea rows={2} value={probesText}
                onChange={(e) => setProbesText(e.target.value)} />
              <button onClick={runProbes}>推演 / 推送 FRR</button>
            </div>
            {cv && (
              <div>
                <span className="muted">
                  FRR 在线：{cv.frr_available ? '是' : '否（仅模拟器结果）'}
                </span>
                {cv.planes.map((p) => (
                  <table key={p.family} className="cv">
                    <thead><tr>
                      <th>IPv{p.family} 探针</th><th>模拟器</th><th>FRR</th>
                    </tr></thead>
                    <tbody>
                      {p.rows.map((row) => (
                        <tr key={row.prefix}
                          className={row.action_match === false ? 'badrow'
                            : row.action_match === true ? 'okrow' : ''}>
                          <td><code>{row.prefix}</code></td>
                          <td className={row.sim_action}>{row.sim_action}{row.sim_seq != null && ` #${row.sim_seq}`}</td>
                          <td>{row.frr_action ?? '—'}{row.frr_seq != null && ` #${row.frr_seq}`}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}
