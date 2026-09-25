import React, { useEffect, useMemo, useState } from 'react'
import { api } from '../api.js'

function ruleText(r) {
  if (!r) return '—'
  const ge = r.ge == null ? '' : ` ge ${r.ge}`
  const le = r.le == null ? '' : ` le ${r.le}`
  return `#${r.seq} ${r.action} ${r.prefix}${ge}${le}${r.remark ? ` · ${r.remark}` : ''}`
}

function RuleTable({ title, rules, action }) {
  return (
    <details className="merge-payload" open>
      <summary>{title}（{rules.length}）{action && <> · 默认 <b>{action}</b></>}</summary>
      <table className="witness compact">
        <tbody>
          {rules.map((r) => (
            <tr key={`${r.rid}-${r.seq}`} className={r.action}>
              <td><code>{r.seq}</code></td>
              <td><code className="chip">{r.prefix}</code></td>
              <td className={r.action}>{r.action}</td>
              <td>{r.ge ?? '—'}/{r.le ?? '—'}</td>
              <td>{r.remark || ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  )
}

function WitnessCard({ w }) {
  const cls = w.classification
  return (
    <div className={`witness-card ${cls}`}>
      <div className="witness-head">
        <code className="chip big">{w.prefix}</code>
        <span className={`tag ${cls === 'conflict' ? 'bad' : cls.startsWith('auto') ? 'warn' : 'ok'}`}>
          {cls === 'conflict' ? '人工冲突' : cls === 'auto_main' ? '自动采用主线'
            : cls === 'auto_copy' ? '自动采用副本' : '语义等价/共同修改'}
        </span>
        <span>base <b className={w.base.action}>{w.base.action}#{w.base.seq ?? '默认'}</b></span>
        <span>main <b className={w.main.action}>{w.main.action}#{w.main.seq ?? '默认'}</b></span>
        <span>copy <b className={w.copy.action}>{w.copy.action}#{w.copy.seq ?? '默认'}</b></span>
      </div>
      <details>
        <summary>最小见证前缀与三方命中链</summary>
        {['base', 'main', 'copy'].map((side) => (
          <div key={side} className="chain-block">
            <h5>{side} → {w[side].action} #{w[side].seq ?? 'default'}</h5>
            <ol>
              {w[side].chain.map((c, i) => (
                <li key={i} className={c.matched ? 'matched' : c.contained ? 'contained' : ''}>
                  #{c.seq ?? 'default'} {c.prefix} {c.action} · {c.reason}
                </li>
              ))}
            </ol>
          </div>
        ))}
      </details>
    </div>
  )
}

export default function MergeLab({ policy, onChange }) {
  const [copies, setCopies] = useState([])
  const [wcId, setWcId] = useState('')
  const [name, setName] = useState('')
  const [draft, setDraft] = useState('')
  const [merge, setMerge] = useState(null)
  const [res, setRes] = useState({})
  const [probes, setProbes] = useState('')
  const [node, setNode] = useState('a')
  const [runFrr, setRunFrr] = useState(false)
  const [validation, setValidation] = useState(null)
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)

  async function refresh(keepId = true) {
    const cs = await api.workCopies(policy.id)
    setCopies(cs)
    const next = keepId && cs.some((c) => c.id === Number(wcId)) ? wcId : String(cs[0]?.id || '')
    setWcId(next)
    return cs.find((c) => c.id === Number(next))
  }

  useEffect(() => {
    setMerge(null); setRes({}); setMsg(''); setValidation(null)
    refresh(false).catch((e) => setMsg(e.message))
  }, [policy.id])

  const wc = useMemo(() => copies.find((c) => c.id === Number(wcId)) || null, [copies, wcId])
  useEffect(() => {
    if (wc) setDraft(JSON.stringify(wc.current_payload.rules, null, 2))
  }, [wc?.id, wc?.version])

  async function call(fn, ok) {
    setBusy(true); setMsg('')
    try { const out = await fn(); ok?.(out); return out }
    catch (e) { setMsg('错误：' + e.message) }
    finally { setBusy(false) }
  }

  async function createCopy() {
    if (!name.trim()) return setMsg('请填写工作副本名称')
    await call(() => api.createWorkCopy(policy.id, { name: name.trim() }), async (c) => {
      setName(''); const cs = await refresh(false); setWcId(String(c.id))
    })
  }

  async function saveCopy() {
    let rules
    try { rules = JSON.parse(draft) } catch (e) { return setMsg('JSON 错误：' + e.message) }
    await call(() => api.setWorkCopyRules(wc.id, rules, wc.current_payload.default_action, wc.version, 'ui edit'), async () => {
      await refresh(); setMerge(null)
    })
  }

  async function preview(force = false) {
    await call(() => api.mergePreview(Number(wcId), {
      expected_workcopy_version: wc.version, refresh: force,
    }), (m) => { setMerge(m); setRes({}); setValidation(null) })
  }

  async function sendResolutions() {
    if (!merge) return
    await call(() => api.resolveMerge(merge.id, res, merge.version), (m) => {
      setMerge(m); setValidation(null)
    })
  }

  async function validateCandidate() {
    const list = probes.split(/\s+/).filter(Boolean)
    await call(() => api.validateMerge(merge.id, list, node, runFrr), setValidation)
  }

  async function commit() {
    await call(() => api.commitMerge(merge.id, {
      expected_session_version: merge.version,
      label: `merge from workcopy #${wc.id}`,
      validate_probes: probes.split(/\s+/).filter(Boolean),
      node,
      run_frr: runFrr,
    }), async () => {
      await onChange(); const c = await refresh()
      setMerge(null)
    })
  }

  async function abandon() {
    await call(() => api.abandonMerge(merge.id, 'user discarded preview'), () => setMerge(null))
  }

  return (
    <div className="merge-lab">
      <div className="bar wrap">
        <b>语义三方合并工作副本</b>
        <input placeholder="新副本名，如 alice" value={name} onChange={(e) => setName(e.target.value)} />
        <button onClick={createCopy} disabled={busy}>从最新主线创建副本</button>
        <select value={wcId} onChange={(e) => { setWcId(e.target.value); setMerge(null) }}>
          {copies.map((c) => <option key={c.id} value={c.id}>
            #{c.id} {c.name} v{c.version} · {c.status}
          </option>)}
        </select>
        <button onClick={saveCopy} disabled={!wc || busy}>保存副本编辑（递增版本）</button>
        <button onClick={() => preview(false)} disabled={!wc || busy}>预览三方合并</button>
        <button onClick={() => preview(true)} disabled={!wc || busy}>强制刷新预览</button>
        {msg && <span className="error">{msg}</span>}
      </div>

      {wc && (
        <div className="merge-grid">
          <div>
            <h4>副本规则 JSON（保留 rid；换行调整 seq 即换序）</h4>
            <textarea className="json-edit" value={draft} onChange={(e) => setDraft(e.target.value)} />
            <p className="muted">
              基线快照 #{wc.base_snapshot_id}；当前主线 #{wc.latest_snapshot_id}；
              编辑历史为 append-only，保存需要 expected_version={wc.version}。
            </p>
          </div>

          {merge && (
            <div>
              <div className="summary">
                <span>状态：<b className={merge.status === 'conflict' ? 'bad' : 'ok'}>{merge.status}</b></span>
                <span>base v{merge.analysis.base_version}</span>
                <span>main v{merge.analysis.main_version}</span>
                <span>workcopy v{merge.analysis.workcopy_version}</span>
                <span>人工冲突 {merge.analysis.semantic_conflict_count}</span>
              </div>

              <div className="bar wrap">
                <input placeholder="探针前缀，空格分隔" value={probes} onChange={(e) => setProbes(e.target.value)} />
                <select value={node} onChange={(e) => setNode(e.target.value)}>
                  <option value="a">router-a</option><option value="b">router-b</option>
                </select>
                <label><input type="checkbox" checked={runFrr} onChange={(e) => setRunFrr(e.target.checked)} /> 本地 FRR</label>
                <button onClick={validateCandidate} disabled={busy}>运行探针{runFrr ? '/FRR' : ''}</button>
                <button onClick={sendResolutions} disabled={busy || merge.status !== 'conflict'}>应用逐项决议</button>
                <button className="primary" onClick={commit} disabled={busy || merge.status === 'conflict'}>
                  原子提交新快照
                </button>
                <button className="danger" onClick={abandon} disabled={busy}>放弃</button>
              </div>

              {validation && (
                <div className="analysis">
                  <h4>验证结果：{validation.status}</h4>
                  {validation.frr && <div>FRR mismatch: {validation.frr.mismatch_count}</div>}
                  <ol>{validation.simulation.map((r) => <li key={r.order}>
                    {r.prefix} → <b className={r.action}>{r.action}</b> #{r.seq ?? 'default'}
                  </li>)}</ol>
                </div>
              )}

              <h4>自动合并（{merge.analysis.auto_merges.length}）</h4>
              <ul className="decisions">
                {merge.analysis.auto_merges.map((d) => <li key={d.key} className="ok">
                  {d.decision} · {ruleText(d.main || d.copy)}
                </li>)}
              </ul>
              <h4>文本不同但语义等价（{merge.analysis.semantic_equivalences.length}）</h4>
              <ul className="decisions">
                {merge.analysis.semantic_equivalences.map((d, i) => <li key={d.key + i} className="muted">
                  {d.kind}: {ruleText(d.main)} ≡ {ruleText(d.copy)}
                </li>)}
              </ul>

              <h4>必须逐项决议（{merge.analysis.conflicts.length}）</h4>
              {merge.analysis.conflicts.map((c) => (
                <div className="conflict-card" key={c.key}>
                  <div className="bar">
                    <b>{c.kind} {c.key}</b>
                    <label><input type="radio" name={c.key} checked={res[c.key] === 'main'}
                      onChange={() => setRes((x) => ({ ...x, [c.key]: 'main' }))} /> 采用主线</label>
                    <label><input type="radio" name={c.key} checked={res[c.key] === 'copy'}
                      onChange={() => setRes((x) => ({ ...x, [c.key]: 'copy' }))} /> 采用副本</label>
                  </div>
                  <div className="side-cmp">
                    <div><b>base</b><pre>{c.kind === 'default' ? c.base.action : JSON.stringify(c.base, null, 2)}</pre></div>
                    <div><b>main</b><pre>{c.kind === 'default' ? c.main.action : JSON.stringify(c.main, null, 2)}</pre></div>
                    <div><b>copy</b><pre>{c.kind === 'default' ? c.copy.action : JSON.stringify(c.copy, null, 2)}</pre></div>
                  </div>
                  {(c.witnesses || []).map((w) => <WitnessCard key={w.prefix} w={w} />)}
                </div>
              ))}

              <h4>最小行为见证（三方差异）</h4>
              {merge.analysis.witnesses.map((w) => <WitnessCard key={w.prefix} w={w} />)}

              <details>
                <summary>三方规则快照</summary>
                <RuleTable title="base" rules={merge.analysis.base.rules} action={merge.analysis.base.default_action} />
                <RuleTable title="main" rules={merge.analysis.main.rules} action={merge.analysis.main.default_action} />
                <RuleTable title="copy" rules={merge.analysis.copy.rules} action={merge.analysis.copy.default_action} />
                {merge.candidate_payload && <RuleTable title="merged candidate" rules={merge.candidate_payload.rules} action={merge.candidate_payload.default_action} />}
              </details>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
