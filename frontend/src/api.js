const BASE = '/api';

async function req(path, { method = 'GET', body } = {}) {
  const r = await fetch(BASE + path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  const data = text ? JSON.parse(text) : null;
  if (!r.ok) throw new Error(data?.detail || `${r.status} ${r.statusText}`);
  return data;
}

export const api = {
  listPolicies: () => req('/policies'),
  getPolicy: (id) => req(`/policies/${id}`),
  createPolicy: (b) => req('/policies', { method: 'POST', body: b }),
  setRules: (id, rules, default_action) =>
    req(`/policies/${id}/rules`, { method: 'PUT', body: { rules, default_action } }),
  analyze: (id) => req(`/policies/${id}/analyze`),
  classify: (id, prefix) =>
    req(`/policies/${id}/classify`, { method: 'POST', body: { prefix } }),
  batch: (id, probes) =>
    req(`/policies/${id}/classify/batch`, { method: 'POST', body: { probes } }),
  trie: (id) => req(`/policies/${id}/trie`),
  snapshots: (id) => req(`/policies/${id}/snapshots`),
  snapshot: (id, label, created_by = 'lab') =>
    req(`/policies/${id}/snapshots`, { method: 'POST', body: { label, created_by } }),
  getSnapshot: (id) => req(`/snapshots/${id}`),
  diff: (a, b) => req('/snapshots/diff', { method: 'POST', body: { old_snapshot_id: a, new_snapshot_id: b } }),
  replay: (id, probes) =>
    req(`/snapshots/${id}/replay`, { method: 'POST', body: { probes } }),
  scenarios: () => req('/scenarios'),
  scenario: (id) => req(`/scenarios/${id}`),
  replayScenario: (id) => req(`/scenarios/${id}/replay`, { method: 'POST' }),
  neighbors: () => req('/neighbors'),
  frrStatus: () => req('/frr/status'),
  crossValidate: (id, probes, node = 'a') =>
    req(`/snapshots/${id}/cross-validate`, { method: 'POST', body: { probes, node } }),
  runs: () => req('/runs'),
  createWorkCopy: (pid, b) => req(`/policies/${pid}/workcopies`, { method: 'POST', body: b }),
  workCopies: (pid) => req(`/policies/${pid}/workcopies`),
  workCopy: (id) => req(`/workcopies/${id}`),
  setWorkCopyRules: (id, rules, default_action, expected_version, note = '') =>
    req(`/workcopies/${id}/rules`, {
      method: 'PUT',
      body: { rules, default_action, expected_version, note },
    }),
  workCopyOps: (id) => req(`/workcopies/${id}/operations`),
  mergePreview: (id, body) => req(`/workcopies/${id}/merge-preview`, { method: 'POST', body }),
  mergeSession: (id) => req(`/merge-sessions/${id}`),
  mergeSessions: (id) => req(`/workcopies/${id}/merge-sessions`),
  resolveMerge: (id, resolutions, expected_session_version) =>
    req(`/merge-sessions/${id}/resolutions`, {
      method: 'POST', body: { resolutions, expected_session_version },
    }),
  validateMerge: (id, probes, node = 'a', run_frr = false) =>
    req(`/merge-sessions/${id}/validate`, {
      method: 'POST', body: { probes, node, run_frr },
    }),
  commitMerge: (id, body) => req(`/merge-sessions/${id}/commit`, { method: 'POST', body }),
  abandonMerge: (id, reason = '') =>
    req(`/merge-sessions/${id}/abandon`, { method: 'POST', body: { reason } }),
  deleteWorkCopy: (id) => req(`/workcopies/${id}`, { method: 'DELETE' }),
};
