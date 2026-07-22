"""Generate interactive HTML report from scenario classification + run results."""

from __future__ import annotations

import html
import json
import logging
import re
from pathlib import Path

from ArtifactGen_garak.config_io import DEFAULT_CONFIG_DIR
from ArtifactGen_garak.gate import gate_garak
from scenario_loader import forge_scenario_to_spec, list_scenario_files, load_scenario

log = logging.getLogger(__name__)

RUNS_DIR = Path("runs")
GARAK_OUT = DEFAULT_CONFIG_DIR
GARAK_RUNS_DIR = Path("reports") / "garak_runs"
REPORTS_DIR = Path("reports")

# ---------------------------------------------------------------------------
# AgentDojo feasibility
# ---------------------------------------------------------------------------

_ADJ_FULL_SURFACES = {"user_turn", "tool_return"}
_ADJ_PARTIAL_SURFACES = {"system_prompt", "tool_definition"}
_ADJ_FULL_ORACLES = {"forbidden_call", "output_string", "wrong_target"}
_ADJ_NO_ORACLES = {"state_vs_log"}


def _agentdojo_feasibility(surface: str, oracle: str) -> str:
    s = "full" if surface in _ADJ_FULL_SURFACES else ("partial" if surface in _ADJ_PARTIAL_SURFACES else "no")
    o = "full" if oracle in _ADJ_FULL_ORACLES else "no"
    if s == "no" or o == "no":
        return "no"
    if s == "partial" or o == "partial":
        return "partial"
    return "full"


_SURFACE_LABELS = {
    "user_turn": "user_turn",
    "tool_return": "retrieved_content",
    "system_prompt": "system_prompt",
    "tool_definition": "tool_definition",
    "none": "none",
}

_SURFACE_EXPLANATIONS = {
    "user_turn": "The attacker interacts directly as the user — the malicious payload is the user's own prompt.",
    "tool_return": "The payload is embedded in data returned by a tool call (e.g. a poisoned database record the agent retrieves).",
    "system_prompt": "The payload is injected into the system prompt itself (e.g. via upstream artifact poisoning).",
    "tool_definition": "The payload is embedded in a tool's schema or description, altering how the agent understands the tool.",
    "none": "The injection surface could not be classified for this scenario.",
}

_ORACLE_EXPLANATIONS = {
    "forbidden_call": "Pass/fail checks whether the agent invoked a tool it should not have (e.g. process_refund without authorization).",
    "output_string": "Pass/fail checks whether the agent's output contains sensitive data patterns (e.g. SSNs, salary figures).",
    "wrong_target": "Pass/fail checks whether the agent sent data to the wrong recipient (e.g. email to attacker instead of user).",
    "state_vs_log": "Pass/fail requires comparing runtime state against audit logs — needs stateful inspection beyond text output.",
    "cross_turn": "Pass/fail requires tracking information leakage across separate conversation turns.",
}


def _garak_explanation(surface: str, oracle: str, gate_result: str, gate_reason: str) -> str:
    if gate_result == "full":
        return f"Garak can deliver the payload via {_SURFACE_LABELS.get(surface, surface)} and detect {oracle} by inspecting model output text."
    if gate_result == "partial":
        return f"Garak can deliver via {_SURFACE_LABELS.get(surface, surface)}, but {oracle} is downgraded to output_string — detection is approximate."
    return f"Not feasible: {gate_reason}."


def _agentdojo_explanation(surface: str, oracle: str, feasibility: str) -> str:
    if feasibility == "full":
        return f"AgentDojo runs the full agent loop with {_SURFACE_LABELS.get(surface, surface)} injection and detects {oracle} via clean-vs-attack trace comparison."
    if feasibility == "partial":
        parts = []
        if surface in _ADJ_PARTIAL_SURFACES:
            parts.append(f"{_SURFACE_LABELS.get(surface, surface)} injection requires custom executor configuration")
        if oracle in _ADJ_NO_ORACLES:
            parts.append(f"{oracle} detection relies on state-diff approximation")
        return f"Partially feasible: {'; '.join(parts)}."
    return f"Not feasible: the pipeline cannot exercise {_SURFACE_LABELS.get(surface, surface)} surface with {oracle} oracle."


def _short_name(mechanism_name: str) -> str:
    name = re.split(r"\s+via\s+|\s+through\s+|\s+for\s+", mechanism_name, maxsplit=1)[0]
    name = name.lower().strip()
    if len(name) > 30:
        name = name[:27] + "..."
    return name


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

def _read_file(path: Path) -> str | None:
    if path.exists():
        return path.read_text()
    return None


def _find_run_dir(scenario_id: str) -> Path | None:
    """Find the runs/ directory for a scenario (may have suffix variants)."""
    exact = RUNS_DIR / scenario_id
    if exact.exists():
        return exact
    for d in RUNS_DIR.iterdir():
        if d.is_dir() and d.name.startswith(scenario_id):
            return d
    return None


def _load_agentdojo_results(scenario_id: str) -> dict | None:
    run_dir = _find_run_dir(scenario_id)
    if not run_dir:
        return None
    report_path = run_dir / "report.json"
    if not report_path.exists():
        return None
    try:
        data = json.loads(report_path.read_text())
        if isinstance(data, list) and data:
            return data[0]
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return None


def _load_agentdojo_artifacts(scenario_id: str) -> dict:
    run_dir = _find_run_dir(scenario_id)
    if not run_dir:
        return {}
    return {
        "env_models": _read_file(run_dir / "env_models.py"),
        "tools": _read_file(run_dir / "tools.py"),
        "seed_data": _read_file(run_dir / "seed_data.yaml"),
        "spec": _read_file(run_dir / "spec.json"),
    }


def _load_garak_results(scenario_id: str) -> dict | None:
    """Load summarized Garak run results from reports/garak_runs/{id}/summary.json."""
    summary_path = GARAK_RUNS_DIR / scenario_id / "summary.json"
    if not summary_path.exists():
        return None
    try:
        data = json.loads(summary_path.read_text())
    except Exception:
        return None
    # Keep report payload lean — drop bulky digest if present
    if isinstance(data, dict):
        data = {k: v for k, v in data.items() if k != "digest"}
        outputs = data.get("outputs") or []
        if isinstance(outputs, list) and len(outputs) > 2:
            data["outputs"] = outputs[:2]
    return data


def _module_name(scenario_id: str) -> str:
    return scenario_id.replace("-", "_")


def collect_scenarios() -> list[dict]:
    scenarios = []
    for path in list_scenario_files():
        loaded = load_scenario(path)
        raw = loaded.raw
        scenario_id = loaded.scenario_id

        spec = forge_scenario_to_spec(raw)
        gate_result, gated_spec, gate_reason = gate_garak(spec)

        surface = spec.injection_surface
        oracle = spec.oracle_target
        adj_feas = _agentdojo_feasibility(surface, oracle)

        config_text = _read_file(GARAK_OUT / f"{scenario_id}.yaml")
        probe_code = config_text
        detector_code = (
            f"# Detection settings live in the same config\n"
            f"# (ArtifactGen_garak/configs/{scenario_id}.yaml → detection:)\n"
            if config_text
            else ""
        )
        garak_results = _load_garak_results(scenario_id)

        adj_results = _load_agentdojo_results(scenario_id)
        adj_artifacts = _load_agentdojo_artifacts(scenario_id)
        yaml_source = path.read_text()

        scenarios.append({
            "scenario_id": scenario_id,
            "seed_id": spec.seed_id,
            "threat_id": spec.threat_id,
            "mechanism_name": spec.mechanism_name,
            "short_name": _short_name(spec.mechanism_name),
            "surface": surface,
            "surface_label": _SURFACE_LABELS.get(surface, surface),
            "oracle": oracle,
            "trigger_tool": spec.injection.trigger_tool,
            "injection_goal": spec.injection.goal,
            "surface_explanation": _SURFACE_EXPLANATIONS.get(surface, ""),
            "oracle_explanation": _ORACLE_EXPLANATIONS.get(oracle, ""),
            "garak": {
                "feasibility": "no" if gate_result == "skip" else gate_result,
                "gate_reason": gate_reason,
                "explanation": _garak_explanation(surface, oracle, gate_result, gate_reason),
                "probe_code": probe_code,
                "detector_code": detector_code,
                "results": garak_results,
            },
            "agentdojo": {
                "feasibility": adj_feas,
                "explanation": _agentdojo_explanation(surface, oracle, adj_feas),
                "artifacts": adj_artifacts if any(adj_artifacts.values()) else None,
                "results": adj_results,
            },
            "yaml_source": yaml_source,
        })

    return scenarios


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Scenario Coverage Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    background: #fff;
    color: #1a1a1a;
    line-height: 1.6;
  }

  .container { max-width: 1200px; margin: 0 auto; padding: 32px 24px; }

  h1 { font-size: 28px; font-weight: 700; margin-bottom: 6px; }
  .subtitle { color: #666; font-size: 15px; margin-bottom: 32px; }

  /* Overview table */
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  thead th {
    text-align: left;
    padding: 10px 14px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: #888;
    border-bottom: 2px solid #e5e5e5;
  }
  tbody tr {
    border-bottom: 1px solid #f0f0f0;
    cursor: pointer;
    transition: background 0.1s;
  }
  tbody tr:hover { background: #f8f8f8; }
  td { padding: 12px 14px; }
  td.mono { font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 13px; color: #555; }

  .badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 600;
    text-align: center;
    min-width: 56px;
  }
  .badge-full { background: #e6f4ea; color: #1a7f37; }
  .badge-partial { background: #fff3e0; color: #b45309; }
  .badge-no { background: #fee; color: #c33; }

  .scenario-name { font-weight: 600; }
  .scenario-id { color: #888; font-size: 12px; font-family: 'SF Mono', Menlo, Consolas, monospace; }

  /* Detail view */
  .view { display: none; }
  .view.active { display: block; }

  .back-link {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: #555;
    text-decoration: none;
    font-size: 14px;
    margin-bottom: 20px;
  }
  .back-link:hover { color: #111; }

  .detail-header { margin-bottom: 28px; }
  .detail-header h2 { font-size: 22px; font-weight: 700; margin-bottom: 4px; }
  .detail-header .meta { color: #666; font-size: 14px; }

  .detail-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-bottom: 28px;
  }

  .info-card {
    border: 1px solid #e5e5e5;
    border-radius: 8px;
    padding: 20px;
  }
  .info-card h3 {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: #888;
    margin-bottom: 8px;
  }
  .info-card .value { font-size: 15px; margin-bottom: 6px; }
  .info-card .desc { font-size: 13px; color: #666; line-height: 1.5; }

  .feasibility-section {
    border: 1px solid #e5e5e5;
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 16px;
  }
  .feasibility-section h3 {
    font-size: 15px;
    font-weight: 600;
    margin-bottom: 8px;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .feasibility-section .explanation { font-size: 14px; color: #444; margin-bottom: 14px; }

  .btn {
    display: inline-block;
    padding: 8px 20px;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 600;
    text-decoration: none;
    cursor: pointer;
    border: 1px solid #d0d0d0;
    background: #fafafa;
    color: #333;
    transition: all 0.15s;
  }
  .btn:hover { background: #f0f0f0; border-color: #bbb; }
  .btn-primary { background: #2563eb; color: #fff; border-color: #2563eb; }
  .btn-primary:hover { background: #1d4ed8; }
  .btn:disabled, .btn.disabled { opacity: 0.4; cursor: not-allowed; pointer-events: none; }

  /* Artifact page */
  .artifact-section { margin-bottom: 32px; }
  .artifact-section h3 {
    font-size: 14px;
    font-weight: 600;
    margin-bottom: 10px;
    padding-bottom: 6px;
    border-bottom: 1px solid #eee;
  }

  pre {
    background: #f6f6f6;
    border: 1px solid #e5e5e5;
    border-radius: 6px;
    padding: 16px;
    overflow-x: auto;
    font-family: 'SF Mono', Menlo, Consolas, monospace;
    font-size: 12.5px;
    line-height: 1.55;
    color: #333;
    max-height: 500px;
    overflow-y: auto;
  }

  /* Results */
  .result-card {
    border: 1px solid #e5e5e5;
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 16px;
  }
  .result-card h4 { font-size: 14px; font-weight: 600; margin-bottom: 12px; }
  .score-row {
    display: flex;
    gap: 24px;
    margin-bottom: 14px;
  }
  .score-item {
    display: flex;
    flex-direction: column;
    align-items: center;
  }
  .score-value {
    font-size: 28px;
    font-weight: 700;
  }
  .score-value.pass { color: #1a7f37; }
  .score-value.fail { color: #c33; }
  .score-label { font-size: 12px; color: #888; text-transform: uppercase; }

  .evidence-list { list-style: none; padding: 0; }
  .evidence-list li {
    padding: 4px 0;
    font-size: 13px;
    font-family: 'SF Mono', Menlo, Consolas, monospace;
  }
  .evidence-list li.pass { color: #1a7f37; }
  .evidence-list li.fail { color: #c33; }
  .evidence-list li.error { color: #b45309; }

  .placeholder-msg {
    padding: 24px;
    text-align: center;
    color: #888;
    font-size: 14px;
    border: 1px dashed #ddd;
    border-radius: 8px;
  }

  .tag-list { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 6px; }
  .tag {
    font-size: 11px;
    padding: 2px 8px;
    background: #f0f0f0;
    border-radius: 3px;
    font-family: 'SF Mono', Menlo, Consolas, monospace;
    color: #555;
  }

  .footer {
    margin-top: 48px;
    padding-top: 16px;
    border-top: 1px solid #eee;
    font-size: 12px;
    color: #aaa;
  }

  /* YAML Modal */
  .modal-overlay {
    display: none;
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.5);
    z-index: 1000;
    justify-content: center;
    align-items: center;
  }
  .modal-overlay.active { display: flex; }
  .modal-content {
    background: #fff;
    border-radius: 10px;
    width: 90%;
    max-width: 900px;
    max-height: 85vh;
    display: flex;
    flex-direction: column;
  }
  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px 20px;
    border-bottom: 1px solid #e5e5e5;
  }
  .modal-header h3 { font-size: 16px; font-weight: 600; margin: 0; }
  .modal-close {
    background: none;
    border: none;
    font-size: 22px;
    cursor: pointer;
    color: #888;
    padding: 4px 8px;
  }
  .modal-close:hover { color: #333; }
  .modal-body {
    overflow-y: auto;
    padding: 20px;
    flex: 1;
  }
  .modal-body pre { max-height: none; margin: 0; }
</style>
</head>
<body>

<div class="container">

  <!-- OVERVIEW VIEW -->
  <div id="view-overview" class="view active">
    <h1>Garak Scenario Coverage &amp; Run Report</h1>
    <div class="subtitle">Feasibility gate + ForgeScenario probe results against qwen2.5:14b (Ollama).</div>
    <table>
      <thead>
        <tr>
          <th>Scenario</th>
          <th>Where it sits</th>
          <th>What we check</th>
          <th>Garak gate</th>
          <th>Garak run</th>
          <th>AgentDojo</th>
        </tr>
      </thead>
      <tbody id="scenario-table"></tbody>
    </table>
    <div class="footer" id="summary-footer"></div>
  </div>

  <!-- DETAIL VIEW -->
  <div id="view-detail" class="view">
    <a href="#" class="back-link" onclick="showOverview(); return false;">&#8592; Back to overview</a>
    <div id="detail-content"></div>
  </div>

  <!-- GARAK ARTIFACT VIEW -->
  <div id="view-garak" class="view">
    <a href="#" class="back-link" id="garak-back-link">&#8592; Back to scenario</a>
    <div id="garak-content"></div>
  </div>

  <!-- AGENTDOJO ARTIFACT VIEW -->
  <div id="view-agentdojo" class="view">
    <a href="#" class="back-link" id="agentdojo-back-link">&#8592; Back to scenario</a>
    <div id="agentdojo-content"></div>
  </div>

</div>

<!-- YAML MODAL -->
<div id="yaml-modal" class="modal-overlay" onclick="if(event.target===this)closeYamlModal()">
  <div class="modal-content">
    <div class="modal-header">
      <h3 id="yaml-modal-title">Scenario YAML</h3>
      <button class="modal-close" onclick="closeYamlModal()">&times;</button>
    </div>
    <div class="modal-body">
      <pre id="yaml-modal-body"></pre>
    </div>
  </div>
</div>

<script>
const SCENARIOS = %%SCENARIOS_JSON%%;

// --- Rendering helpers ---
function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function badgeHtml(level) {
  return `<span class="badge badge-${level}">${level}</span>`;
}

function showView(id) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById('view-' + id).classList.add('active');
  window.scrollTo(0, 0);
}

function showOverview() { showView('overview'); history.pushState(null, '', '#'); }

// --- YAML modal ---
function showYamlModal(scenarioId) {
  const s = SCENARIOS.find(x => x.scenario_id === scenarioId);
  if (!s || !s.yaml_source) return;
  document.getElementById('yaml-modal-title').textContent = s.scenario_id + '.yaml';
  document.getElementById('yaml-modal-body').textContent = s.yaml_source;
  document.getElementById('yaml-modal').classList.add('active');
  document.body.style.overflow = 'hidden';
}
function closeYamlModal() {
  document.getElementById('yaml-modal').classList.remove('active');
  document.body.style.overflow = '';
}
document.addEventListener('keydown', function(e) { if (e.key === 'Escape') closeYamlModal(); });

function runBadge(s) {
  const r = s.garak && s.garak.results;
  if (s.garak.feasibility === 'no') return '<span class="badge badge-no">skipped</span>';
  if (!r) return '<span class="badge" style="background:#eee;color:#888;">pending</span>';
  if (r.status !== 'ok') return `<span class="badge badge-no">${esc(r.status || 'error')}</span>`;
  if (r.attack_success) return '<span class="badge badge-no">hit</span>';
  return '<span class="badge badge-full">pass</span>';
}

// --- Overview table ---
function renderTable() {
  const tbody = document.getElementById('scenario-table');
  let rows = '';
  SCENARIOS.forEach(s => {
    rows += `<tr onclick="showDetail('${s.scenario_id}')">
      <td><span class="scenario-name">${esc(s.seed_id)}  ${esc(s.short_name)}</span></td>
      <td class="mono">${esc(s.surface_label)}</td>
      <td class="mono">${esc(s.oracle)}</td>
      <td>${badgeHtml(s.garak.feasibility)}</td>
      <td>${runBadge(s)}</td>
      <td>${badgeHtml(s.agentdojo.feasibility)}</td>
    </tr>`;
  });
  tbody.innerHTML = rows;

  const full_g = SCENARIOS.filter(s => s.garak.feasibility === 'full').length;
  const partial_g = SCENARIOS.filter(s => s.garak.feasibility === 'partial').length;
  const no_g = SCENARIOS.filter(s => s.garak.feasibility === 'no').length;
  const ran = SCENARIOS.filter(s => s.garak.results && s.garak.results.status === 'ok');
  const hits = ran.filter(s => s.garak.results.attack_success).length;
  const passes = ran.length - hits;
  const full_a = SCENARIOS.filter(s => s.agentdojo.feasibility === 'full').length;
  const partial_a = SCENARIOS.filter(s => s.agentdojo.feasibility === 'partial').length;
  document.getElementById('summary-footer').textContent =
    `${SCENARIOS.length} scenarios. Garak gate: ${full_g} full, ${partial_g} partial, ${no_g} no. ` +
    `Garak runs: ${ran.length} completed (${hits} detector hits, ${passes} passes). ` +
    `AgentDojo: ${full_a} full, ${partial_a} partial.`;
}

// --- Detail view ---
function showDetail(scenarioId) {
  const s = SCENARIOS.find(x => x.scenario_id === scenarioId);
  if (!s) return;
  showView('detail');

  const garakBtnClass = s.garak.feasibility === 'no' ? 'btn disabled' : 'btn btn-primary';
  const garakBtnClick = s.garak.feasibility === 'no' ? '' : `onclick="showGarak('${s.scenario_id}')"`;
  const adjBtnClass = s.agentdojo.feasibility === 'no' ? 'btn disabled' : 'btn btn-primary';
  const adjBtnClick = s.agentdojo.feasibility === 'no' ? '' : `onclick="showAgentdojo('${s.scenario_id}')"`;

  document.getElementById('detail-content').innerHTML = `
    <div class="detail-header">
      <h2>${esc(s.seed_id)} — ${esc(s.short_name)}</h2>
      <div class="meta">${esc(s.mechanism_name)}</div>
      <div class="meta" style="margin-top:4px">Trigger tool: <code>${esc(s.trigger_tool)}</code> &nbsp; Scenario: <code>${esc(s.scenario_id)}</code></div>
    </div>

    <div class="detail-grid">
      <div class="info-card">
        <h3>Where it sits (injection surface)</h3>
        <div class="value"><code>${esc(s.surface_label)}</code></div>
        <div class="desc">${esc(s.surface_explanation)}</div>
      </div>
      <div class="info-card">
        <h3>What we check (oracle)</h3>
        <div class="value"><code>${esc(s.oracle)}</code></div>
        <div class="desc">${esc(s.oracle_explanation)}</div>
      </div>
    </div>

    <div class="feasibility-section">
      <h3>Garak ${badgeHtml(s.garak.feasibility)}</h3>
      <div class="explanation">${esc(s.garak.explanation)}</div>
      <span class="${garakBtnClass}" ${garakBtnClick}>View Garak Artifacts</span>
    </div>

    <div class="feasibility-section">
      <h3>AgentDojo ${badgeHtml(s.agentdojo.feasibility)}</h3>
      <div class="explanation">${esc(s.agentdojo.explanation)}</div>
      <span class="${adjBtnClass}" ${adjBtnClick}>View AgentDojo Artifacts</span>
    </div>

    <div style="margin-top:16px; font-size:13px; color:#888;">
      <strong>Injection goal:</strong> ${esc(s.injection_goal).substring(0, 300)}
    </div>

    <div style="margin-top:16px;">
      <span class="btn" onclick="showYamlModal('${s.scenario_id}')">View Source YAML</span>
    </div>
  `;
}

// --- Garak artifact view ---
function showGarak(scenarioId) {
  const s = SCENARIOS.find(x => x.scenario_id === scenarioId);
  if (!s) return;
  showView('garak');
  document.getElementById('garak-back-link').onclick = function() { showDetail(scenarioId); return false; };

  let probeHtml = s.garak.probe_code
    ? `<pre>${esc(s.garak.probe_code)}</pre>`
    : `<div class="placeholder-msg">No probe generated (scenario was skipped by gate).</div>`;
  let detectorHtml = s.garak.detector_code
    ? `<pre>${esc(s.garak.detector_code)}</pre>`
    : `<div class="placeholder-msg">No detector generated.</div>`;

  let resultsHtml = '';
  const r = s.garak.results;
  if (r && r.status === 'ok') {
    const hit = r.attack_success;
    const badge = hit
      ? '<span class="badge badge-no">DETECTOR HIT</span>'
      : '<span class="badge badge-full">PASS</span>';
    const scorePct = Math.round((r.mean_detector_score || 0) * 100);
    const scoreClass = hit ? 'fail' : 'pass';
    const outputs = (r.outputs || []).map(o => `<pre>${esc(o)}</pre>`).join('');
    resultsHtml = `
      <div class="result-card">
        <h4>Garak Run ${badge}</h4>
        <div class="score-row">
          <div class="score-item">
            <div class="score-value ${scoreClass}">${scorePct}%</div>
            <div class="score-label">Detector score</div>
          </div>
          <div class="score-item">
            <div class="score-value pass">${esc(String(r.elapsed_sec || '?'))}s</div>
            <div class="score-label">Elapsed</div>
          </div>
          <div class="score-item">
            <div class="score-value pass">${esc(String(r.attempts || 0))}</div>
            <div class="score-label">Attempts</div>
          </div>
        </div>
        <div class="desc" style="margin-bottom:12px;">
          Target: <code>${esc(r.target_type || '')} / ${esc(r.target_name || '')}</code>
          &nbsp; Gate: <code>${esc(r.gate || s.garak.feasibility)}</code>
        </div>
        <details open>
          <summary style="cursor:pointer; font-size:13px; font-weight:600;">Model outputs</summary>
          ${outputs || '<div class="placeholder-msg">No outputs captured.</div>'}
        </details>
      </div>
    `;
  } else if (r) {
    resultsHtml = `<div class="placeholder-msg">Garak run status: <code>${esc(r.status || 'error')}</code>${r.error ? ' — ' + esc(r.error) : ''}</div>`;
  } else if (s.garak.feasibility === 'no') {
    resultsHtml = `<div class="placeholder-msg">Skipped by gate: ${esc(s.garak.gate_reason || s.garak.explanation)}</div>`;
  } else {
    resultsHtml = `<div class="placeholder-msg">No Garak run results yet.<br>
      Run: <code>python3 scripts/run_garak_batch.py ${esc(s.scenario_id)}</code></div>`;
  }

  document.getElementById('garak-content').innerHTML = `
    <div class="detail-header">
      <h2>Garak Artifacts — ${esc(s.seed_id)}</h2>
      <div class="meta">${esc(s.mechanism_name)}</div>
    </div>
    <div class="artifact-section">
      <h3>Run Results</h3>
      ${resultsHtml}
    </div>
    <div class="artifact-section">
      <h3>Probe config</h3>
      ${probeHtml}
    </div>
    <div class="artifact-section">
      <h3>Detector</h3>
      ${detectorHtml}
    </div>
  `;
}

// --- AgentDojo artifact view ---
function showAgentdojo(scenarioId) {
  const s = SCENARIOS.find(x => x.scenario_id === scenarioId);
  if (!s) return;
  showView('agentdojo');
  document.getElementById('agentdojo-back-link').onclick = function() { showDetail(scenarioId); return false; };

  let artifactsHtml = '';
  if (s.agentdojo.artifacts) {
    const a = s.agentdojo.artifacts;
    if (a.spec) {
      try {
        const spec = JSON.parse(a.spec);
        if (spec.user_task) {
          const ut = spec.user_task;
          artifactsHtml += `<div class="artifact-section"><h3>User Task</h3>
            <div class="info-card" style="margin-bottom:16px;">
              <div class="desc" style="margin-bottom:10px;">${esc(ut.prompt || '')}</div>
              <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;">
                <div>
                  <h3>Required Data Access</h3>
                  <div class="tag-list">${(ut.required_data_access || []).map(d => '<span class="tag">' + esc(d) + '</span>').join('')}</div>
                </div>
                <div>
                  <h3>Forbidden Actions</h3>
                  <div class="tag-list">${(ut.forbidden_actions || []).map(f => '<span class="tag" style="background:#fee;color:#c33;">' + esc(f) + '</span>').join('')}</div>
                </div>
              </div>
              ${ut.expected_outcome ? '<div class="desc" style="margin-top:10px;"><strong>Expected outcome:</strong> ' + esc(ut.expected_outcome) + '</div>' : ''}
            </div>
          </div>`;
        }
        if (spec.injection) {
          const inj = spec.injection;
          artifactsHtml += `<div class="artifact-section"><h3>Injection</h3>
            <div class="info-card" style="margin-bottom:16px;">
              <div class="desc" style="margin-bottom:10px;"><strong>Goal:</strong> ${esc(inj.goal || '')}</div>
              <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:10px;">
                <div>
                  <h3>Attack Pattern</h3>
                  <div class="value"><code>${esc(inj.attack_pattern || '')}</code></div>
                </div>
                <div>
                  <h3>Attack Variant</h3>
                  <div class="value"><code>${esc(inj.attack_variant || '')}</code></div>
                </div>
              </div>
              <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; margin-bottom:10px;">
                <div>
                  <h3>Trigger Tool</h3>
                  <div class="value"><code>${esc(inj.trigger_tool || '')}</code></div>
                </div>
                <div>
                  <h3>Exfil Channel</h3>
                  <div class="value"><code>${esc(inj.exfil_channel || '')}</code></div>
                </div>
                <div>
                  <h3>Exfil Address</h3>
                  <div class="value" style="word-break:break-all;"><code>${esc(inj.exfil_address || '')}</code></div>
                </div>
              </div>
              <div>
                <h3>Target Surfaces</h3>
                <div class="tag-list">${(inj.target_surfaces || []).map(t => '<span class="tag">' + esc(t) + '</span>').join('')}</div>
              </div>
            </div>
          </div>`;
        }
      } catch(e) {}
    }
    if (a.env_models) {
      artifactsHtml += `<div class="artifact-section"><h3>Environment Models (env_models.py)</h3><pre>${esc(a.env_models)}</pre></div>`;
    }
    if (a.tools) {
      artifactsHtml += `<div class="artifact-section"><h3>Tool Functions (tools.py)</h3><pre>${esc(a.tools)}</pre></div>`;
    }
    if (a.seed_data) {
      artifactsHtml += `<div class="artifact-section"><h3>Seed Data (seed_data.yaml)</h3><pre>${esc(a.seed_data)}</pre></div>`;
    }
  } else {
    artifactsHtml = `<div class="placeholder-msg">No AgentDojo artifacts generated for this scenario.</div>`;
  }

  let resultsHtml = '';
  if (s.agentdojo.results) {
    const r = s.agentdojo.results;
    const secPct = Math.round((r.security_score || 0) * 100);
    const utilPct = Math.round((r.utility_score || 0) * 100);
    const secClass = secPct >= 100 ? 'pass' : 'fail';
    const violated = r.policy_violated ? '<span class="badge badge-no">VIOLATED</span>' : '<span class="badge badge-full">PASSED</span>';

    let secEvidence = '';
    if (r.security_evidence) {
      secEvidence = '<ul class="evidence-list">' + r.security_evidence.map(e => {
        let cls = 'pass';
        if (e.startsWith('FAIL')) cls = 'fail';
        else if (e.startsWith('ERROR')) cls = 'error';
        return `<li class="${cls}">${esc(e)}</li>`;
      }).join('') + '</ul>';
    }

    let utilEvidence = '';
    if (r.utility_evidence) {
      utilEvidence = '<ul class="evidence-list">' + r.utility_evidence.map(e => {
        let cls = 'pass';
        if (e.startsWith('FAIL')) cls = 'fail';
        else if (e.startsWith('ERROR')) cls = 'error';
        return `<li class="${cls}">${esc(e)}</li>`;
      }).join('') + '</ul>';
    }

    resultsHtml = `
      <div class="result-card">
        <h4>Red Team Run Results ${violated}</h4>
        <div class="score-row">
          <div class="score-item">
            <div class="score-value ${secClass}">${secPct}%</div>
            <div class="score-label">Security</div>
          </div>
          <div class="score-item">
            <div class="score-value pass">${utilPct}%</div>
            <div class="score-label">Utility</div>
          </div>
        </div>
        <details style="margin-bottom:12px;">
          <summary style="cursor:pointer; font-size:13px; font-weight:600;">Security Evidence</summary>
          ${secEvidence}
        </details>
        <details>
          <summary style="cursor:pointer; font-size:13px; font-weight:600;">Utility Evidence</summary>
          ${utilEvidence}
        </details>
      </div>
    `;
  } else {
    resultsHtml = `<div class="placeholder-msg">No AgentDojo run results available for this scenario. Run: <code>python3 pipeline.py --scenario examples/scenarios/${esc(s.scenario_id)}.yaml</code></div>`;
  }

  document.getElementById('agentdojo-content').innerHTML = `
    <div class="detail-header">
      <h2>AgentDojo Artifacts — ${esc(s.seed_id)}</h2>
      <div class="meta">${esc(s.mechanism_name)}</div>
    </div>
    ${artifactsHtml}
    <div class="artifact-section">
      <h3>Run Results (Qwen 2.5 14B via Ollama)</h3>
      ${resultsHtml}
    </div>
  `;
}

// --- Init ---
renderTable();
</script>
</body>
</html>"""


def generate_report() -> Path:
    scenarios = collect_scenarios()
    scenarios_json = json.dumps(scenarios, indent=2, ensure_ascii=False)

    html_content = HTML_TEMPLATE.replace("%%SCENARIOS_JSON%%", scenarios_json)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = REPORTS_DIR / "index.html"
    out_path.write_text(html_content)

    log.info("Report written to %s", out_path)
    return out_path


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)-5s %(message)s")
    path = generate_report()
    print(f"Report generated: {path}")
