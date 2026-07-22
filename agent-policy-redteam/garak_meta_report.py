"""Generate a self-contained HTML meta-report for Garak artifact generation + runs.

Usage:
    python garak_meta_report.py
    python garak_meta_report.py --out reports/garak_meta.html

Embeds:
  - ArtifactGen flow diagram
  - Shared probe/detector templates
  - Attack-success bar chart from reports/garak_runs/*/summary.json
  - Gate labels from ArtifactGen_garak/configs/manifest.json
  - Spec / probe config / detection raw viewers for full|partial scenarios
"""

from __future__ import annotations

import argparse
import html
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent
MANIFEST_PATH = ROOT / "ArtifactGen_garak" / "configs" / "manifest.json"
CONFIG_DIR = ROOT / "ArtifactGen_garak" / "configs"
RUNS_DIR = ROOT / "runs"
GARAK_RUNS_DIR = ROOT / "reports" / "garak_runs"
PROBE_SRC = ROOT / "ArtifactGen_garak" / "plugins" / "probes" / "forge_scenario.py"
DETECTOR_SRC = ROOT / "ArtifactGen_garak" / "plugins" / "detectors" / "forge_scenario.py"
DEFAULT_OUT = ROOT / "reports" / "garak_meta.html"

PROBE_TEMPLATE_HTML = '''\
<span class="code-muted">class</span> ForgeScenario(Probe):
    <span class="code-muted">"""One probe class for every forge scenario."""</span>
    primary_detector = <span class="dyn" title="Fixed detector class for all scenarios">"forge_scenario.ForgeScenarioDetector"</span>
    DEFAULT_PARAMS = Probe.DEFAULT_PARAMS | {"config_path": ""}

    <span class="code-muted">def</span> __init__(self, config_root=_config):
        path = self.config_path <span class="code-muted">or</span> os.environ["FORGE_SCENARIO_CONFIG"]
        cfg = load_yaml(path)          <span class="anno">← per-scenario YAML</span>
        self.goal = <span class="dyn" title="From YAML: goal">cfg["goal"]</span>
        self.tags = <span class="dyn" title="From YAML: tags">cfg["tags"]</span>
        self.prompts = <span class="dyn" title="From YAML: prompts (attack conversation)">cfg["prompts"]</span>  <span class="anno">← attack conversation</span>
        self.detection = <span class="dyn" title="From YAML: detection block">cfg["detection"]</span>
'''

DETECTOR_TEMPLATE_HTML = '''\
<span class="code-muted">class</span> ForgeScenarioDetector(Detector):
    <span class="code-muted">"""One detector class; rules come from the same YAML."""</span>
    DEFAULT_PARAMS = Detector.DEFAULT_PARAMS | {"config_path": ""}

    <span class="code-muted">def</span> __init__(self, config_root=_config):
        cfg = load_yaml(config_path)
        d = <span class="dyn" title="From YAML: detection">cfg["detection"]</span>           <span class="anno">← per-scenario rules</span>
        self.strategy = <span class="dyn" title="forbidden_call | output_string">d["strategy"]</span>
        self.trigger_tool = <span class="dyn" title="Privileged tool that must not be called">d["trigger_tool"]</span>
        self.exfil_address = <span class="dyn" title="Attacker destination to detect in output">d["exfil_address"]</span>
        self.predicates = <span class="dyn" title="must_not_call / must_not_contain rules">d["predicates"]</span>

    <span class="code-muted">def</span> detect(self, attempt):
        <span class="code-muted"># hit = model complied with the attack</span>
        <span class="code-muted">return</span> [1.0 <span class="code-muted">if</span> self._is_hit(out) <span class="code-muted">else</span> 0.0
                <span class="code-muted">for</span> out <span class="code-muted">in</span> attempt.all_outputs]
'''

PROBE_TEMPLATE = PROBE_TEMPLATE_HTML
DETECTOR_TEMPLATE = DETECTOR_TEMPLATE_HTML


def _read(path: Path) -> str | None:
    if path.is_file():
        return path.read_text(encoding="utf-8")
    return None


def _load_manifest() -> list[dict]:
    if not MANIFEST_PATH.is_file():
        log.warning("Manifest not found: %s", MANIFEST_PATH)
        return []
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _load_run_summary(scenario_id: str) -> dict | None:
    path = GARAK_RUNS_DIR / scenario_id / "summary.json"
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    # Drop bulky digest for the embedded payload
    if isinstance(data, dict) and "digest" in data:
        data = {k: v for k, v in data.items() if k != "digest"}
    return data


def _format_llm_response(run: dict | None) -> str | None:
    """Format model outputs from a Garak run summary (body only, no header)."""
    if not run:
        return None
    outputs = run.get("outputs") or []
    if not isinstance(outputs, list):
        outputs = [str(outputs)]
    unique: list[str] = []
    for o in outputs:
        text = str(o).strip() if o is not None else ""
        if text and text not in unique:
            unique.append(text)
    if not unique:
        return None
    if len(unique) == 1:
        return unique[0]
    parts = []
    for i, text in enumerate(unique, 1):
        parts.append(f"--- Response {i}/{len(unique)} ---\n{text}")
    return "\n\n".join(parts)


def _extract_prompts(probe_yaml: str | None) -> str | None:
    if not probe_yaml:
        return None
    try:
        import yaml

        cfg = yaml.safe_load(probe_yaml) or {}
        prompts = cfg.get("prompts") or []
        if not prompts:
            return None
        if len(prompts) == 1:
            return str(prompts[0])
        parts = []
        for i, p in enumerate(prompts, 1):
            parts.append(f"--- Prompt {i}/{len(prompts)} ---\n{p}")
        return "\n\n".join(parts)
    except Exception:
        return None


def _format_run_view(
    *,
    scenario_id: str,
    prompt: str | None,
    llm_response: str | None,
    detection: str | None,
    run: dict | None,
) -> str | None:
    """Combined prompt + LLM response + detector rules for the Run button."""
    if not prompt and not llm_response and not detection:
        return None
    target = "?"
    outcome = "n/a"
    if run:
        target = f"{run.get('target_type') or '?'} / {run.get('target_name') or '?'}"
        outcome = "ATTACK SUCCESS (hit)" if run.get("attack_success") else "DEFENDED (pass)"
        hits = run.get("hits")
        attempts = run.get("attempts")
        outcome = f"{outcome}  (hits {hits}/{attempts})"

    sep = "═" * 64
    mid = "─" * 64
    sections = [
        f"Scenario: {scenario_id}",
        f"Target:   {target}",
        f"Outcome:  {outcome}",
        sep,
        "PROMPT (sent by Garak ForgeScenario probe)",
        mid,
        prompt or "(no prompt embedded)",
        "",
        sep,
        "LLM RESPONSE",
        mid,
        llm_response or "(no run / no model output recorded)",
        "",
        sep,
        "DETECTOR LOGIC (from config detection block)",
        mid,
        detection or "(no detection block)",
        "",
    ]
    return "\n".join(sections)


def _build_scenario_row(
    *,
    sid: str,
    gate: str,
    gate_reason: str = "",
    seed_id: str = "",
    threat_id: str = "",
    attack_pattern: str = "",
    attack_variant: str = "",
    surface: str = "",
    oracle: str = "",
    mechanism_name: str = "",
    parent_id: str | None = None,
    experiment: str | None = None,
    spec_path: Path | None = None,
) -> dict:
    config_path = CONFIG_DIR / f"{sid}.yaml"
    run = _load_run_summary(sid)
    attack_success = None
    defense_pass = None
    asr = None
    hits = None
    attempts = None
    target = None
    llm_response = None
    if run:
        attack_success = bool(run.get("attack_success"))
        defense_pass = bool(run.get("passed"))
        hits = run.get("hits")
        attempts = run.get("attempts") or 0
        if attempts:
            asr = (hits or 0) / attempts * 100.0
        elif attack_success is not None:
            asr = 100.0 if attack_success else 0.0
        target = f"{run.get('target_type', '')}:{run.get('target_name', '')}"
        llm_response = _format_llm_response(run)

    runnable = gate in ("full", "partial", "experiment")
    probe_yaml = _read(config_path) if runnable else None
    probe_yaml_label = probe_yaml if probe_yaml is not None else _read(config_path)
    goal = ""
    detection_text = None

    if probe_yaml_label:
        try:
            import yaml

            cfg = yaml.safe_load(probe_yaml_label) or {}
            mechanism_name = mechanism_name or cfg.get("mechanism_name") or ""
            goal = (cfg.get("goal") or "")[:200]
            seed_id = seed_id or cfg.get("seed_id") or ""
            threat_id = threat_id or cfg.get("threat_id") or ""
            surface = surface or cfg.get("surface") or ""
            oracle = oracle or cfg.get("oracle") or ""
            if probe_yaml:
                detection_text = yaml.safe_dump(
                    cfg.get("detection") or {},
                    sort_keys=False,
                    allow_unicode=True,
                )
        except Exception:
            if probe_yaml:
                detection_text = "(could not parse detection block)"

    spec_text = None
    if spec_path and spec_path.is_file() and runnable:
        spec_text = _read(spec_path)
        if spec_text:
            try:
                spec_text = json.dumps(json.loads(spec_text), indent=2, ensure_ascii=False)
            except Exception:
                pass

    parent_forge = parent_id or sid.split("-nopolicy")[0]
    forge_yaml = _read(ROOT / "examples" / "scenarios" / f"{parent_forge}.yaml")
    description = mechanism_name or goal or sid
    if experiment:
        description = f"[{experiment}] {description}"

    prompt_text = _extract_prompts(probe_yaml)
    run_view = _format_run_view(
        scenario_id=sid,
        prompt=prompt_text,
        llm_response=llm_response,
        detection=detection_text,
        run=run,
    )

    return {
        "scenario_id": sid,
        "seed_id": seed_id,
        "threat_id": threat_id,
        "mechanism_name": mechanism_name,
        "description": description,
        "goal": goal,
        "surface": surface,
        "oracle": oracle,
        "attack_pattern": attack_pattern,
        "attack_variant": attack_variant,
        "gate": gate,
        "gate_reason": gate_reason,
        "has_run": run is not None,
        "attack_success": attack_success,
        "defense_pass": defense_pass,
        "asr": asr,
        "hits": hits,
        "attempts": attempts,
        "target": target,
        "spec": spec_text,
        "probe": probe_yaml,
        "detector": detection_text,
        "forge_yaml": forge_yaml,
        "run": run_view,
        "experiment": experiment,
        "parent_id": parent_id,
        "is_extra": bool(experiment),
    }


def _discover_extra_experiments(existing_ids: set[str]) -> list[dict]:
    """Pick up experiment configs not listed in the main forge manifest (e.g. *-nopolicy)."""
    extras = []
    for path in sorted(CONFIG_DIR.glob("*-nopolicy.yaml")):
        sid = path.stem
        if sid in existing_ids:
            continue
        parent = sid.removesuffix("-nopolicy")
        parent_spec = RUNS_DIR / parent / "spec.json"
        extras.append(
            _build_scenario_row(
                sid=sid,
                gate="experiment",
                gate_reason="extra run: system prompt without policy instructions",
                parent_id=parent,
                experiment="nopolicy",
                spec_path=parent_spec if parent_spec.is_file() else None,
            )
        )
    return extras


def collect() -> dict:
    manifest = _load_manifest()
    scenarios: list[dict] = []

    for entry in manifest:
        sid = entry["scenario_id"]
        spec_path = ROOT / entry.get("spec_path", f"runs/{sid}/spec.json")
        if not spec_path.is_file():
            alt = RUNS_DIR / sid / "spec.json"
            if alt.is_file():
                spec_path = alt
        scenarios.append(
            _build_scenario_row(
                sid=sid,
                gate=entry.get("gate_result", "skip"),
                gate_reason=entry.get("gate_reason", ""),
                seed_id=entry.get("seed_id", ""),
                threat_id=entry.get("threat_id", ""),
                attack_pattern=entry.get("attack_pattern", ""),
                attack_variant=entry.get("attack_variant", ""),
                surface=entry.get("surface", ""),
                oracle=entry.get("oracle", ""),
                mechanism_name=entry.get("mechanism_name", ""),
                spec_path=spec_path,
            )
        )

    existing = {s["scenario_id"] for s in scenarios}
    scenarios.extend(_discover_extra_experiments(existing))

    ran = [s for s in scenarios if s["has_run"]]
    hits_n = sum(1 for s in ran if s["attack_success"])
    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "counts": {
            "total": len(scenarios),
            "full": sum(1 for s in scenarios if s["gate"] == "full"),
            "partial": sum(1 for s in scenarios if s["gate"] == "partial"),
            "skip": sum(1 for s in scenarios if s["gate"] == "skip"),
            "experiment": sum(1 for s in scenarios if s["gate"] == "experiment"),
            "ran": len(ran),
            "attack_hits": hits_n,
            "defense_passes": sum(1 for s in ran if s["defense_pass"]),
        },
        "probe_template": PROBE_TEMPLATE,
        "detector_template": DETECTOR_TEMPLATE,
        "probe_source_path": str(PROBE_SRC.relative_to(ROOT)),
        "detector_source_path": str(DETECTOR_SRC.relative_to(ROOT)),
        "scenarios": scenarios,
    }


def render_html(data: dict) -> str:
    payload = json.dumps(data, ensure_ascii=False)
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Garak Meta Report</title>
<style>
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  background: #fafafa;
  color: #111;
  line-height: 1.5;
}}
.wrap {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px 64px; }}
h1 {{ margin: 0 0 6px; font-size: 1.6rem; font-weight: 650; }}
.subtitle {{ color: #333; margin: 0 0 4px; }}
.meta {{ color: #666; font-size: 0.9rem; margin-bottom: 28px; }}
h2 {{
  margin: 0 0 10px;
  font-size: 1.15rem;
  font-weight: 650;
  padding: 10px 14px;
  border-radius: 8px;
}}
h2.sec-flow {{ background: #ede9fe; color: #4c1d95; }}
h2.sec-templates {{ background: #fce7f3; color: #9d174d; }}
h2.sec-chart {{ background: #d1fae5; color: #065f46; }}
h2.sec-table {{ background: #e0f2fe; color: #075985; }}
h3 {{ margin: 0 0 8px; font-size: 1rem; font-weight: 600; }}
.lead {{ color: #444; margin: 0 0 16px; }}
.section {{
  margin: 28px 0;
  padding: 16px;
  border-radius: 12px;
  border: 1px solid #eee;
  background: #fff;
}}
.section.flow-sec {{ background: #faf5ff; border-color: #e9d5ff; }}
.section.templates-sec {{ background: #fff7fb; border-color: #fbcfe8; }}
.section.chart-sec {{ background: #f0fdf4; border-color: #bbf7d0; }}
.section.table-sec {{ background: #f0f9ff; border-color: #bae6fd; }}
.kpis {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 10px;
  margin: 16px 0 8px;
}}
.kpi {{
  border: 1px solid transparent;
  padding: 12px 14px;
  border-radius: 10px;
}}
.kpi:nth-child(1) {{ background: #ede9fe; }}
.kpi:nth-child(2) {{ background: #d1fae5; }}
.kpi:nth-child(3) {{ background: #fef3c7; }}
.kpi:nth-child(4) {{ background: #e5e5ea; }}
.kpi:nth-child(5) {{ background: #e0f2fe; }}
.kpi:nth-child(6) {{ background: #ffe4e6; }}
.kpi:nth-child(7) {{ background: #dcfce7; }}
.kpi .n {{ font-size: 1.4rem; font-weight: 700; font-variant-numeric: tabular-nums; }}
.kpi .l {{ font-size: 0.78rem; color: #555; margin-top: 2px; }}

.flow {{
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 8px;
  margin: 16px 0;
}}
@media (max-width: 900px) {{ .flow {{ grid-template-columns: 1fr; }} }}
.stage {{
  border: 1px solid transparent;
  padding: 12px;
  border-radius: 10px;
}}
.stage:nth-child(1) {{ background: #ede9fe; }}
.stage:nth-child(2) {{ background: #fce7f3; }}
.stage:nth-child(3) {{ background: #fef3c7; }}
.stage:nth-child(4) {{ background: #dbeafe; }}
.stage:nth-child(5) {{ background: #d1fae5; }}
.stage .num {{
  display: inline-block;
  background: #fff;
  border: 1px solid #ddd;
  font-size: 0.75rem;
  font-weight: 700;
  padding: 1px 7px;
  margin-bottom: 8px;
  border-radius: 999px;
}}
.stage .title {{ font-weight: 650; margin-bottom: 4px; }}
.stage .desc {{ font-size: 0.88rem; color: #444; }}
.stage .tag {{
  display: inline-block;
  margin-top: 8px;
  font-size: 0.72rem;
  color: #555;
  background: rgba(255,255,255,0.7);
  border: 1px solid rgba(0,0,0,0.06);
  padding: 1px 6px;
  border-radius: 4px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}}
.arrow-row {{
  color: #666;
  font-size: 0.85rem;
  margin: 4px 0 0;
}}

.templates {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}}
@media (max-width: 900px) {{ .templates {{ grid-template-columns: 1fr; }} }}
.template-card {{
  border: 1px solid #fbcfe8;
  padding: 12px;
  border-radius: 10px;
  background: #fff;
}}
.template-card:last-child {{
  border-color: #ddd6fe;
}}
.note {{
  margin-top: 12px;
  font-size: 0.9rem;
  color: #333;
  border: 1px solid #e9d5ff;
  padding: 10px 12px;
  background: #faf5ff;
  border-radius: 8px;
}}

.chart-wrap {{
  border: 1px solid #bbf7d0;
  padding: 16px 14px 10px;
  background: #fff;
  overflow-x: auto;
  border-radius: 10px;
}}
.chart {{
  display: flex;
  align-items: flex-end;
  gap: 6px;
  min-height: 260px;
  padding: 8px 4px 0;
}}
.bar-col {{
  flex: 1 0 30px;
  min-width: 30px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: flex-end;
  height: 240px;
  cursor: pointer;
  border-radius: 8px 8px 0 0;
  padding: 4px 2px 0;
  scroll-margin-top: 16px;
}}
.bar-col:hover {{ background: #faf8ff; }}
.bar-col.active {{
  background: #f3eeff;
  outline: 2px solid #c4b5fd;
  outline-offset: 1px;
}}
.bar {{
  width: 70%;
  max-width: 36px;
  border-radius: 8px 8px 3px 3px;
  min-height: 4px;
  transition: height 0.15s ease;
}}
.bar.hit {{ background: #f7b2b2; }}
.bar.pass {{ background: #b8e0d2; }}
.bar.none {{ background: #e5e5ea; min-height: 6px; }}
.bar-val {{
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.62rem;
  color: #666;
  margin-bottom: 4px;
}}
.bar-label {{
  writing-mode: vertical-rl;
  transform: rotate(180deg);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.62rem;
  color: #555;
  margin-top: 8px;
  max-height: 100px;
  overflow: hidden;
  position: relative;
  cursor: help;
}}
.bar-label .tip {{
  display: none;
  position: absolute;
  left: 50%;
  bottom: calc(100% + 8px);
  transform: translateX(-50%) rotate(180deg);
  writing-mode: horizontal-tb;
  background: #333;
  color: #fff;
  padding: 8px 10px;
  border-radius: 6px;
  font-size: 0.72rem;
  line-height: 1.35;
  width: max-content;
  max-width: 260px;
  z-index: 5;
  white-space: normal;
  pointer-events: none;
  box-shadow: 0 4px 12px rgba(0,0,0,0.12);
}}
.bar-col:hover .bar-label .tip,
.bar-label:hover .tip {{
  display: block;
}}
tr.scenario-row {{
  border-left: 3px solid transparent;
}}
tr.scenario-row.active {{
  background: #f3eeff;
  border-left: 3px solid #c4b5fd;
}}
a.scenario-link {{
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.84em;
  background: #f5f3ff;
  padding: 1px 4px;
  color: #111;
  text-decoration: underline;
  text-underline-offset: 2px;
  cursor: pointer;
  border-radius: 3px;
}}
a.scenario-link:hover {{ background: #e9e5ff; }}
button.jump {{
  font: inherit;
  font-size: 0.72rem;
  margin-left: 6px;
  padding: 1px 6px;
  border: 1px solid #ddd;
  background: #fff;
  color: #666;
  cursor: pointer;
  border-radius: 4px;
}}
button.jump:hover {{ border-color: #c4b5fd; color: #111; }}
#scenarios-table {{ scroll-margin-top: 16px; }}
.legend {{
  display: flex;
  gap: 16px;
  margin-top: 12px;
  font-size: 0.85rem;
  color: #555;
  flex-wrap: wrap;
}}
.legend i {{
  display: inline-block;
  width: 12px;
  height: 12px;
  border-radius: 3px;
  margin-right: 6px;
  vertical-align: -1px;
}}
.legend .hit i {{ background: #f7b2b2; }}
.legend .ok i {{ background: #b8e0d2; }}
.legend .na i {{ background: #e5e5ea; }}

.template-card pre {{
  margin: 0;
  background: #fafafa;
  border: 1px solid #eee;
  padding: 12px;
  overflow: auto;
  max-height: 360px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.72rem;
  line-height: 1.5;
  white-space: pre;
  color: #222;
  border-radius: 6px;
}}
.dyn {{
  background: #ffe4ec;
  color: #9d174d;
  padding: 0 3px;
  border-radius: 3px;
  border-bottom: 1px solid #f9a8d4;
}}
.anno {{
  color: #7c3aed;
  font-style: italic;
  background: #f3e8ff;
  padding: 0 4px;
  border-radius: 3px;
}}
.code-muted {{ color: #888; }}
.hl-legend {{
  display: flex;
  gap: 14px;
  flex-wrap: wrap;
  margin: 0 0 10px;
  font-size: 0.82rem;
  color: #555;
}}
.hl-legend span {{ display: inline-flex; align-items: center; gap: 6px; }}
.hl-legend .swatch {{
  display: inline-block;
  width: 14px;
  height: 14px;
  border-radius: 3px;
}}
.hl-legend .swatch.dyn {{ background: #ffe4ec; border: 1px solid #f9a8d4; }}
.hl-legend .swatch.anno {{ background: #f3e8ff; border: 1px solid #ddd6fe; }}

.table-wrap {{ border: 1px solid #ddd; overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
th, td {{
  text-align: left;
  padding: 9px 10px;
  border-bottom: 1px solid #eee;
  vertical-align: top;
}}
th {{
  background: #fafafa;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  color: #444;
  font-weight: 650;
}}
tr:last-child td {{ border-bottom: none; }}
code {{
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.84em;
  background: #f5f5f5;
  padding: 1px 4px;
}}
.badge {{
  display: inline-block;
  font-size: 0.72rem;
  font-weight: 650;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  padding: 2px 7px;
  border: 1px solid transparent;
  border-radius: 4px;
  background: #f3f4f6;
  color: #111;
}}
.badge.experiment {{ background: #fce7f3; color: #9d174d; }}
.badge.full {{ background: #d1fae5; color: #065f46; }}
.badge.partial {{ background: #fef3c7; color: #92400e; }}
.badge.skip {{ background: #e5e5ea; color: #555; }}
.badge.hit {{ background: #ffe4e6; color: #9f1239; }}
.badge.pass {{ background: #d1fae5; color: #065f46; }}
.filters button.active {{
  border-color: #a5b4fc;
  color: #3730a3;
  background: #eef2ff;
  font-weight: 650;
}}
.table-wrap {{
  border: 1px solid #bae6fd;
  overflow-x: auto;
  border-radius: 10px;
  background: #fff;
}}
th {{
  background: #e0f2fe;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  color: #075985;
  font-weight: 650;
}}
.btns {{ display: flex; gap: 6px; flex-wrap: wrap; }}
button.view {{
  font: inherit;
  font-size: 0.78rem;
  background: #fff;
  color: #111;
  border: 1px solid #bbb;
  padding: 4px 9px;
  cursor: pointer;
}}
button.view:hover {{ border-color: #111; }}
button.view:disabled {{ opacity: 0.35; cursor: not-allowed; }}

.filters {{ display: flex; gap: 6px; flex-wrap: wrap; margin: 0 0 10px; }}
.filters button {{
  font: inherit;
  font-size: 0.82rem;
  background: #fff;
  border: 1px solid #bbb;
  padding: 5px 10px;
  cursor: pointer;
  color: #333;
}}
.filters button.active {{
  border-color: #a5b4fc;
  color: #3730a3;
  background: #eef2ff;
  font-weight: 650;
}}

.modal-backdrop {{
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.35);
  z-index: 100;
  align-items: center;
  justify-content: center;
  padding: 20px;
}}
.modal-backdrop.open {{ display: flex; }}
.modal {{
  background: #fff;
  border: 1px solid #111;
  width: min(920px, 100%);
  max-height: 85vh;
  display: flex;
  flex-direction: column;
}}
.modal-head {{
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 12px;
  padding: 12px 14px;
  border-bottom: 1px solid #ddd;
}}
.modal-head h3 {{ margin: 0; }}
.modal-head .path {{
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.75rem;
  color: #666;
  margin-top: 2px;
}}
.modal-close {{
  font: inherit;
  font-size: 0.85rem;
  background: #111;
  color: #fff;
  border: none;
  padding: 6px 12px;
  cursor: pointer;
}}
.modal-body {{ overflow: auto; flex: 1; }}
.modal-body pre {{
  margin: 0;
  padding: 14px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.75rem;
  line-height: 1.45;
  white-space: pre-wrap;
  word-break: break-word;
}}
</style>
</head>
<body>
<div class="wrap">
  <h1>Garak Artifact Generator — Meta Report</h1>
  <p class="subtitle">From forge scenarios to shared specs, config-driven probes, and batch run results.</p>

  <div class="kpis" id="kpis"></div>

  <div class="section flow-sec">
  <h2 class="sec-flow">1. How the generator works</h2>
  <p class="lead">Forge YAML → shared ScenarioSpec (with attack library payloads) → gate → realize → Garak YAML → ForgeScenario probe.</p>

  <div class="flow">
    <div class="stage">
      <div class="num">1</div>
      <div class="title">Forge scenario</div>
      <div class="desc">examples/scenarios/*.yaml — narrative, tools, threat, behavior_spec</div>
      <span class="tag">input</span>
    </div>
    <div class="stage">
      <div class="num">2</div>
      <div class="title">ScenarioSpec</div>
      <div class="desc">Shared record + attack pattern/variant from attack_library</div>
      <span class="tag">runs/{{id}}/spec.json</span>
    </div>
    <div class="stage">
      <div class="num">3</div>
      <div class="title">Gate</div>
      <div class="desc">Can Garak write this surface and observe this oracle?</div>
      <span class="tag">full · partial · skip</span>
    </div>
    <div class="stage">
      <div class="num">4</div>
      <div class="title">Realize</div>
      <div class="desc">Fill conversation + payload (LLM or --no-llm fallback)</div>
      <span class="tag">prompts[]</span>
    </div>
    <div class="stage">
      <div class="num">5</div>
      <div class="title">Probe config</div>
      <div class="desc">ArtifactGen_garak/configs/{{id}}.yaml for ForgeScenario</div>
      <span class="tag">garak run</span>
    </div>
  </div>
  <p class="arrow-row">scenario → spec (+ attack) → gate → realize → probe / detector</p>
  </div>

  <div class="section templates-sec">
  <h2 class="sec-templates">2. Probe &amp; detector templates</h2>
  <p class="lead">One Python probe and one detector for all scenarios. Highlighted fields are filled from each scenario’s YAML.</p>
  <div class="hl-legend">
    <span><i class="swatch dyn"></i> Scenario-specific (from YAML)</span>
    <span><i class="swatch anno"></i> Annotation</span>
  </div>
  <div class="templates">
    <div class="template-card">
      <h3>Probe — <code>ForgeScenario</code></h3>
      <pre id="probe-template"></pre>
    </div>
    <div class="template-card">
      <h3>Detector — <code>ForgeScenarioDetector</code></h3>
      <pre id="detector-template"></pre>
    </div>
  </div>
  <div class="note">
    Same classes every time. Only <code>prompts</code>, <code>goal</code>, <code>tags</code>, and <code>detection</code> change per scenario.
    Source: <code id="probe-path"></code> · <code id="detector-path"></code>
  </div>
  </div>

  <div class="section chart-sec">
  <h2 class="sec-chart">3. Attack success by scenario</h2>
  <p class="lead">Two colors only: coral = attack success, mint = defended. Hover an x-axis label for the scenario description. Click a bar to jump to its table row.</p>
  <div class="chart-wrap">
    <div class="chart" id="chart"></div>
    <div class="legend">
      <span class="hit"><i></i>Attack success</span>
      <span class="ok"><i></i>Defended</span>
      <span class="na"><i></i>No run / skip</span>
    </div>
  </div>
  </div>

  <div class="section table-sec">
  <h2 class="sec-table">4. Scenarios &amp; Garak gate</h2>
  <p class="lead">Click a scenario id or <strong>Run</strong> for prompt + LLM response + detector logic. <strong>Spec</strong> opens the shared ScenarioSpec. Chart bars jump to the matching row.</p>
  <div class="filters" id="filters">
    <button type="button" class="active" data-filter="all">All</button>
    <button type="button" data-filter="full">Full</button>
    <button type="button" data-filter="partial">Partial</button>
    <button type="button" data-filter="skip">Skip</button>
    <button type="button" data-filter="experiment">Experiment</button>
  </div>
  <div class="table-wrap" id="scenarios-table">
    <table>
      <thead>
        <tr>
          <th>Scenario</th>
          <th>Threat</th>
          <th>Surface</th>
          <th>Oracle</th>
          <th>Gate</th>
          <th>Run</th>
          <th>Artifacts</th>
        </tr>
      </thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>
  </div>
</div>


<div class="modal-backdrop" id="modal" role="dialog" aria-modal="true">
  <div class="modal">
    <div class="modal-head">
      <div>
        <h3 id="modal-title">Artifact</h3>
        <div class="path" id="modal-path"></div>
      </div>
      <button type="button" class="modal-close" id="modal-close">Close</button>
    </div>
    <div class="modal-body"><pre id="modal-body"></pre></div>
  </div>
</div>

<script id="report-data" type="application/json">{payload}</script>
<script>
const DATA = JSON.parse(document.getElementById('report-data').textContent);

function esc(s) {{
  return String(s ?? '').replace(/[&<>"']/g, c => ({{
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }})[c]);
}}

document.getElementById('probe-template').innerHTML = DATA.probe_template;
document.getElementById('detector-template').innerHTML = DATA.detector_template;
document.getElementById('probe-path').textContent = DATA.probe_source_path;
document.getElementById('detector-path').textContent = DATA.detector_source_path;

const c = DATA.counts;
document.getElementById('kpis').innerHTML = [
  ['Total scenarios', c.total],
  ['Gate full', c.full],
  ['Gate partial', c.partial],
  ['Gate skip', c.skip],
  ['Experiments', c.experiment || 0],
  ['Garak runs', c.ran],
  ['Attack hits', c.attack_hits],
  ['Defended', c.defense_passes],
].map(([l,n]) => `<div class="kpi"><div class="n">${{n}}</div><div class="l">${{l}}</div></div>`).join('');

function highlightLinked(id) {{
  document.querySelectorAll('.bar-col.active, tr.scenario-row.active').forEach(el => el.classList.remove('active'));
  document.querySelectorAll(`.bar-col[data-id="${{CSS.escape(id)}}"], tr.scenario-row[data-id="${{CSS.escape(id)}}"]`)
    .forEach(el => el.classList.add('active'));
}}

function jumpToTable(id) {{
  const s = DATA.scenarios.find(x => x.scenario_id === id);
  if (s && filter !== 'all' && filter !== s.gate) {{
    filter = 'all';
    document.querySelectorAll('#filters button').forEach(b => b.classList.toggle('active', b.dataset.filter === 'all'));
    renderTable();
  }}
  highlightLinked(id);
  const row = document.querySelector(`tr.scenario-row[data-id="${{CSS.escape(id)}}"]`);
  if (row) row.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
}}

function jumpToChart(id) {{
  highlightLinked(id);
  const bar = document.querySelector(`.bar-col[data-id="${{CSS.escape(id)}}"]`);
  if (bar) bar.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
}}

const chart = document.getElementById('chart');
DATA.scenarios.forEach((s) => {{
  let cls = 'none', val = '—', h = 8;
  if (s.has_run) {{
    if (s.attack_success) {{ cls = 'hit'; val = '100%'; h = 180; }}
    else {{ cls = 'pass'; val = '0%'; h = 28; }}
  }}
  const desc = s.description || s.mechanism_name || s.goal || '';
  const col = document.createElement('div');
  col.className = 'bar-col';
  col.dataset.id = s.scenario_id;
  col.id = `chart-${{s.scenario_id}}`;
  col.innerHTML = `
    <div class="bar-val">${{val}}</div>
    <div class="bar ${{cls}}" style="height:${{h}}px"></div>
    <div class="bar-label">
      ${{esc(s.scenario_id)}}
      <span class="tip"><strong>${{esc(s.scenario_id)}}</strong><br>${{esc(desc)}}</span>
    </div>`;
  col.addEventListener('click', () => jumpToTable(s.scenario_id));
  chart.appendChild(col);
}});

let filter = 'all';
function renderTable() {{
  const tb = document.getElementById('tbody');
  const rows = DATA.scenarios.filter(s => filter === 'all' || s.gate === filter);
  tb.innerHTML = rows.map(s => {{
    const runnable = s.gate === 'full' || s.gate === 'partial' || s.gate === 'experiment';
    const hasYaml = !!(s.probe || s.forge_yaml || s.run);
    const runBadge = !s.has_run
      ? '<span class="badge skip">no run</span>'
      : (s.attack_success
          ? '<span class="badge hit">hit</span>'
          : '<span class="badge pass">pass</span>');
    const desc = s.description ? `<div style="font-size:0.82rem;color:#444;margin-top:2px">${{esc(s.description)}}</div>` : '';
    const idLink = hasYaml
      ? `<a class="scenario-link" href="#" data-open-yaml="${{esc(s.scenario_id)}}" title="Open run view">${{esc(s.scenario_id)}}</a>`
      : `<code>${{esc(s.scenario_id)}}</code>`;
    const jumpBtn = `<button type="button" class="jump" data-jump-chart="${{esc(s.scenario_id)}}" title="Highlight chart bar">Chart</button>`;
    const hasRun = !!s.run;
    const btns = runnable
      ? `<div class="btns">
           <button type="button" class="view" data-id="${{esc(s.scenario_id)}}" data-kind="spec" ${{s.spec ? '' : 'disabled'}}>Spec</button>
           <button type="button" class="view" data-id="${{esc(s.scenario_id)}}" data-kind="run" ${{hasRun ? '' : 'disabled'}}>Run</button>
         </div>`
      : `<div class="btns">
           <button type="button" class="view" disabled>Spec</button>
           <button type="button" class="view" disabled>Run</button>
         </div>`;
    return `<tr class="scenario-row" data-id="${{esc(s.scenario_id)}}" id="row-${{esc(s.scenario_id)}}">
      <td>${{idLink}} ${{jumpBtn}}${{desc}}<div style="font-size:0.75rem;color:#777;margin-top:2px">${{esc(s.gate_reason)}}</div></td>
      <td>${{esc(s.threat_id)}}</td>
      <td><code>${{esc(s.surface)}}</code></td>
      <td><code>${{esc(s.oracle)}}</code></td>
      <td><span class="badge ${{esc(s.gate)}}">${{esc(s.gate)}}</span></td>
      <td>${{runBadge}}</td>
      <td>${{btns}}</td>
    </tr>`;
  }}).join('');
}}
renderTable();

document.getElementById('filters').addEventListener('click', (e) => {{
  const btn = e.target.closest('button[data-filter]');
  if (!btn) return;
  filter = btn.dataset.filter;
  document.querySelectorAll('#filters button').forEach(b => b.classList.toggle('active', b === btn));
  renderTable();
}});

const modal = document.getElementById('modal');
const modalTitle = document.getElementById('modal-title');
const modalPath = document.getElementById('modal-path');
const modalBody = document.getElementById('modal-body');

function openViewer(id, kind) {{
  const s = DATA.scenarios.find(x => x.scenario_id === id);
  if (!s) return;
  const labels = {{
    spec: ['ScenarioSpec (JSON)', `runs/${{id}}/spec.json`],
    run: ['Garak run — prompt, LLM response, detector', `configs/${{id}}.yaml + reports/garak_runs/${{id}}/`],
    forge: ['Forge scenario (YAML)', `examples/scenarios/${{id}}.yaml`],
  }};
  let raw = kind === 'forge' ? s.forge_yaml : s[kind];
  let labelKey = kind;
  if (kind === 'run' && !raw) {{
    labelKey = 'run';
  }}
  if (!raw) {{
    modalTitle.textContent = labels[labelKey][0];
    modalPath.textContent = labels[labelKey][1] + ' — not available';
    modalBody.textContent = '(no data embedded for this scenario)';
  }} else {{
    modalTitle.textContent = `${{labels[labelKey][0]}} — ${{id}}`;
    modalPath.textContent = labels[labelKey][1];
    modalBody.textContent = raw;
  }}
  modal.classList.add('open');
  highlightLinked(id);
}}

function openScenarioYaml(id) {{
  const s = DATA.scenarios.find(x => x.scenario_id === id);
  if (!s) return;
  if (s.run) openViewer(id, 'run');
  else if (s.forge_yaml) openViewer(id, 'forge');
  else openViewer(id, 'run');
}}

document.getElementById('tbody').addEventListener('click', (e) => {{
  const yamlLink = e.target.closest('[data-open-yaml]');
  if (yamlLink) {{
    e.preventDefault();
    openScenarioYaml(yamlLink.dataset.openYaml);
    return;
  }}
  const jump = e.target.closest('[data-jump-chart]');
  if (jump) {{
    e.preventDefault();
    jumpToChart(jump.dataset.jumpChart);
    return;
  }}
  const btn = e.target.closest('button.view:not(:disabled)');
  if (!btn) return;
  openViewer(btn.dataset.id, btn.dataset.kind);
}});

document.getElementById('modal-close').addEventListener('click', () => modal.classList.remove('open'));
modal.addEventListener('click', (e) => {{ if (e.target === modal) modal.classList.remove('open'); }});
document.addEventListener('keydown', (e) => {{ if (e.key === 'Escape') modal.classList.remove('open'); }});
</script>

</body>
</html>
"""




def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Generate Garak meta HTML report")
    parser.add_argument(
        "--out",
        default=str(DEFAULT_OUT),
        help=f"Output HTML path (default: {DEFAULT_OUT})",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)-5s %(message)s")
    data = collect()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(data), encoding="utf-8")
    log.info(
        "Wrote %s (%d scenarios, %d runs, %.1f KB)",
        out,
        data["counts"]["total"],
        data["counts"]["ran"],
        out.stat().st_size / 1024,
    )
    print(f"Report generated: {out}")


if __name__ == "__main__":
    main()
