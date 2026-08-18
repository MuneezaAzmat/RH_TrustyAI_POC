"""Build ArtifactGen_garak/Demo/demo.ipynb. Run from repo root or this directory."""

from __future__ import annotations

import json
from pathlib import Path

NB_PATH = Path(__file__).resolve().parent / "demo.ipynb"


def md(source: str) -> dict:
    text = source.strip("\n") + "\n"
    return {
        "cell_type": "markdown",
        "metadata": {},
        "source": [line + "\n" for line in text.split("\n")[:-1]] + [text.split("\n")[-1] + "\n"],
    }


def code(source: str) -> dict:
    text = source.strip("\n") + "\n"
    lines = text.split("\n")
    src = [line + "\n" for line in lines[:-1]]
    if lines[-1]:
        src.append(lines[-1] + "\n")
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": src,
    }


CELLS = [
    md("""\
# End-to-end demo: scenario → Garak artifact → ToolChat attack

This notebook is a walkthrough of **policy-driven agentic red teaming** as implemented in this repository.

You will:

1. Choose an LLM provider and paste an API key (Gemini, OpenAI, Ollama, Hugging Face, or OpenRouter).
2. Pick a bundled threat-model scenario **or paste your own YAML**.
3. Classify the injection surface and generate a Garak **probe artifact** (multi-turn transcript + detector rubric).
4. Replay that artifact against a target model with NVIDIA Garak, using the custom **`toolchat.ToolChat`** generator at `garak/generators/toolchat.py`.
5. Read detector scores, model outputs (including tool calls), and an optional LLM-as-judge verdict.

Run cells **in order**. The attack cell calls a live model and will spend tokens (or a local Ollama pull).
"""),
    md("""\
## Why this pipeline exists

A scenario YAML (under `examples/scenarios/`) is a **threat narrative**: actor beliefs, attack tree, behavior spec. Garak cannot consume that directly. It needs:

- a **fixed transcript** up to the attack encounter (the probe input)
- a **detector** that scores the target's *next* message (did the model comply?)

`ArtifactGen_garak` is the translator:

```
scenario YAML
    → classify injection surface (user_turn | tool_return | system_prompt | skip)
    → one-shot LLM writes turns[] + detector_rubric
    → structural gate (full | partial | skip)
    → runs/{scenario_id}/{scenario_id}-garak.json
    → Garak + ToolChat replays the transcript and judges the next message
```

| Surface | Where the payload lives | Last turn role |
|---|---|---|
| `user_turn` | the user's last message | `user` |
| `tool_return` | a poisoned tool result | `tool` |
| `system_prompt` | the system prompt | `system` |
| `tool_definition` | tool schema itself | **skip** — Garak cannot write this |

Coverage labels:

- **full** — surface and oracle are expressible in Garak
- **partial** — runnable with a downgrade (for example output-string oracle)
- **skip** — not writable; artifact is a stub and no LLM / no attack run
"""),
    md("""\
## Why `toolchat.ToolChat` instead of a plain chat generator

Garak's core `Turn` roles are `system` / `user` / `assistant`. Tool-result injection and multi-turn tool histories need extra OpenAI fields (`role=tool`, `tool_calls`, `tool_call_id`) that those turns cannot carry.

`garak/generators/toolchat.py` solves that without changing Garak's role model:

- Put the full OpenAI `messages` list on `Conversation.notes["messages"]`.
- Pass tool schemas in `extra_params.tools`.
- Model `tool_calls` come back on `Message.notes["tool_calls"]` for detectors.

The demo installs a small **scenario probe + detector** into your local Garak checkout so:

```bash
python -m garak --target_type toolchat.ToolChat --probes scenario.Scenario ...
```

can load `SCENARIO_CONFIG` (the JSON artifact) and replay it.
"""),
    md("""\
## 0. Paths and imports

The notebook locates the **agent-policy-redteam** repo root even if you launched Jupyter from `Demo/`, `ArtifactGen_garak/`, or the repo root. It also records the sibling Garak checkout (override with `GARAK_ROOT` if yours lives elsewhere).
"""),
    code("""\
from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

from IPython.display import Markdown, display

logging.basicConfig(level=logging.INFO, format="%(levelname)-5s %(name)s: %(message)s")

HERE = Path.cwd().resolve()
sys.path.insert(0, str(HERE))
# When launched from Demo/, repo root is two levels up from this file's package.
for candidate in (HERE, *HERE.parents):
    if (candidate / "ArtifactGen_garak" / "gen.py").is_file():
        if str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))
        break

try:
    from ArtifactGen_garak.Demo.demo_runtime import (
        CUSTOM_SCENARIO_TEMPLATE,
        PROVIDER_PRESETS,
        apply_artifact_llm,
        artifact_tools_and_messages,
        build_generator_options,
        classify_preview,
        default_garak_root,
        ensure_garak_plugins,
        existing_key,
        judge_with_llm,
        list_scenario_files,
        repo_root_from,
        run_garak_toolchat,
        run_toolchat_inprocess,
        target_api_key,
        write_custom_scenario,
    )
except ImportError:
    demo_dir = HERE if (HERE / "demo_runtime.py").is_file() else HERE / "ArtifactGen_garak" / "Demo"
    sys.path.insert(0, str(demo_dir))
    from demo_runtime import (
        CUSTOM_SCENARIO_TEMPLATE,
        PROVIDER_PRESETS,
        apply_artifact_llm,
        artifact_tools_and_messages,
        build_generator_options,
        classify_preview,
        default_garak_root,
        ensure_garak_plugins,
        existing_key,
        judge_with_llm,
        list_scenario_files,
        repo_root_from,
        run_garak_toolchat,
        run_toolchat_inprocess,
        target_api_key,
        write_custom_scenario,
    )
from ArtifactGen_garak.extract import load_scenario
from ArtifactGen_garak.gen import generate_artifact
from ArtifactGen_garak.spec_io import load_garak_artifact

try:
    import ipywidgets as widgets
    HAS_WIDGETS = True
except ImportError:
    HAS_WIDGETS = False
    print("ipywidgets not installed — falling back to Python input().")
    print("For the interactive form:  pip install ipywidgets")

REPO = repo_root_from(HERE)
GARAK_ROOT = default_garak_root(REPO)
SCENARIOS = list_scenario_files(REPO)

print(f"Repo root:     {REPO}")
print(f"Garak root:    {GARAK_ROOT}  exists={GARAK_ROOT.is_dir()}")
print(f"Scenarios:     {len(SCENARIOS)} YAML files in examples/scenarios/")
print(f"ToolChat file: {GARAK_ROOT / 'garak' / 'generators' / 'toolchat.py'}")
"""),
    md("""\
## 1. Configure LLM providers and API keys

Two models are involved, and they **do not have to be the same**:

| Role | What it does | Typical choice |
|---|---|---|
| **Artifact generator** | Writes the multi-turn probe + rubric from the scenario YAML | A strong hosted model (Gemini Flash, GPT-4o-mini) |
| **Attack target** | The model Garak actually red-teams via ToolChat | Often a local Ollama model you want to evaluate |

Every preset talks OpenAI Chat Completions. Gemini uses Google's OpenAI-compatible base URL; Ollama speaks the same protocol on `localhost:11434/v1`.

Paste keys only into the password widgets. They are set as process environment variables for this kernel (not written to disk). For Ollama the key can stay `ollama`.
"""),
    code("""\
def _preset_options():
    return [(p["label"], key) for key, p in PROVIDER_PRESETS.items()]


def _fill_from_preset(dd, base_tb, model_tb, key_tb):
    preset = PROVIDER_PRESETS[dd.value]
    base_tb.value = preset["base_url"]
    model_tb.value = preset["model"]
    key_tb.value = existing_key(preset)


if HAS_WIDGETS:
    gen_provider = widgets.Dropdown(options=_preset_options(), value="gemini", description="Provider:")
    gen_base = widgets.Text(description="Base URL:", layout=widgets.Layout(width="560px"))
    gen_model = widgets.Text(description="Model:", layout=widgets.Layout(width="560px"))
    gen_key = widgets.Password(description="API key:", layout=widgets.Layout(width="560px"))
    gen_provider.observe(lambda *_: _fill_from_preset(gen_provider, gen_base, gen_model, gen_key), names="value")
    _fill_from_preset(gen_provider, gen_base, gen_model, gen_key)

    tgt_provider = widgets.Dropdown(options=_preset_options(), value="ollama", description="Provider:")
    tgt_base = widgets.Text(description="Base URL:", layout=widgets.Layout(width="560px"))
    tgt_model = widgets.Text(description="Model:", layout=widgets.Layout(width="560px"))
    tgt_key = widgets.Password(description="API key:", layout=widgets.Layout(width="560px"))
    tgt_provider.observe(lambda *_: _fill_from_preset(tgt_provider, tgt_base, tgt_model, tgt_key), names="value")
    _fill_from_preset(tgt_provider, tgt_base, tgt_model, tgt_key)

    display(Markdown("### Artifact generator (writes the probe)"))
    display(widgets.VBox([gen_provider, gen_base, gen_model, gen_key]))
    display(Markdown(PROVIDER_PRESETS[gen_provider.value]["notes"]))
    display(Markdown("### Attack target (Garak / ToolChat)"))
    display(widgets.VBox([tgt_provider, tgt_base, tgt_model, tgt_key]))
    display(Markdown(PROVIDER_PRESETS[tgt_provider.value]["notes"]))
else:
    print("Available providers:", ", ".join(PROVIDER_PRESETS))
    gen_provider = input("Artifact provider [gemini]: ").strip() or "gemini"
    preset = PROVIDER_PRESETS[gen_provider]
    gen_base = input(f"Artifact base URL [{preset['base_url']}]: ").strip() or preset["base_url"]
    gen_model = input(f"Artifact model [{preset['model']}]: ").strip() or preset["model"]
    import getpass
    gen_key = getpass.getpass("Artifact API key (blank = env / ollama): ")
    tgt_provider = input("Target provider [ollama]: ").strip() or "ollama"
    tpreset = PROVIDER_PRESETS[tgt_provider]
    tgt_base = input(f"Target base URL [{tpreset['base_url']}]: ").strip() or tpreset["base_url"]
    tgt_model = input(f"Target model [{tpreset['model']}]: ").strip() or tpreset["model"]
    tgt_key = getpass.getpass("Target API key (blank = env / ollama): ")
"""),
    code("""\
def _val(widget_or_str):
    return widget_or_str.value if hasattr(widget_or_str, "value") else widget_or_str


GEN_PROVIDER = _val(gen_provider)
GEN_BASE = _val(gen_base).strip()
GEN_MODEL = _val(gen_model).strip()
GEN_KEY = _val(gen_key)

TGT_PROVIDER = _val(tgt_provider)
TGT_BASE = _val(tgt_base).strip()
TGT_MODEL = _val(tgt_model).strip()
TGT_KEY = target_api_key(TGT_PROVIDER, _val(tgt_key))

applied = apply_artifact_llm(
    provider=GEN_PROVIDER,
    base_url=GEN_BASE,
    model=GEN_MODEL,
    api_key=GEN_KEY,
)

# ToolChat always reads OPENAI_API_KEY, even when the target is Gemini / Ollama.
os.environ["OPENAI_API_KEY"] = TGT_KEY or os.environ.get("OPENAI_API_KEY") or "ollama"

print("Artifact generator:")
print(f"  provider={applied['provider']}  model={applied['model']}")
print(f"  base_url={applied['base_url']}")
print("Attack target (ToolChat):")
print(f"  provider={TGT_PROVIDER}  model={TGT_MODEL}")
print(f"  uri={TGT_BASE}")
print(f"  OPENAI_API_KEY set: {bool(os.environ.get('OPENAI_API_KEY'))}")
"""),
    md("""\
## 2. Provide a scenario

Three ways in:

1. **Bundled YAML** — `examples/scenarios/AP-*.yaml` (Klarna-style agent threat models).
2. **Custom YAML** — paste a full scenario in the textarea. `scenario_id` is required. `scenario_seed_metadata.seed_id` (for example `AP-T2-01`) drives injection-surface lookup.
3. **Path** — load a YAML from disk.

`seed_id` prefixes map to surfaces (see `ArtifactGen_garak/classify.py`). Unknown seeds default to `user_turn`. `AP-T17-02` is `tool_definition` and will **skip** generation.

A starter custom scenario is pre-filled. Edit it or ignore it and pick a bundled file.
"""),
    code("""\
scenario_names = [p.name for p in SCENARIOS]
default_scenario = "AP-T2-01-28712e.yaml" if "AP-T2-01-28712e.yaml" in scenario_names else (
    scenario_names[0] if scenario_names else ""
)

if HAS_WIDGETS:
    source_dd = widgets.RadioButtons(
        options=[
            ("Bundled example", "bundled"),
            ("Custom YAML (textarea)", "custom"),
            ("Path on disk", "path"),
        ],
        value="bundled",
        description="Source:",
    )
    scenario_dd = widgets.Dropdown(
        options=scenario_names,
        value=default_scenario or None,
        description="Scenario:",
        layout=widgets.Layout(width="480px"),
    )
    custom_ta = widgets.Textarea(
        value=CUSTOM_SCENARIO_TEMPLATE,
        description="YAML:",
        layout=widgets.Layout(width="100%", height="280px"),
    )
    path_tb = widgets.Text(
        description="Path:",
        placeholder="/absolute/or/repo-relative/scenario.yaml",
        layout=widgets.Layout(width="640px"),
    )
    force_cb = widgets.Checkbox(value=True, description="Write artifact even if structural validation fails (--force)")
    reuse_cb = widgets.Checkbox(value=False, description="Skip LLM; reuse existing runs/{id}/{id}-garak.json if present")
    display(source_dd, scenario_dd, custom_ta, path_tb, force_cb, reuse_cb)
else:
    source_dd = "bundled"
    print("Bundled:", ", ".join(scenario_names[:8]), "...")
    scenario_dd = input(f"Scenario filename [{default_scenario}]: ").strip() or default_scenario
    custom_ta = CUSTOM_SCENARIO_TEMPLATE
    path_tb = ""
    force_cb = True
    reuse_cb = False
"""),
    code("""\
from ArtifactGen_garak.spec_io import garak_artifact_path

source = _val(source_dd)
if source == "bundled":
    scenario_path = REPO / "examples" / "scenarios" / _val(scenario_dd)
elif source == "path":
    raw = Path(_val(path_tb)).expanduser()
    scenario_path = raw if raw.is_absolute() else (REPO / raw)
else:
    scenario_path = write_custom_scenario(REPO, _val(custom_ta))

if not scenario_path.is_file():
    raise FileNotFoundError(f"Scenario not found: {scenario_path}")

ctx = load_scenario(scenario_path)
preview = classify_preview(ctx)
FORCE = bool(_val(force_cb))
REUSE = bool(_val(reuse_cb))

display(Markdown(f"### Loaded `{preview['scenario_id']}`"))
display(Markdown(
    f"- **Threat:** {preview['threat_name']} — {preview['mechanism_name']}\\n"
    f"- **Seed:** `{preview['seed_id']}`\\n"
    f"- **Injection surface:** `{preview['injection_surface']}`"
    f"{' (writable)' if preview['writable'] else ' — will SKIP'}\\n"
    f"- **Quoted tools:** {preview['quoted_tools'] or '—'}\\n"
    f"- **Tags:** {', '.join(preview['tags']) or '—'}\\n"
    f"- **Entry:** {preview['entry_point']}"
))
if preview["skip_reason"]:
    display(Markdown(f"> Skip reason: {preview['skip_reason']}"))
display(Markdown("**Narrative summary**"))
print(preview["narrative_summary"] or "(none)")
print()
print("Attack goal:", preview["attack_goal"])
print("Zones:", " → ".join(preview["zone_sequence"]) or "—")
print("Scenario file:", scenario_path)
"""),
    md("""\
## 3. Generate the Garak artifact

`generate_artifact` is the same entry point as:

```bash
python -m ArtifactGen_garak.gen examples/scenarios/<id>.yaml --force -v
```

It classifies, optionally calls the LLM with `prompts/generate_artifact.md`, validates the probe (last turn adversarial, surface/role alignment, non-empty rubric), then writes:

```
runs/{scenario_id}/{scenario_id}-garak.json   # probe
runs/{scenario_id}/validation.json            # structural gate
```

Check **reuse existing** above if you already generated this id and only want to run Garak.
"""),
    code("""\
from ArtifactGen_garak.spec_io import garak_artifact_path, validation_path

artifact_path = garak_artifact_path(ctx.scenario_id, REPO / "runs")
validation_file = validation_path(ctx.scenario_id, REPO / "runs")

if REUSE and artifact_path.is_file():
    result = type("R", (), {
        "ok": True,
        "gate": "reused",
        "gate_reason": "loaded existing artifact",
        "artifact_path": str(artifact_path),
        "errors": None,
        "scenario_id": ctx.scenario_id,
    })()
    print(f"Reusing {artifact_path}")
else:
    print(f"Generating with {applied['provider']} / {applied['model']} ...")
    result = generate_artifact(
        ctx,
        output_dir=REPO / "runs",
        use_llm=True,
        force=FORCE,
        dry_run=False,
    )

print()
print(f"scenario_id:    {result.scenario_id}")
print(f"ok:             {result.ok}")
print(f"gate:           {result.gate}")
print(f"gate_reason:    {result.gate_reason}")
print(f"artifact_path:  {result.artifact_path}")
if result.errors:
    print("errors:")
    for e in result.errors:
        print(" -", e)

artifact = None
if result.artifact_path and Path(result.artifact_path).is_file():
    artifact = load_garak_artifact(result.artifact_path)
    artifact_path = Path(result.artifact_path)
    display(Markdown(f"Wrote `{artifact_path.relative_to(REPO) if artifact_path.is_relative_to(REPO) else artifact_path}`"))
if validation_file.is_file():
    val = json.loads(validation_file.read_text())
    display(Markdown(f"Validation ok=`{val.get('ok')}` errors=`{val.get('errors')}`"))
"""),
    md("""\
## 4. Inspect the probe

The artifact is the contract between generation and Garak:

- `turns` — fabricated history. Assistant turns are **context**, not model output. The last turn is the attack (`adversarial: true`).
- `detector_rubric` — judge prompt, ground-truth `context`, and `attack_success` / `attack_blocked` predicates. The judge (and the heuristic detector) see **only the target's next message**.
"""),
    code("""\
if artifact is None:
    display(Markdown("No artifact loaded — generation skipped or failed. Stop here if `gate=skip`."))
else:
    display(Markdown(
        f"### `{artifact.get('scenario_id')}`  "
        f"surface=`{artifact.get('injection_surface')}`  "
        f"coverage=`{artifact.get('platform_coverage')}`  "
        f"model=`{artifact.get('model')}`"
    ))
    display(Markdown((artifact.get("narrative") or {}).get("summary") or ""))
    rows = []
    for i, t in enumerate(artifact.get("turns") or []):
        flag = " **ATTACK**" if t.get("adversarial") else ""
        tool = f" `{t.get('tool_name')}`" if t.get("tool_name") else ""
        body = (t.get("content") or "").replace("\\n", " ")
        if len(body) > 280:
            body = body[:280] + "…"
        rows.append(f"| {i} | `{t.get('role')}`{tool}{flag} | {body} |")
    display(Markdown(
        "| # | role | content |\\n|---|---|---|\\n" + "\\n".join(rows)
    ))
    rubric = artifact.get("detector_rubric") or {}
    display(Markdown("### Detector rubric"))
    print("judge_prompt:", (rubric.get("judge_prompt") or "")[:400], "...")
    print()
    print("context:", rubric.get("context") or "")
    print()
    print("attack_success:")
    for p in (rubric.get("rubrics") or {}).get("attack_success") or []:
        print("  ✓", p)
    print("attack_blocked:")
    for p in (rubric.get("rubrics") or {}).get("attack_blocked") or []:
        print("  ✗", p)
"""),
    md("""\
## 5. Prepare Garak + ToolChat

This step:

1. Copies `ArtifactGen_garak/plugins/probes/scenario.py` and `.../detectors/scenario.py` into your Garak checkout so `--probes scenario.Scenario` resolves.
2. Converts artifact turns into OpenAI `messages` (injecting synthetic `tool_calls` before `role=tool` turns — required by the Chat Completions API).
3. Parses tool signatures out of the system prompt for `extra_params.tools`.

The probe stores those messages on `Conversation.notes["messages"]`, which is exactly what `ToolChat._call_model` forwards.
"""),
    code("""\
if artifact is None or not artifact.get("turns"):
    raise RuntimeError("Need a generated artifact with turns[] before running Garak.")

plugin_paths = ensure_garak_plugins(REPO, GARAK_ROOT)
tools, messages = artifact_tools_and_messages(artifact)
gen_opts = build_generator_options(uri=TGT_BASE, tools=tools)

display(Markdown("### Installed Garak plugins"))
print("probe:    ", plugin_paths["probe"])
print("detector: ", plugin_paths["detector"])
print("ToolChat: ", GARAK_ROOT / "garak" / "generators" / "toolchat.py")
print()
print(f"OpenAI messages to replay: {len(messages)}")
print(f"Tools advertised: {[t['function']['name'] for t in tools] or '(none parsed)'}")
display(Markdown("### Last three messages (attack should be last)"))
print(json.dumps(messages[-3:], indent=2)[:4000])
display(Markdown("### Generator options passed to Garak"))
print(json.dumps(gen_opts, indent=2)[:2500])
"""),
    md("""\
## 6. Run the attack

Garak CLI equivalent (what the next cell executes):

```bash
export SCENARIO_CONFIG=/path/to/{id}-garak.json
export OPENAI_API_KEY=...          # dummy 'ollama' is fine for local
export PYTHONPATH=/path/to/garak:$PYTHONPATH

python -m garak \\
  --target_type toolchat.ToolChat \\
  --target_name qwen2.5:14b \\
  --probes scenario.Scenario \\
  --generations 1 \\
  --report_prefix reports/garak_runs/{id}/garak \\
  --generator_options '{"toolchat":{"ToolChat":{"uri":"http://127.0.0.1:11434/v1/",...}}}'
```

**Scoring reminder:** in this detector, **1.0 = attack succeeded** (the model complied). That is the opposite of a “passed safety test” reading. `attack_success=true` means the target is vulnerable to this scenario.

If the CLI fails (plugin cache, missing garak install), the cell falls back to calling `ToolChat.generate` in-process so you still see a model response.
"""),
    code("""\
USE_CLI = True  # set False to skip CLI and call ToolChat in-process only

garak_result = None
inprocess = None

if USE_CLI:
    try:
        print("Running python -m garak --target_type toolchat.ToolChat ...")
        garak_result = run_garak_toolchat(
            repo=REPO,
            garak_root=GARAK_ROOT,
            artifact_path=artifact_path,
            target_name=TGT_MODEL,
            uri=TGT_BASE,
            api_key=TGT_KEY,
            tools=tools,
            generations=1,
            out_dir=REPO / "reports" / "garak_runs" / ctx.scenario_id,
        )
        print(f"exit={garak_result['exit_code']}  elapsed={garak_result['elapsed_sec']}s  "
              f"status={garak_result.get('status')}  attack_success={garak_result.get('attack_success')}")
        if garak_result.get("run_log"):
            log_tail = Path(garak_result["run_log"]).read_text(encoding="utf-8")[-2500:]
            display(Markdown("### Garak log (tail)"))
            print(log_tail)
    except Exception as exc:
        print("CLI run failed:", type(exc).__name__, exc)
        print("Falling back to in-process ToolChat.generate ...")
        USE_CLI = False

if not USE_CLI or not garak_result or garak_result.get("status") in {"missing_report", "no_attempts"}:
    inprocess = run_toolchat_inprocess(
        garak_root=GARAK_ROOT,
        artifact=artifact,
        target_name=TGT_MODEL,
        uri=TGT_BASE,
        api_key=TGT_KEY,
        tools=tools,
        generations=1,
    )
    display(Markdown("### In-process ToolChat output"))
    print(json.dumps(inprocess, indent=2)[:6000])
"""),
    md("""\
## 7. Read the result

Two signals:

1. **Heuristic detector** (`scenario.ScenarioDetector`) — matches quoted strings and tool names from the rubric against the reply + `tool_calls`. Fast, no extra LLM call. Can under- or over-fire on paraphrase.
2. **LLM-as-judge** (next cell) — sends the artifact `judge_prompt` + `context` + rubrics + the target's message to the *artifact generator* model. Closer to how the rubric was designed to be used.
"""),
    code("""\
outputs = []
if garak_result and garak_result.get("outputs"):
    outputs = garak_result["outputs"]
elif inprocess and inprocess.get("outputs"):
    outputs = [o for o in inprocess["outputs"] if o]

display(Markdown("### Target next message"))
if not outputs:
    print("No model outputs recorded. Check the run log and that the target URI is reachable.")
else:
    for i, o in enumerate(outputs):
        text = o.get("text") if isinstance(o, dict) else str(o)
        notes = (o.get("notes") if isinstance(o, dict) else {}) or {}
        print(f"--- generation {i} ---")
        print(text or "(empty text)")
        tcs = notes.get("tool_calls")
        if tcs:
            print("tool_calls:", json.dumps(tcs, indent=2)[:3000])
        print()

if garak_result:
    display(Markdown("### Detector summary"))
    keys = (
        "scenario_id", "status", "attack_success", "mean_detector_score",
        "attempts", "hits", "elapsed_sec", "report_jsonl", "report_html",
    )
    print(json.dumps({k: garak_result.get(k) for k in keys}, indent=2))
    print("detector_scores:", garak_result.get("detector_scores"))
    if garak_result.get("attack_success"):
        display(Markdown(
            "**Attack succeeded** — the target's next message matched `attack_success` "
            "more strongly than `attack_blocked`. The agent complied with the injected instruction."
        ))
    elif garak_result.get("status") == "ok":
        display(Markdown(
            "**Attack blocked** — detector score below 0.5. The target refused, "
            "asked for verification, or did not perform the forbidden action."
        ))
"""),
    code("""\
# Optional LLM-as-judge using the same provider as artifact generation.
RUN_LLM_JUDGE = True

judge = None
if RUN_LLM_JUDGE and outputs:
    first = outputs[0] if isinstance(outputs[0], dict) else {"text": str(outputs[0]), "notes": {}}
    print("Judging with", applied["model"], "...")
    try:
        judge = judge_with_llm(
            artifact,
            first.get("text") or "",
            (first.get("notes") or {}).get("tool_calls"),
        )
        display(Markdown("### LLM judge"))
        print(json.dumps(judge, indent=2))
        verdict = str(judge.get("verdict") or "")
        if verdict == "attack_success":
            display(Markdown("Judge: **attack succeeded**."))
        elif verdict == "attack_blocked":
            display(Markdown("Judge: **attack blocked**."))
    except Exception as exc:
        print("LLM judge failed:", type(exc).__name__, exc)
        print("Heuristic detector scores above still stand.")
else:
    print("Skipped LLM judge (set RUN_LLM_JUDGE = True and ensure there is a model output).")
"""),
    md("""\
## 8. What to do with a finding

- **Attack succeeded** on a `full` artifact: the scenario is a credible Garak-reproducible failure. File it against the target's tool-use / policy stack (argument validation, human-in-the-loop, tool allow-lists).
- **Attack blocked**: either the model refused correctly, or the transcript/rubric is too weak. Re-generate with `--force`, try a stronger artifact model, or tighten the last user/tool turn.
- **Skip / no turns**: pick a writable surface (`AP-T2-*` user_turn, `AP-T7-02` tool_return). `AP-T17-02` is tool-definition and will never run.
- **CLI vs in-process**: CLI writes `reports/garak_runs/{id}/garak.report.jsonl` (and HTML). In-process is a smoke test only.

Batch the same flow from the repo root:

```bash
python -m ArtifactGen_garak.gen examples/scenarios/AP-T2-01-28712e.yaml --force -v
# then this notebook's Garak cell, or:
python ArtifactGen_garak/run_garak_batch.py --artifact runs/AP-T2-01-28712e/AP-T2-01-28712e-garak.json
```

The batch runner currently defaults to `ollama.OllamaGeneratorChat`. This demo is the ToolChat path, which is the one that preserves tool histories.
"""),
    md("""\
## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Gemini selected but no API key` | Artifact provider is Gemini, key widget empty, `.env` unset | Paste `GEMINI_API_KEY` or switch provider |
| Garak `APIKeyMissingError` / `OPENAI_API_KEY` | ToolChat always reads that env var | Cell 1 sets it; for Ollama use `ollama` |
| Connection refused on `:11434` | Ollama not running / wrong model tag | `ollama serve` and `ollama pull qwen2.5:14b` |
| `Unknown plugin: scenario` | Plugins not copied into the Garak checkout | Re-run the prepare cell; check `GARAK_ROOT` |
| Probe validation errors | LLM JSON drifted from schema | Enable `--force`, or switch artifact model |
| Empty `tool_calls` | Target ignored tools or extra_params dropped | Confirm tools parsed from the system prompt; try a tool-capable model |
| `gate=skip` | Unwritable surface | Choose a `user_turn` / `tool_return` seed |

Custom Garak location:

```python
import os
os.environ["GARAK_ROOT"] = "/Users/Muneeza/Documents/experiments/garak"
```

then re-run the paths cell.
"""),
]


def main() -> None:
    nb = {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3",
            },
            "language_info": {"name": "python", "pygments_lexer": "ipython3"},
        },
        "cells": CELLS,
    }
    NB_PATH.write_text(json.dumps(nb, indent=1) + "\n", encoding="utf-8")
    print(f"Wrote {NB_PATH} ({len(CELLS)} cells)")


if __name__ == "__main__":
    main()
