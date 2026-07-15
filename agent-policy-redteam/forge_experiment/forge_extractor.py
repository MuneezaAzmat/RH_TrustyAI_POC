"""Extract structured scenario data from scanario_forge.html raw YAML blocks."""

import html
import re
import sys
from pathlib import Path

import yaml


HTML_PATH = Path(__file__).parent.parent / "scanario_forge.html"

SCENARIO_RAW_IDS = {
    "T15-S1-602576": {"yaml": "raw-5-code", "feature": "raw-36-code"},
    "T10-S2-667499": {"yaml": "raw-3-code", "feature": "raw-34-code"},
}


def _strip_html(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text)
    text = html.unescape(text)
    return text


def _extract_block(html_content: str, block_id: str) -> str:
    pattern = rf'id="{block_id}">(.*?)</div>'
    match = re.search(pattern, html_content, re.DOTALL)
    if not match:
        raise ValueError(f"Block {block_id} not found in HTML")
    return _strip_html(match.group(1))


def extract_scenario(html_content: str, scenario_id: str) -> dict:
    ids = SCENARIO_RAW_IDS[scenario_id]
    yaml_text = _extract_block(html_content, ids["yaml"])
    feature_text = _extract_block(html_content, ids["feature"])

    scenario = yaml.safe_load(yaml_text)
    scenario["_feature_text"] = feature_text
    return scenario


def extract_all(html_path: str | Path = HTML_PATH) -> dict[str, dict]:
    content = Path(html_path).read_text()
    results = {}
    for sid in SCENARIO_RAW_IDS:
        results[sid] = extract_scenario(content, sid)
    return results


def _print_summary(scenario: dict) -> None:
    n = scenario.get("narrative", {})
    p = scenario.get("priority", {})
    tree = scenario.get("attack_tree", {})

    print(f"  ID:            {scenario.get('scenario_id')}")
    print(f"  Title:         {n.get('title')}")
    print(f"  Entry Point:   {n.get('entry_point')}")
    print(f"  Zone Sequence: {n.get('zone_sequence')}")
    print(f"  Priority:      {p.get('composite')} ({p.get('signals', {}).get('risk_impact')})")
    print(f"  Attack Goal:   {tree.get('goal')}")
    print(f"  Steps:         {len(n.get('steps', []))}")

    steps = n.get("steps", [])
    for s in steps:
        print(f"    Step {s['step_number']} [Z{s['zone']}]: {s['action'][:80]}...")

    leaves = []
    _collect_leaves(tree.get("root", {}), leaves)
    print(f"  Attack Tree Leaves: {len(leaves)}")
    for leaf in leaves:
        print(f"    [{leaf.get('id')}] Z{leaf.get('zone')}: {leaf.get('label')}")


def _collect_leaves(node: dict, leaves: list) -> None:
    if node.get("gate") == "LEAF":
        leaves.append(node)
    for child in node.get("children", []):
        _collect_leaves(child, leaves)


if __name__ == "__main__":
    scenarios = extract_all()
    for sid, data in scenarios.items():
        print(f"\n{'='*60}")
        print(f"SCENARIO: {sid}")
        print(f"{'='*60}")
        _print_summary(data)

    print(f"\nExtracted {len(scenarios)} scenarios successfully.")
