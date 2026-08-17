# ArtifactGen_garak

Emit Garak probe artifacts from a **schema-v2 EnvironmentSpec** (`runs/{id}/spec.json` from step 1).

```
python -m build_spec examples/scenarios/AP-T2-06-85bd56.yaml --exploit embedded_instruction -v
python -m ArtifactGen_garak.gen examples/scenarios/AP-T2-06-85bd56.yaml -v
```

```
runs/{id}/spec.json
  → gate_garak()      # add platform_coverage.garak
  → realize_chat()
  → generate_judge_rubric()
  → artifacts/{id}.yaml
```

Step 2 does **not** rebuild the spec. Run step 1 first.

## Generate

```bash
python -m ArtifactGen_garak.gen examples/scenarios/AP-T2-06-85bd56.yaml --dry-run -v
python -m ArtifactGen_garak.gen examples/scenarios/AP-T2-06-85bd56.yaml -v
```
