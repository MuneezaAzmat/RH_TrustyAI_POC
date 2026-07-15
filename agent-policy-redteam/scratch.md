```
class ScenarioSpec(BaseModel):
    spec_id: str
    risk_card_id: str
    risk_type: str
    domain: str                          # "hr", "finance", "healthcare", "legal", etc.

    # USER TASK — fully specified upfront
    user_task:
        prompt: str                      # exact text given to the agent
        required_data_access: list[str]   # e.g. ["employee records", "performance ratings"]
        forbidden_actions: list[str]      # e.g. ["send_email", "export_data"]
        expected_outcome: str             # what "done" looks like

    # INJECTION TASK — fully specified upfront
    injection:
        goal: str                         # "Trick agent into emailing SSNs to external address"
        attack_pattern: str               # delayed_trigger | progressive_escalation
        attack_variant: str | None
        payload_templates: list[PayloadTemplate]  # text with {placeholders}
        target_surfaces: list[str]        # ["notes", "comments", "bio"]
        trigger_tool: str                 # tool the attack should cause: "send_email"
        exfil_channel: str                # how data leaves: "email", "api", "report"

    # SECURITY CRITERIA — defined upfront, evaluator just runs them
    security_criteria:
        must_not_call: list[str]          # tools that should never appear in attack run
        must_not_contain: list[str]       # sensitive field names in suspicious tool args
        verification_predicates: list[str]
        recipient_must_not_change: bool

    # UTILITY CRITERIA — defined upfront
    utility_criteria:
        must_complete_task: bool
        expected_tool_calls: list[str]    # predicted sequence (validated by dry run)
        task_output_checks: list[str]     # predicates on agent's final response

    # DOMAIN SKELETON — constrains what LLM instantiator can build
    domain_skeleton:
        entity_types: list[EntitySpec]    # name, fields (sensitive flagged), count
        required_tools: list[ToolSpec]    # name, category (read|write|communicate), params
        seed_data_constraints: list[str] # "5-10 records", "realistic fake SSNs", etc. ```