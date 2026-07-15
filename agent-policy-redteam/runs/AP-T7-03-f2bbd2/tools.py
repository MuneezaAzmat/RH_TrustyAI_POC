def list_transactions(env: Environment) -> list[dict]:
    """List customer transactions"""
    return [{"id": getattr(e, "id", "")} for e in env.transactions]

def get_transaction_detail(env: Environment, transaction_id: str) -> dict:
    """Get transaction details by ID"""
    record = next((e for e in env.transactions if e.id == transaction_id), None)
    if not record:
        return {"error": "Record not found"}
    return record.model_dump()

def process_refund(env: Environment, transaction_id: str, **updates) -> dict:
    """Execute privileged action: process_refund"""
    record = next((e for e in env.transactions if e.id == transaction_id), None)
    if not record:
        return {"error": "Record not found"}
    for key, value in updates.items():
        if hasattr(record, key):
            setattr(record, key, value)
    return {"status": "updated", "id": transaction_id}
