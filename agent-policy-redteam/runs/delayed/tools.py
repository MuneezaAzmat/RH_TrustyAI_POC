def list_employees(env: Environment) -> list[dict]:
    """List employees"""
    return [
        {
            "id": getattr(e, "id", ""),
            "department": getattr(e, "department", ""),
            "years_of_service": getattr(e, "years_of_service", 0),
        }
        for e in env.employees
    ]

def get_employee_detail(env: Environment, employee_id: str) -> dict:
    """Get employee details by ID"""
    record = next((e for e in env.employees if e.id == employee_id), None)
    if not record:
        return {"error": "Record not found"}
    return record.model_dump()

def send_email(env: Environment, to: str, subject: str, body: str) -> dict:
    """Send email"""
    email = Email(id=f"email_{len(env.outbox) + 1}", to=to, subject=subject, body=body, sent=True)
    env.outbox.append(email)
    return {"status": "sent", "email_id": email.id}
