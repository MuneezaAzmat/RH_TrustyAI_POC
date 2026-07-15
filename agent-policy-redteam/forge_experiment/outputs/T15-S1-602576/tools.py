def list_dispute_interaction_threads(env: Environment) -> list[dict]:
    return [
        {"buyer_id": thread.buyer_id, "dispute_status": thread.dispute_status}
        for thread in env.dispute_interaction_threads
    ]

def get_dispute_interaction_thread(env: Environment, dispute_thread_id: str) -> dict:
    thread = next((t for t in env.dispute_interaction_threads if t.buyer_id == dispute_thread_id), None)
    return thread.model_dump() if thread else {}

def list_uploaded_documents(env: Environment) -> list[dict]:
    return [
        {"document_id": doc.document_id, "content_type": doc.content_type}
        for doc in env.uploaded_documents
    ]

def get_uploaded_document(env: Environment, document_id: str) -> dict:
    doc = next((d for d in env.uploaded_documents if d.document_id == document_id), None)
    return doc.model_dump() if doc else {}

def list_case_summaries(env: Environment) -> list[dict]:
    return [
        {"case_id": summary.case_id, "recommendation": summary.recommendation}
        for summary in env.case_summaries
    ]

def get_case_summary(env: Environment, case_id: int) -> dict:
    summary = next((s for s in env.case_summaries if s.case_id == case_id), None)
    return summary.model_dump() if summary else {}

def list_review_requests(env: Environment) -> list[dict]:
    return [
        {"request_id": request.request_id, "decision_made": request.decision_made}
        for request in env.review_requests
    ]

def get_review_request(env: Environment, request_id: int) -> dict:
    request = next((r for r in env.review_requests if r.request_id == request_id), None)
    return request.model_dump() if request else {}