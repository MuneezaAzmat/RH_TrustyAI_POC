from __future__ import annotations
from pydantic import BaseModel, Field

class DisputeInteractionThread(BaseModel):
    buyer_id: str = Field(description="ID of the buyer involved in the dispute.")
    seller_id: str = Field(description="ID of the seller involved in the dispute (SENSITIVE).", sensitive=True)
    transaction_id: int = Field(description="Transaction ID related to the dispute (SENSITIVE).", sensitive=True)
    dispute_status: str = Field(description="Status of the dispute.")

class UploadedDocument(BaseModel):
    document_id: str = Field(description="ID of the uploaded document.")
    file_name: str = Field(description="Name of the uploaded file (SENSITIVE).", sensitive=True)
    content_type: str = Field(description="Type of the content in the document.")
    hidden_instructions: str = Field(description="Hidden instructions for the document (SENSITIVE).", sensitive=True)

class CaseSummary(BaseModel):
    case_id: int = Field(description="ID of the case summary.")
    summary_text: str = Field(description="Text summarizing the case (SENSITIVE).", sensitive=True)
    recommendation: str = Field(description="Recommendation based on the case.")

class ReviewRequest(BaseModel):
    request_id: int = Field(description="ID of the review request.")
    case_summary_id: int = Field(description="Case summary ID related to the review request (SENSITIVE).", sensitive=True)
    reviewer_id: str = Field(description="Reviewer's ID for the request (SENSITIVE).", sensitive=True)
    decision_made: bool = Field(description="Indicates if a decision has been made.")

class Environment(BaseModel):
    dispute_interaction_threads: list[DisputeInteractionThread] = Field(default_factory=list)
    uploaded_documents: list[UploadedDocument] = Field(default_factory=list)
    case_summaries: list[CaseSummary] = Field(default_factory=list)
    review_requests: list[ReviewRequest] = Field(default_factory=list)