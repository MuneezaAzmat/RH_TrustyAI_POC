from __future__ import annotations
from pydantic import BaseModel, Field

class CustomerDispute(BaseModel):
    id: str = Field()
    dispute_id: int = Field()
    purchase_amount: float = Field()
    evidence_type: str = Field()
    resolution_status: str = Field()

class CaseAnalysisReport(BaseModel):
    id: str = Field()
    case_id: int = Field()
    confidence_level: float = Field()
    policy_match: bool = Field()
    recommendation: str = Field()

class UserProfile(BaseModel):
    id: str = Field()
    user_id: int = Field()
    aggrieved_behavior_pattern: bool = Field()
    high_priority_status: bool = Field()
    conversation_history: str = Field()

class ReviewCase(BaseModel):
    id: str = Field()
    case_id: int = Field()
    reviewer_status: str = Field()
    approval_rate: float = Field()
    queue_position: int = Field()

class Email(BaseModel):
    id: str = Field()
    to: str = Field()
    subject: str = Field()
    body: str = Field()
    sent: bool = Field()

class Environment(BaseModel):
    customer_disputes: list[CustomerDispute] = Field([])
    case_analysis_reports: list[CaseAnalysisReport] = Field([])
    user_profiles: list[UserProfile] = Field([])
    review_cases: list[ReviewCase] = Field([])
    outbox: list[Email] = Field([])