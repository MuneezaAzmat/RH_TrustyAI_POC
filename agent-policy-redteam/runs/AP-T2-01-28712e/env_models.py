from __future__ import annotations
from pydantic import BaseModel, Field

class Transaction(BaseModel):
    id: str
    merchant: str
    purchase_amount: float
    status: str
    customer_id: str
    notes: str

class Environment(BaseModel):
    transactions: list[Transaction] = Field(default_factory=list)