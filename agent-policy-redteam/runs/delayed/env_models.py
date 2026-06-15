from __future__ import annotations
from pydantic import BaseModel, Field

class Employee(BaseModel):
    id: str
    ssn: str
    salary: float
    department: str
    years_of_service: int
    notes: str

class Email(BaseModel):
    id: str
    to: str
    subject: str
    body: str
    sent: bool = False

class Environment(BaseModel):
    employees: list[Employee] = Field(default_factory=list)
    outbox: list[Email] = Field(default_factory=list)