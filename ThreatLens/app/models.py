from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: datetime
    event_type: str
    source_ip: str
    username: Optional[str] = None
    host: Optional[str] = None
    action: Optional[str] = None
    outcome: Optional[str] = None
    command: Optional[str] = None
    bytes_sent: int = Field(default=0, ge=0)
    metadata: Dict[str, str] = Field(default_factory=dict)


class Evidence(BaseModel):
    event_id: str
    explanation: str


class Alert(BaseModel):
    alert_id: str
    title: str
    technique_id: str
    technique_name: str
    severity: str
    confidence: float = Field(ge=0, le=1)
    status: str = "open"
    first_seen: datetime
    last_seen: datetime
    evidence: List[Evidence]
    recommendation: str


class AlertUpdate(BaseModel):
    status: str = Field(pattern="^(open|investigating|resolved|false_positive)$")
