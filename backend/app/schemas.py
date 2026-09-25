"""Pydantic request/response schemas."""
from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class RuleIn(BaseModel):
    seq: int = Field(ge=1, le=4294967295)
    prefix: str
    action: str = Field(pattern="^(permit|deny)$")
    ge: Optional[int] = Field(default=None, ge=0, le=128)
    le: Optional[int] = Field(default=None, ge=0, le=128)
    remark: str = ""
    rid: Optional[str] = Field(default=None, min_length=1, max_length=64)


class PolicyIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    family: int = Field(default=4, ge=4, le=6)
    default_action: str = Field(default="deny", pattern="^(permit|deny)$")
    description: str = ""


class PolicyRulesIn(BaseModel):
    rules: List[RuleIn]
    default_action: Optional[str] = Field(default=None, pattern="^(permit|deny)$")


class SnapshotIn(BaseModel):
    label: str = ""
    created_by: str = "lab"
    parent_snapshot_id: Optional[int] = None


class WorkCopyIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    base_snapshot_id: Optional[int] = None
    created_by: str = "lab"


class WorkCopyRulesIn(BaseModel):
    rules: List[RuleIn]
    default_action: Optional[str] = Field(default=None, pattern="^(permit|deny)$")
    expected_version: int = Field(ge=0)
    note: str = ""


class MergePreviewIn(BaseModel):
    expected_workcopy_version: Optional[int] = Field(default=None, ge=0)
    refresh: bool = False


class MergeResolutionIn(BaseModel):
    resolutions: dict[str, str] = Field(default_factory=dict)
    expected_session_version: int = Field(default=1, ge=1)


class MergeCommitIn(BaseModel):
    expected_session_version: int = Field(default=1, ge=1)
    label: str = ""
    validate_probes: List[str] = []
    node: str = "a"
    run_frr: bool = False


class MergeDiscardIn(BaseModel):
    reason: str = ""


class CandidateValidateIn(BaseModel):
    probes: List[str]
    node: str = "a"
    run_frr: bool = False


class ClassifyIn(BaseModel):
    prefix: str


class ProbesIn(BaseModel):
    probes: List[str]
    node: str = "a"
    install: bool = True


class DiffIn(BaseModel):
    old_snapshot_id: int
    new_snapshot_id: int


class ScenarioIn(BaseModel):
    name: str
    description: str = ""
    from_snapshot_id: Optional[int] = None
    to_snapshot_id: Optional[int] = None
    probes: List[str] = []


class NeighborIn(BaseModel):
    name: str
    ip: str
    family: int = 4
    asn: Optional[int] = None
    inbound_policy: Optional[str] = None
    outbound_policy: Optional[str] = None
    description: str = ""
