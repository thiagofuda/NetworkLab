from typing import Literal

from pydantic import BaseModel


class TerraformPlanSummary(BaseModel):
    create: int = 0
    update: int = 0
    delete: int = 0
    replace: int = 0
    no_op: int = 0
    read: int = 0


class TerraformPlanResource(BaseModel):
    resource_index: int
    address: str
    type: str
    action: str
    provider_name: str | None = None
    action_reason: str | None = None


class TerraformPlanFinding(BaseModel):
    code: str
    severity: Literal["warning", "high"]
    resource: str
    resource_index: int
    message: str
    status: Literal["confirmed", "inconclusive"] = "confirmed"


class TerraformPlanResult(BaseModel):
    valid: bool = True
    provider: Literal["aws", "oci"]
    summary: TerraformPlanSummary
    resources: list[TerraformPlanResource]
    findings: list[TerraformPlanFinding]
    truncated: bool = False


class TerraformPlanErrorDetail(BaseModel):
    code: str
    message: str


class TerraformPlanErrorResponse(BaseModel):
    detail: TerraformPlanErrorDetail
