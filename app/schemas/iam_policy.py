from pydantic import BaseModel


class PolicyIssue(BaseModel):
    code: str
    message: str
    path: str | None = None
    field: str | None = None
    line: int | None = None
    column: int | None = None
    suggestion: str | None = None


class PolicyValidationResult(BaseModel):
    valid: bool
    errors: list[PolicyIssue]
    warnings: list[PolicyIssue]
    truncated: bool = False
