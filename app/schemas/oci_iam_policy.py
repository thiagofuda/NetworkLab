from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

# Cada statement tem limite proprio, alem do limite agregado da requisicao.
PolicyStatement = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=2048),
]


class OciPolicyAnalysisRequest(BaseModel):
    """Entrada publica com limites por statement e para o conjunto completo."""

    model_config = ConfigDict(extra="forbid")

    statements: list[PolicyStatement] = Field(min_length=1, max_length=50)

    @model_validator(mode="after")
    def check_total_statement_size(self) -> "OciPolicyAnalysisRequest":
        """Conta bytes UTF-8, nao caracteres, para limitar o corpo enviado."""
        try:
            total_bytes = sum(
                len(statement.encode("utf-8")) for statement in self.statements
            )
        except UnicodeEncodeError as error:
            raise ValueError("Statements must be valid UTF-8.") from error
        if total_bytes > 16 * 1024:
            raise ValueError("The combined statement text exceeds 16 KiB.")
        return self


class GeminiPolicyFinding(BaseModel):
    """Formato esperado do modelo; configurado como estrito e sem campos extras."""

    model_config = ConfigDict(extra="forbid", strict=True)

    code: Literal[
        "POTENTIAL_REDUNDANCY",
        "BROAD_PERMISSION",
        "CONDITION_REVIEW",
    ]
    severity: Literal["info", "warning", "high"]
    assessment: Literal["candidate", "inconclusive"]
    statement_indexes: list[int] = Field(min_length=1, max_length=50)
    suggested_keep_indexes: list[int] = Field(max_length=50)
    message: Annotated[str, StringConstraints(min_length=1, max_length=240)]
    explanation: Annotated[str, StringConstraints(min_length=1, max_length=800)]

    @model_validator(mode="after")
    def check_suggestion_indexes(self) -> "GeminiPolicyFinding":
        """Impede indices repetidos ou sugestoes fora do grupo analisado."""
        if len(set(self.statement_indexes)) != len(self.statement_indexes):
            raise ValueError("Statement indexes must be unique.")
        if not set(self.suggested_keep_indexes).issubset(self.statement_indexes):
            raise ValueError("Suggested indexes must refer to finding indexes.")
        return self


class GeminiPolicyAnalysis(BaseModel):
    """Resposta completa esperada do Gemini."""

    model_config = ConfigDict(extra="forbid", strict=True)

    findings: list[GeminiPolicyFinding] = Field(max_length=100)


class OciPolicyFinding(BaseModel):
    """Finding publico; findings Gemini continuam marcados para revisao humana."""

    code: str
    source: Literal["python", "gemini"]
    assessment: Literal["confirmed", "candidate", "inconclusive"]
    severity: Literal["info", "warning", "high"]
    statement_indexes: list[int]
    message: str
    explanation: str
    suggested_keep_indexes: list[int] = Field(default_factory=list)
    review_only: bool = True


class OciPolicyAnalysisResponse(BaseModel):
    """Resultado agregado; completed nao significa policy aprovada."""

    status: Literal["completed", "inconclusive"]
    findings: list[OciPolicyFinding]
    analysis_limitations: list[str] = Field(default_factory=list)


class OciPolicyErrorDetail(BaseModel):
    """Detalhe publico sem texto bruto de erro ou dados da policy."""

    code: str
    message: str
    operation: str | None = None
    upstream_status: str | None = None


class OciPolicyErrorResponse(BaseModel):
    """Envelope de erro documentado pela API."""

    detail: OciPolicyErrorDetail
