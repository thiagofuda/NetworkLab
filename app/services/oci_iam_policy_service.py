import re
from collections import defaultdict
from typing import Protocol

from app.schemas.oci_iam_policy import (
    GeminiPolicyAnalysis,
    OciPolicyAnalysisResponse,
    OciPolicyFinding,
)

# Este parser reconhece apenas o formato Allow usado pelo analisador; ele nao
# substitui o parser oficial da linguagem OCI IAM.
MAX_STATEMENT_BYTES = 16 * 1024
POLICY_STATEMENT_PATTERN = re.compile(
    r"^Allow\s+(?P<subject>.+?)\s+to\s+"
    r"(?P<verb>inspect|read|use|manage)\s+"
    r"(?P<resource_type>.+?)\s+in\s+(?P<scope>.+)$",
    re.IGNORECASE,
)
PATTERN_WITH_WHITESPACE = re.compile(r"/[^/]*\s+[^/]*/")
BASE_LIMITATIONS = [
    # A analise e local: nao consulta a tenancy nem resolve equivalencias OCI.
    "TENANCY_NOT_QUERIED",
    "RESOURCE_FAMILY_EQUIVALENCE_NOT_EVALUATED",
]


class PolicyInputError(ValueError):
    """Indica que a entrada nao pertence ao subconjunto aceito pelo servico."""

    pass


class InvalidGeminiResponse(ValueError):
    """Indica que a resposta Gemini nao pode ser usada com seguranca."""

    pass


class GeminiPolicyAnalyzer(Protocol):
    """Contrato minimo da chamada externa, facil de substituir nos testes."""

    async def analyze(
        self,
        indexed_statements: list[tuple[int, str]],
    ) -> GeminiPolicyAnalysis: ...


def _validate_statement(statement: str, index: int) -> None:
    """Rejeita statements fora do formato suportado antes de chamar o Gemini."""
    if _policy_scope(statement) is None:
        raise PolicyInputError(
            f"Statement at index {index} is not a supported OCI Allow statement."
        )


def _split_where(scope: str) -> tuple[str, str | None]:
    """Separa localizacao e condicao sem cortar a palavra dentro de aspas."""
    in_quote = False
    escaped = False
    lower_scope = scope.lower()

    for index, character in enumerate(scope):
        # Aspas escapadas nao encerram a string da condicao.
        if in_quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == "'":
                in_quote = False
            continue
        if character == "'":
            in_quote = True
            continue
        if (
            lower_scope.startswith("where", index)
            and index > 0
            and scope[index - 1].isspace()
            and index + 5 < len(scope)
            and scope[index + 5].isspace()
        ):
            return scope[:index].strip(), scope[index + 5 :].strip()
    return scope.strip(), None


def _policy_scope(statement: str) -> tuple[str, str, str, str | None] | None:
    """Retorna principal, recurso, localizacao e condicao do formato aceito."""
    match = POLICY_STATEMENT_PATTERN.fullmatch(statement)
    if match is None:
        return None
    location, condition = _split_where(match.group("scope"))
    if not location or condition == "":
        return None
    return (
        _normalize_statement(match.group("subject")),
        _normalize_statement(match.group("resource_type")),
        _normalize_statement(location),
        _normalize_statement(condition) if condition is not None else None,
    )


def _normalize_statement(statement: str) -> str:
    """Normaliza espacos sem alterar valores entre aspas ou expressoes regex."""
    # Em expressoes entre barras, ate espacos fora de aspas podem ser relevantes.
    if PATTERN_WITH_WHITESPACE.search(statement):
        return statement.strip()

    normalized: list[str] = []
    in_quote = False
    pending_space = False
    escaped = False

    for character in statement.strip():
        if in_quote:
            normalized.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == "'":
                in_quote = False
        elif character == "'":
            if pending_space and normalized:
                normalized.append(" ")
            normalized.append(character)
            pending_space = False
            in_quote = True
        elif character.isspace():
            pending_space = True
        else:
            if pending_space and normalized:
                normalized.append(" ")
            normalized.append(character)
            pending_space = False

    return "".join(normalized)


def _find_exact_duplicates(statements: list[str]) -> list[OciPolicyFinding]:
    """Agrupa somente statements iguais apos a normalizacao conservadora."""
    indexes_by_statement: dict[str, list[int]] = defaultdict(list)
    for index, statement in enumerate(statements):
        indexes_by_statement[_normalize_statement(statement)].append(index)

    findings: list[OciPolicyFinding] = []
    for indexes in indexes_by_statement.values():
        if len(indexes) < 2:
            continue
        findings.append(
            OciPolicyFinding(
                code="EXACT_DUPLICATE",
                source="python",
                assessment="confirmed",
                severity="warning",
                statement_indexes=indexes,
                message=(
                    "These statements are identical after safe whitespace "
                    "normalization."
                ),
                explanation="Only whitespace outside quoted values was normalized.",
                suggested_keep_indexes=[indexes[0]],
            )
        )
    return findings


def _build_inconclusive_result(
    duplicate_findings: list[OciPolicyFinding],
    limitation: str,
) -> OciPolicyAnalysisResponse:
    """Preserva duplicatas confirmadas quando a parte semantica falha."""
    return OciPolicyAnalysisResponse(
        status="inconclusive",
        findings=duplicate_findings,
        analysis_limitations=[*BASE_LIMITATIONS, limitation],
    )


def _convert_gemini_findings(
    analysis: GeminiPolicyAnalysis,
    valid_indexes: set[int],
    statements_by_index: dict[int, str],
) -> list[OciPolicyFinding]:
    """Valida referencias do Gemini e limita sugestoes a revisao humana."""
    findings: list[OciPolicyFinding] = []
    for finding in analysis.findings:
        indexes = set(finding.statement_indexes)
        suggestions = set(finding.suggested_keep_indexes)
        # O modelo externo nao pode criar indices nem sugerir indices fora do grupo.
        if not indexes.issubset(valid_indexes) or not suggestions.issubset(indexes):
            raise InvalidGeminiResponse()

        assessment = finding.assessment
        message = finding.message
        explanation = finding.explanation
        suggested_indexes = finding.suggested_keep_indexes
        if finding.code == "POTENTIAL_REDUNDANCY":
            # Uma diferenca de escopo invalida a comparacao, mesmo se o modelo
            # afirmar que os statements sao redundantes.
            scopes = {_policy_scope(statements_by_index[index]) for index in indexes}
            if None in scopes or len(scopes) != 1:
                assessment = "inconclusive"
                message = "The statements have different or unsupported policy scopes."
                explanation = (
                    "Principal, resource type, location, or where condition differs; "
                    "no simplification is confirmed."
                )
                suggested_indexes = []
        elif finding.code == "CONDITION_REVIEW":
            assessment = "inconclusive"
            suggested_indexes = []
        else:
            suggested_indexes = []
        if assessment == "inconclusive":
            suggested_indexes = []

        findings.append(
            OciPolicyFinding(
                code=finding.code,
                source="gemini",
                assessment=assessment,
                severity=finding.severity,
                statement_indexes=finding.statement_indexes,
                message=message,
                explanation=explanation,
                suggested_keep_indexes=suggested_indexes,
                review_only=True,
            )
        )
    return findings


async def analyze_oci_iam_policy(
    statements: list[str],
    gemini_analyzer: GeminiPolicyAnalyzer,
) -> OciPolicyAnalysisResponse:
    """Combina duplicatas locais com sugestoes Gemini validadas."""
    for index, statement in enumerate(statements):
        _validate_statement(statement, index)

    # O limite e medido em bytes UTF-8 para corresponder ao tamanho transmitido.
    total_bytes = sum(len(statement.encode("utf-8")) for statement in statements)
    if total_bytes > MAX_STATEMENT_BYTES:
        raise PolicyInputError("The combined statement text exceeds 16 KiB.")

    duplicate_findings = _find_exact_duplicates(statements)
    seen: set[str] = set()
    indexed_unique_statements: list[tuple[int, str]] = []
    # Remove duplicatas do prompt, mas conserva o indice original para os findings.
    for index, statement in enumerate(statements):
        normalized = _normalize_statement(statement)
        if normalized in seen:
            continue
        seen.add(normalized)
        indexed_unique_statements.append((index, statement))

    try:
        gemini_analysis = await gemini_analyzer.analyze(indexed_unique_statements)
        gemini_findings = _convert_gemini_findings(
            gemini_analysis,
            {index for index, _ in indexed_unique_statements},
            dict(indexed_unique_statements),
        )
    except InvalidGeminiResponse:
        # Nao descarta duplicatas locais confirmadas por causa de uma resposta ruim.
        return _build_inconclusive_result(
            duplicate_findings,
            "GEMINI_RESPONSE_INVALID_OR_REFERENCES_UNKNOWN_STATEMENTS",
        )

    status = (
        "inconclusive"
        if any(finding.assessment == "inconclusive" for finding in gemini_findings)
        else "completed"
    )
    return OciPolicyAnalysisResponse(
        status=status,
        findings=[*duplicate_findings, *gemini_findings],
        analysis_limitations=BASE_LIMITATIONS.copy(),
    )
