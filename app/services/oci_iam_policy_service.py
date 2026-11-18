import re
from collections import defaultdict
from typing import Protocol

from app.schemas.oci_iam_policy import (
    GeminiPolicyAnalysis,
    OciPolicyAnalysisResponse,
    OciPolicyFinding,
)

# O reconhecimento do formato Allow serve apenas para comparar escopos.
MAX_STATEMENT_BYTES = 16 * 1024
POLICY_STATEMENT_PATTERN = re.compile(
    r"^Allow\s+(?P<subject>.+?)\s+to\s+"
    r"(?P<verb>inspect|read|use|manage)\s+"
    r"(?P<resource_type>.+?)\s+in\s+(?P<scope>.+)$",
    re.IGNORECASE,
)
PATTERN_WITH_WHITESPACE = re.compile(r"/[^/]*\s+[^/]*/")
BALANCED_QUOTES = re.compile(r"(?:[^']|'(?:[^'\\]|\\.)*')*")
PolicyScope = tuple[str, str, str, str | None]
BASE_LIMITATIONS = [
    "TENANCY_NOT_QUERIED",
    "RESOURCE_FAMILY_EQUIVALENCE_NOT_EVALUATED",
]


class PolicyInputError(ValueError):
    """Indica que a entrada nao pertence ao subconjunto aceito pelo servico."""


class PolicyTextError(PolicyInputError):
    """Indica falha no tamanho ou na codificacao do texto."""


class InvalidGeminiResponse(ValueError):
    """Indica que a resposta Gemini nao pode ser usada com seguranca."""


class GeminiPolicyAnalyzer(Protocol):
    """Contrato minimo da chamada externa, facil de substituir nos testes."""

    async def analyze(
        self,
        indexed_statements: list[tuple[int, str]],
    ) -> GeminiPolicyAnalysis: ...


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


def _policy_scope(statement: str) -> PolicyScope | None:
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


def _find_exact_duplicates(
    indexes_by_statement: dict[str, list[int]],
) -> list[OciPolicyFinding]:
    """Confirma duplicatas de texto e usa a primeira ocorrencia como referencia."""
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
    scopes_by_index: dict[int, PolicyScope | None],
) -> list[OciPolicyFinding]:
    """Valida referencias do Gemini e limita sugestoes a revisao humana."""
    findings: list[OciPolicyFinding] = []
    for finding in analysis.findings:
        indexes = set(finding.statement_indexes)
        # Aceita apenas os indices originais que foram enviados ao modelo.
        if not indexes.issubset(scopes_by_index) or not set(
            finding.suggested_keep_indexes
        ).issubset(indexes):
            raise InvalidGeminiResponse()

        assessment = finding.assessment
        message = finding.message
        explanation = finding.explanation
        if finding.code == "POTENTIAL_REDUNDANCY":
            # Condicoes diferentes podem liberar acesso em casos distintos.
            # Por isso a sugestao so passa quando os escopos coincidem.
            scopes = {scopes_by_index[index] for index in indexes}
            if None in scopes or len(scopes) != 1:
                assessment = "inconclusive"
                message = "The statements have different or unsupported policy scopes."
                explanation = (
                    "Principal, resource type, location, or where condition differs; "
                    "no simplification is confirmed."
                )
        elif finding.code == "CONDITION_REVIEW":
            assessment = "inconclusive"

        suggested_indexes = (
            finding.suggested_keep_indexes
            if finding.code == "POTENTIAL_REDUNDANCY" and assessment == "candidate"
            else []
        )

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
    # O schema limita caracteres por item. Aqui contamos bytes UTF-8 do conjunto,
    # pois um caractere pode ocupar mais de um byte.
    try:
        total_bytes = sum(len(statement.encode("utf-8")) for statement in statements)
    except UnicodeEncodeError as error:
        raise PolicyTextError("Statements must be valid UTF-8.") from error
    if total_bytes > MAX_STATEMENT_BYTES:
        raise PolicyTextError("The combined statement text exceeds 16 KiB.")

    indexes_by_statement: dict[str, list[int]] = defaultdict(list)
    indexed_unique_statements: list[tuple[int, str]] = []
    scopes_by_index: dict[int, PolicyScope | None] = {}
    for index, statement in enumerate(statements):
        scope = _policy_scope(statement)
        if scope is None:
            raise PolicyInputError(
                f"Statement at index {index} is not a supported OCI Allow statement."
            )
        indexes = indexes_by_statement[_normalize_statement(statement)]
        if not indexes:
            # Mantem o indice original para ligar cada finding a entrada.
            indexed_unique_statements.append((index, statement))
            # Aspas abertas deixam os limites do escopo incertos.
            scopes_by_index[index] = (
                scope if BALANCED_QUOTES.fullmatch(statement) else None
            )
        indexes.append(index)

    duplicate_findings = _find_exact_duplicates(indexes_by_statement)
    try:
        gemini_analysis = await gemini_analyzer.analyze(indexed_unique_statements)
        gemini_findings = _convert_gemini_findings(gemini_analysis, scopes_by_index)
    except InvalidGeminiResponse:
        # Nao descarta duplicatas locais confirmadas por causa de uma resposta ruim.
        return _build_inconclusive_result(
            duplicate_findings,
            "GEMINI_RESPONSE_INVALID_OR_REFERENCES_UNKNOWN_STATEMENTS",
        )

    status = (
        "inconclusive"
        if None in scopes_by_index.values()
        or any(finding.assessment == "inconclusive" for finding in gemini_findings)
        else "completed"
    )
    return OciPolicyAnalysisResponse(
        status=status,
        findings=[*duplicate_findings, *gemini_findings],
        analysis_limitations=BASE_LIMITATIONS.copy(),
    )
