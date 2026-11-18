import json
from typing import NoReturn

from fastapi import APIRouter, HTTPException, Request
from pydantic import ValidationError

from app.routers.request_body import (
    decode_utf8,
    read_limited_body,
    validate_json_headers,
)
from app.schemas.oci_iam_policy import (
    OciPolicyAnalysisRequest,
    OciPolicyAnalysisResponse,
    OciPolicyErrorResponse,
)
from app.services.gemini_service import GeminiServiceError
from app.services.oci_iam_policy_service import (
    PolicyInputError,
    PolicyTextError,
    analyze_oci_iam_policy,
)

router = APIRouter()
MAX_BODY_SIZE = 32 * 1024
REQUEST_ERROR_MESSAGES = {
    "INVALID_CONTENT_LENGTH": "Content-Length is invalid.",
    "PAYLOAD_TOO_LARGE": "The request body exceeds 32 KiB.",
    "INCOMPLETE_BODY": "The request body is incomplete.",
    "EMPTY_BODY": "The request body is required.",
    "INVALID_UTF8": "The request body must be valid UTF-8.",
    "UNSUPPORTED_MEDIA_TYPE": (
        "Content-Type must be application/json with UTF-8 encoding."
    ),
    "UNSUPPORTED_CONTENT_ENCODING": "Content-Encoding is not supported.",
}
MAX_JSON_DEPTH = 20
# Mantem os erros esperados visiveis no contrato OpenAPI.
ERROR_RESPONSES = {
    400: {
        "model": OciPolicyErrorResponse,
        "description": "The request body is empty, invalid JSON, or invalid UTF-8.",
    },
    413: {
        "model": OciPolicyErrorResponse,
        "description": "The request exceeds a byte or Gemini token limit.",
    },
    415: {
        "model": OciPolicyErrorResponse,
        "description": "The content type or content encoding is unsupported.",
    },
    422: {
        "model": OciPolicyErrorResponse,
        "description": "The request does not contain supported OCI policy statements.",
    },
    429: {
        "model": OciPolicyErrorResponse,
        "description": "The Gemini Free Tier quota is currently exceeded.",
    },
    503: {
        "model": OciPolicyErrorResponse,
        "description": (
            "Gemini credentials, model access, or service availability failed."
        ),
    },
    502: {
        "model": OciPolicyErrorResponse,
        "description": "Gemini rejected the request configuration.",
    },
    504: {
        "model": OciPolicyErrorResponse,
        "description": "Gemini analysis exceeded the 20-second timeout.",
    },
}


def _http_error(status_code: int, code: str, message: str) -> HTTPException:
    """Cria erros locais com o mesmo formato JSON publico."""
    return HTTPException(
        status_code=status_code,
        detail={"code": code, "message": message},
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate JSON key.")
    return result


def _reject_json_constant(_value: str) -> NoReturn:
    raise ValueError("Non-standard JSON constant.")


def _validate_json_depth(payload: object) -> None:
    # Conta apenas objetos e listas, sem interpretar delimitadores em strings.
    pending = [(payload, 1)]
    while pending:
        value, depth = pending.pop()
        if isinstance(value, (dict, list)):
            if depth > MAX_JSON_DEPTH:
                raise ValueError("JSON nesting limit exceeded.")
            children = value.values() if isinstance(value, dict) else value
            pending.extend((child, depth + 1) for child in children)


def _request_error(status_code: int, code: str) -> HTTPException:
    return _http_error(status_code, code, REQUEST_ERROR_MESSAGES[code])


def _invalid_statements() -> HTTPException:
    return _http_error(
        422,
        "INVALID_STATEMENTS",
        "The request must contain 1 to 50 valid OCI policy statements "
        "within the configured limits.",
    )


async def _read_request(request: Request) -> OciPolicyAnalysisRequest:
    body = await read_limited_body(request, MAX_BODY_SIZE, _request_error)
    text = decode_utf8(body, _request_error)
    try:
        payload = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        _validate_json_depth(payload)
    except (ValueError, RecursionError) as error:
        raise _http_error(
            400, "INVALID_JSON", "The request body must be valid JSON."
        ) from error
    try:
        return OciPolicyAnalysisRequest.model_validate(payload)
    except ValidationError as error:
        raise _invalid_statements() from error


@router.post(
    "/api/oci/iam-policy-analyze",
    response_model=OciPolicyAnalysisResponse,
    responses=ERROR_RESPONSES,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": OciPolicyAnalysisRequest.model_json_schema()
                }
            },
        }
    },
    tags=["OCI IAM Policy Analyzer"],
    description=(
        "Analyze OCI IAM policy statements using Google Gemini. Statements are sent "
        "to Google for analysis. Do not send confidential policies. Findings from "
        "Gemini are candidates for human review and are never an approved "
        "replacement policy."
    ),
)
async def analyze_oci_iam_policy_request(
    request: Request,
) -> OciPolicyAnalysisResponse:
    """Valida a requisicao e traduz erros internos para a resposta publica."""
    # Nesta rota, tipo de conteudo invalido tem prioridade sobre o tamanho.
    validate_json_headers(request, _request_error)
    policy_request = await _read_request(request)
    analyzer = request.app.state.oci_iam_policy_analyzer
    try:
        return await analyze_oci_iam_policy(policy_request.statements, analyzer)
    except PolicyTextError as error:
        raise _invalid_statements() from error
    except PolicyInputError as error:
        raise _http_error(422, "INVALID_STATEMENTS", str(error)) from error
    except GeminiServiceError as error:
        # A resposta usa mensagens publicas e metadados controlados.
        detail = {
            "code": error.code,
            "message": error.public_message,
        }
        if error.operation is not None:
            detail["operation"] = error.operation
        if error.upstream_status is not None:
            detail["upstream_status"] = error.upstream_status
        raise HTTPException(error.status_code, detail=detail) from error
