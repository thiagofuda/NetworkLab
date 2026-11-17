import json
from email.message import Message
from typing import NoReturn

from fastapi import APIRouter, HTTPException, Request
from pydantic import ValidationError
from starlette.requests import ClientDisconnect

from app.schemas.oci_iam_policy import (
    OciPolicyAnalysisRequest,
    OciPolicyAnalysisResponse,
    OciPolicyErrorResponse,
)
from app.services.gemini_service import GeminiServiceError
from app.services.oci_iam_policy_service import (
    PolicyInputError,
    analyze_oci_iam_policy,
)

router = APIRouter()
MAX_BODY_SIZE = 32 * 1024
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


def _validate_headers(request: Request) -> None:
    """Aceita somente JSON UTF-8 sem compressao ou cabecalhos duplicados."""
    content_types = request.headers.getlist("content-type")
    if len(content_types) != 1:
        raise _http_error(
            415,
            "UNSUPPORTED_MEDIA_TYPE",
            "Content-Type must be application/json with UTF-8 encoding.",
        )

    content_type = Message()
    content_type["Content-Type"] = content_types[0]
    parameters = content_type.get_params() or []
    # O parser de email interpreta parametros Content-Type sem dividir valores a mao.
    charsets = [value for name, value in parameters[1:] if name.lower() == "charset"]
    if (
        not parameters
        or parameters[0][0].lower() != "application/json"
        or len(charsets) > 1
        or any(
            not isinstance(value, str) or value.lower() != "utf-8" for value in charsets
        )
        or any(name.lower() != "charset" for name, _ in parameters[1:])
    ):
        raise _http_error(
            415,
            "UNSUPPORTED_MEDIA_TYPE",
            "Content-Type must be application/json with UTF-8 encoding.",
        )

    encodings = request.headers.getlist("content-encoding")
    if len(encodings) > 1 or (encodings and encodings[0].lower() != "identity"):
        raise _http_error(
            415,
            "UNSUPPORTED_CONTENT_ENCODING",
            "Content-Encoding is not supported.",
        )


async def _read_request(request: Request) -> OciPolicyAnalysisRequest:
    """Le o corpo em partes para impor o limite antes de decodificar o JSON."""
    lengths = request.headers.getlist("content-length")
    if len(lengths) > 1 or any(
        not length.isascii() or not length.isdecimal() for length in lengths
    ):
        raise _http_error(400, "INVALID_CONTENT_LENGTH", "Content-Length is invalid.")
    if lengths and (len(lengths[0]) > 10 or int(lengths[0]) > MAX_BODY_SIZE):
        raise _http_error(
            413,
            "PAYLOAD_TOO_LARGE",
            "The request body exceeds 32 KiB.",
        )

    body = bytearray()
    try:
        # Content-Length pode faltar; por isso o limite tambem e conferido por chunk.
        async for chunk in request.stream():
            if len(body) + len(chunk) > MAX_BODY_SIZE:
                raise _http_error(
                    413,
                    "PAYLOAD_TOO_LARGE",
                    "The request body exceeds 32 KiB.",
                )
            body.extend(chunk)
    except ClientDisconnect as error:
        raise _http_error(
            400, "INCOMPLETE_BODY", "The request body is incomplete."
        ) from error

    if not body:
        raise _http_error(400, "EMPTY_BODY", "The request body is required.")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise _http_error(
            400, "INVALID_UTF8", "The request body must be valid UTF-8."
        ) from error
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
        raise _http_error(
            422,
            "INVALID_STATEMENTS",
            "The request must contain 1 to 50 valid OCI policy statements "
            "within the configured limits.",
        ) from error


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
    _validate_headers(request)
    policy_request = await _read_request(request)
    analyzer = request.app.state.oci_iam_policy_analyzer
    try:
        return await analyze_oci_iam_policy(policy_request.statements, analyzer)
    except PolicyInputError as error:
        raise _http_error(422, "INVALID_STATEMENTS", str(error)) from error
    except GeminiServiceError as error:
        # A resposta usa mensagens públicas e metadados controlados.
        detail = {
            "code": error.code,
            "message": error.public_message,
        }
        if error.operation is not None:
            detail["operation"] = error.operation
        if error.upstream_status is not None:
            detail["upstream_status"] = error.upstream_status
        raise HTTPException(error.status_code, detail=detail) from error
