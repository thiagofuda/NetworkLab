from fastapi import APIRouter, HTTPException, Request

from app.routers.request_body import decode_utf8, is_utf8_media_type, read_limited_body
from app.schemas.iam_policy import PolicyValidationResult
from app.services.iam_policy_service import validate_iam_policy

router = APIRouter()
MAX_BODY_SIZE = 32 * 1024
REQUEST_ERROR_MESSAGES = {
    "INVALID_CONTENT_LENGTH": "Invalid Content-Length.",
    "PAYLOAD_TOO_LARGE": "Request body exceeds 32 KiB.",
    "INCOMPLETE_BODY": "Incomplete request body.",
    "EMPTY_BODY": "Request body is required.",
    "INVALID_UTF8": "Request body must be valid UTF-8.",
}


def _request_error(status_code: int, code: str) -> HTTPException:
    return HTTPException(status_code, detail=REQUEST_ERROR_MESSAGES[code])


@router.post(
    "/api/aws/iam-validate",
    response_model=PolicyValidationResult,
    response_model_exclude_none=True,
    responses={
        400: {"description": "Empty body, invalid request, or invalid UTF-8."},
        413: {"description": "The request body exceeds 32 KiB."},
        415: {"description": "Unsupported content type or encoding."},
        429: {"description": "Rate limit exceeded by the reverse proxy."},
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"text/plain": {"schema": {"type": "string"}}},
        }
    },
    description=(
        "Check IAM identity-policy JSON syntax and selected structural rules. "
        "A valid result does not guarantee AWS acceptance or safe permissions."
    ),
)
async def validate_policy_request(request: Request) -> PolicyValidationResult:
    # Esta rota verifica o corpo antes do tipo de conteudo. Isso preserva
    # o erro 413 quando o corpo e grande e o tipo tambem e invalido.
    body = await read_limited_body(request, MAX_BODY_SIZE, _request_error)

    content_types = request.headers.getlist("content-type")
    if len(content_types) != 1:
        raise HTTPException(status_code=415, detail="Content-Type must be text/plain.")
    if not is_utf8_media_type(content_types[0], "text/plain"):
        raise HTTPException(
            status_code=415, detail="Content-Type must be UTF-8 text/plain."
        )

    content_encoding = request.headers.get("content-encoding", "identity").lower()
    if content_encoding != "identity":
        raise HTTPException(
            status_code=415, detail="Content-Encoding is not supported."
        )

    return validate_iam_policy(decode_utf8(body, _request_error))
