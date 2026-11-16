from email.message import Message

from fastapi import APIRouter, HTTPException, Request
from starlette.requests import ClientDisconnect

from app.schemas.iam_policy import PolicyValidationResult
from app.services.iam_policy_service import validate_iam_policy

router = APIRouter()
MAX_BODY_SIZE = 32 * 1024


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
    lengths = request.headers.getlist("content-length")
    if len(lengths) > 1 or any(
        not length.isascii() or not length.isdecimal() for length in lengths
    ):
        raise HTTPException(status_code=400, detail="Invalid Content-Length.")
    if lengths and (len(lengths[0]) > 10 or int(lengths[0]) > MAX_BODY_SIZE):
        raise HTTPException(status_code=413, detail="Request body exceeds 32 KiB.")

    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > MAX_BODY_SIZE:
                raise HTTPException(
                    status_code=413, detail="Request body exceeds 32 KiB."
                )
            body.extend(chunk)
    except ClientDisconnect as error:
        raise HTTPException(
            status_code=400, detail="Incomplete request body."
        ) from error

    if not body:
        raise HTTPException(status_code=400, detail="Request body is required.")

    content_types = request.headers.getlist("content-type")
    if len(content_types) != 1:
        raise HTTPException(status_code=415, detail="Content-Type must be text/plain.")
    content_type = Message()
    content_type["Content-Type"] = content_types[0]
    parameters = content_type.get_params() or []
    charsets = [value for name, value in parameters[1:] if name.lower() == "charset"]
    if (
        not parameters
        or parameters[0][0].lower() != "text/plain"
        or len(charsets) > 1
        or any(
            not isinstance(value, str) or value.lower() != "utf-8" for value in charsets
        )
        or any(name.lower() != "charset" for name, _ in parameters[1:])
    ):
        raise HTTPException(
            status_code=415, detail="Content-Type must be UTF-8 text/plain."
        )

    content_encoding = request.headers.get("content-encoding", "identity").lower()
    if content_encoding != "identity":
        raise HTTPException(
            status_code=415, detail="Content-Encoding is not supported."
        )

    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HTTPException(
            status_code=400, detail="Request body must be valid UTF-8."
        ) from error

    return validate_iam_policy(text)
