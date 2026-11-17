from email.message import Message

from fastapi import APIRouter, HTTPException, Request
from starlette.requests import ClientDisconnect

from app.schemas.terraform_plan import (
    TerraformPlanErrorResponse,
    TerraformPlanResult,
)
from app.services.terraform_plan_service import (
    MAX_RESOURCES,
    TerraformPlanError,
    analyze_terraform_plan,
)

router = APIRouter()
MAX_BODY_SIZE = 1024 * 1024
ERROR_RESPONSES = {
    400: {
        "model": TerraformPlanErrorResponse,
        "description": "The request body is empty, invalid JSON, or invalid UTF-8.",
    },
    413: {
        "model": TerraformPlanErrorResponse,
        "description": "The request body exceeds 1 MiB.",
    },
    415: {
        "model": TerraformPlanErrorResponse,
        "description": "The content type or content encoding is unsupported.",
    },
    422: {
        "model": TerraformPlanErrorResponse,
        "description": "The document is not a supported plan for this provider route.",
    },
    429: {
        "model": TerraformPlanErrorResponse,
        "description": "The reverse proxy rate limit was exceeded.",
    },
}


def _http_error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"code": code, "message": message},
    )


def _validate_content_type(request: Request) -> None:
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


async def _read_plan_body(request: Request) -> str:
    lengths = request.headers.getlist("content-length")
    if len(lengths) > 1 or any(
        not length.isascii() or not length.isdecimal() for length in lengths
    ):
        raise _http_error(400, "INVALID_CONTENT_LENGTH", "Content-Length is invalid.")
    if lengths and (len(lengths[0]) > 10 or int(lengths[0]) > MAX_BODY_SIZE):
        raise _http_error(
            413,
            "PAYLOAD_TOO_LARGE",
            "The request body exceeds 1 MiB.",
        )

    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > MAX_BODY_SIZE:
                raise _http_error(
                    413,
                    "PAYLOAD_TOO_LARGE",
                    "The request body exceeds 1 MiB.",
                )
            body.extend(chunk)
    except ClientDisconnect as error:
        raise _http_error(
            400, "INCOMPLETE_BODY", "The request body is incomplete."
        ) from error

    if not body:
        raise _http_error(400, "EMPTY_BODY", "The request body is required.")
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise _http_error(
            400, "INVALID_UTF8", "The request body must be valid UTF-8."
        ) from error


async def _analyze_request(request: Request, provider: str) -> TerraformPlanResult:
    _validate_content_type(request)
    text = await _read_plan_body(request)
    try:
        return analyze_terraform_plan(text, provider)
    except TerraformPlanError as error:
        raise _http_error(error.status_code, error.code, error.message) from error


@router.post(
    "/api/aws/terraform-plan-analyze",
    response_model=TerraformPlanResult,
    response_model_exclude_none=True,
    responses=ERROR_RESPONSES,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": {"type": "object"}}},
        }
    },
    tags=["Terraform Plan Inspector"],
    description=(
        f"Analyze one AWS Terraform plan. The body is limited to 1 MiB, depth to 40, "
        f"and resource changes to {MAX_RESOURCES}. Findings are limited to 100. "
        "This is a best-effort inspection, not Terraform validation or a security "
        "approval."
    ),
)
async def analyze_aws_terraform_plan(request: Request) -> TerraformPlanResult:
    return await _analyze_request(request, "aws")


@router.post(
    "/api/oci/terraform-plan-analyze",
    response_model=TerraformPlanResult,
    response_model_exclude_none=True,
    responses=ERROR_RESPONSES,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": {"type": "object"}}},
        }
    },
    tags=["Terraform Plan Inspector"],
    description=(
        f"Analyze one OCI Terraform plan. The body is limited to 1 MiB, depth to 40, "
        f"and resource changes to {MAX_RESOURCES}. Findings are limited to 100. "
        "This is a best-effort inspection, not Terraform validation or a security "
        "approval."
    ),
)
async def analyze_oci_terraform_plan(request: Request) -> TerraformPlanResult:
    return await _analyze_request(request, "oci")
