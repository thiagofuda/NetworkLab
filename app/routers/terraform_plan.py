from fastapi import APIRouter, HTTPException, Request

from app.routers.request_body import (
    decode_utf8,
    read_limited_body,
    validate_json_headers,
)
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
REQUEST_ERROR_MESSAGES = {
    "INVALID_CONTENT_LENGTH": "Content-Length is invalid.",
    "PAYLOAD_TOO_LARGE": "The request body exceeds 1 MiB.",
    "INCOMPLETE_BODY": "The request body is incomplete.",
    "EMPTY_BODY": "The request body is required.",
    "INVALID_UTF8": "The request body must be valid UTF-8.",
    "UNSUPPORTED_MEDIA_TYPE": (
        "Content-Type must be application/json with UTF-8 encoding."
    ),
    "UNSUPPORTED_CONTENT_ENCODING": "Content-Encoding is not supported.",
}
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


def _request_error(status_code: int, code: str) -> HTTPException:
    return _http_error(status_code, code, REQUEST_ERROR_MESSAGES[code])


async def _read_plan_body(request: Request) -> str:
    body = await read_limited_body(request, MAX_BODY_SIZE, _request_error)
    return decode_utf8(body, _request_error)


async def _analyze_request(request: Request, provider: str) -> TerraformPlanResult:
    # Nesta rota, tipo de conteudo invalido tem prioridade sobre o tamanho.
    validate_json_headers(request, _request_error)
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
