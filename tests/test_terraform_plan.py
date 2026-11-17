import asyncio
import json

import pytest
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient

from app.main import app
from app.routers.terraform_plan import MAX_BODY_SIZE, _read_plan_body

client = TestClient(app)
AWS_ENDPOINT = "/api/aws/terraform-plan-analyze"
OCI_ENDPOINT = "/api/oci/terraform-plan-analyze"
HEADERS = {"Content-Type": "application/json"}


def resource_change(
    address: str,
    resource_type: str,
    actions: list[str],
    *,
    provider_name: str,
    mode: str = "managed",
) -> dict:
    return {
        "address": address,
        "type": resource_type,
        "mode": mode,
        "provider_name": provider_name,
        "change": {"actions": actions},
    }


def plan(provider: str, changes: list[dict] | None = None) -> dict:
    provider_path = "hashicorp/aws" if provider == "aws" else "oracle/oci"
    return {
        "format_version": "1.0",
        "resource_changes": changes or [],
        "configuration": {
            "provider_config": {
                "main": {
                    "full_name": f"registry.terraform.io/{provider_path}",
                    "name": provider,
                }
            },
            "root_module": {"resources": []},
        },
    }


def post_plan(endpoint: str, document: dict):
    return client.post(endpoint, content=json.dumps(document), headers=HEADERS)


def test_aws_plan_is_analyzed_by_aws_route() -> None:
    document = plan(
        "aws",
        [
            resource_change(
                "aws_instance.example",
                "aws_instance",
                ["create"],
                provider_name="registry.terraform.io/hashicorp/aws",
            )
        ],
    )

    response = post_plan(AWS_ENDPOINT, document)

    assert response.status_code == 200
    assert response.json()["provider"] == "aws"
    assert response.json()["summary"]["create"] == 1


def test_oci_plan_is_analyzed_by_oci_route() -> None:
    document = plan(
        "oci",
        [
            resource_change(
                "oci_core_vcn.example",
                "oci_core_vcn",
                ["create"],
                provider_name="registry.terraform.io/oracle/oci",
            )
        ],
    )

    response = post_plan(OCI_ENDPOINT, document)

    assert response.status_code == 200
    assert response.json()["provider"] == "oci"
    assert response.json()["summary"]["create"] == 1


def test_aws_and_oci_plans_are_rejected_on_the_other_route() -> None:
    aws_plan = plan("aws")
    oci_plan = plan("oci")

    aws_on_oci = post_plan(OCI_ENDPOINT, aws_plan)
    oci_on_aws = post_plan(AWS_ENDPOINT, oci_plan)

    assert aws_on_oci.status_code == 422
    assert aws_on_oci.json()["detail"]["code"] == "PROVIDER_MISMATCH"
    assert oci_on_aws.status_code == 422
    assert oci_on_aws.json()["detail"]["code"] == "PROVIDER_MISMATCH"


def test_mixed_aws_and_oci_plan_is_explicitly_rejected() -> None:
    document = plan(
        "aws",
        [
            resource_change(
                "aws_instance.example",
                "aws_instance",
                ["no-op"],
                provider_name="registry.terraform.io/hashicorp/aws",
            ),
            resource_change(
                "oci_core_vcn.example",
                "oci_core_vcn",
                ["no-op"],
                provider_name="registry.terraform.io/oracle/oci",
            ),
        ],
    )

    for endpoint in (AWS_ENDPOINT, OCI_ENDPOINT):
        response = post_plan(endpoint, document)
        assert response.status_code == 422
        assert response.json()["detail"]["code"] == "MIXED_CLOUD_PROVIDERS"


def test_auxiliary_provider_is_allowed_with_aws_resources() -> None:
    document = plan(
        "aws",
        [
            resource_change(
                "aws_instance.example",
                "aws_instance",
                ["no-op"],
                provider_name="registry.terraform.io/hashicorp/aws",
            ),
            resource_change(
                "random_id.example",
                "random_id",
                ["update"],
                provider_name="registry.terraform.io/hashicorp/random",
            ),
        ],
    )

    response = post_plan(AWS_ENDPOINT, document)

    assert response.status_code == 200
    assert response.json()["summary"]["update"] == 1


def test_empty_plan_and_data_only_plan_are_not_rejected() -> None:
    empty_response = post_plan(AWS_ENDPOINT, plan("aws"))
    data_only_response = post_plan(
        AWS_ENDPOINT,
        plan(
            "aws",
            [
                resource_change(
                    "data.aws_ami.latest",
                    "aws_ami",
                    ["read"],
                    provider_name="registry.terraform.io/hashicorp/aws",
                    mode="data",
                )
            ],
        ),
    )

    assert empty_response.status_code == 200
    assert empty_response.json()["summary"]["create"] == 0
    assert data_only_response.status_code == 200
    assert data_only_response.json()["summary"]["read"] == 1


def test_oci_resources_get_generic_findings_only() -> None:
    document = plan(
        "oci",
        [
            resource_change(
                "oci_core_instance.create",
                "oci_core_instance",
                ["create"],
                provider_name="registry.terraform.io/oracle/oci",
            ),
            resource_change(
                "oci_core_instance.delete",
                "oci_core_instance",
                ["delete"],
                provider_name="registry.terraform.io/oracle/oci",
            ),
            resource_change(
                "oci_core_instance.replace",
                "oci_core_instance",
                ["create", "delete"],
                provider_name="registry.terraform.io/oracle/oci",
            ),
            resource_change(
                "aws_db_instance.auxiliary",
                "aws_db_instance",
                ["delete"],
                provider_name="registry.terraform.io/hashicorp/random",
            ),
        ],
    )

    response = post_plan(OCI_ENDPOINT, document)

    assert response.status_code == 200
    assert [finding["code"] for finding in response.json()["findings"]] == [
        "RESOURCE_DELETION",
        "RESOURCE_REPLACEMENT",
        "RESOURCE_DELETION",
    ]
    assert not any(
        finding["code"] in {"RDS_DELETION", "PUBLIC_SSH_ACCESS"}
        for finding in response.json()["findings"]
    )


def test_body_errors_are_structured_and_do_not_reflect_payload() -> None:
    invalid_json = client.post(
        AWS_ENDPOINT,
        content='{"token":"private-plan-secret"',
        headers=HEADERS,
    )
    not_a_plan = post_plan(AWS_ENDPOINT, {"format_version": "1.0"})
    incompatible = post_plan(
        AWS_ENDPOINT,
        {"format_version": "2.0", "resource_changes": []},
    )

    assert invalid_json.status_code == 400
    assert invalid_json.json()["detail"]["code"] == "INVALID_JSON"
    assert "private-plan-secret" not in invalid_json.text
    assert not_a_plan.status_code == 422
    assert not_a_plan.json()["detail"]["code"] == "NOT_TERRAFORM_PLAN"
    assert incompatible.status_code == 422
    assert incompatible.json()["detail"]["code"] == "UNSUPPORTED_FORMAT_VERSION"


def test_body_limit_and_content_type() -> None:
    too_large = client.post(
        AWS_ENDPOINT,
        content=b" " * (MAX_BODY_SIZE + 1),
        headers=HEADERS,
    )
    unsupported = client.post(AWS_ENDPOINT, content="{}")

    assert too_large.status_code == 413
    assert too_large.json()["detail"]["code"] == "PAYLOAD_TOO_LARGE"
    assert unsupported.status_code == 415
    assert unsupported.json()["detail"]["code"] == "UNSUPPORTED_MEDIA_TYPE"


def test_streaming_body_limit_without_content_length() -> None:
    chunks = [b" " * 800_000, b" " * 300_000, b"must not be read"]
    received = 0

    async def receive() -> dict:
        nonlocal received
        chunk = chunks[received]
        received += 1
        return {"type": "http.request", "body": chunk, "more_body": True}

    request = Request(
        {"type": "http", "headers": [(b"content-type", b"application/json")]},
        receive,
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(_read_plan_body(request))

    assert error.value.status_code == 413
    assert received == 2


def test_sensitive_values_and_before_after_are_not_returned() -> None:
    document = plan(
        "aws",
        [
            {
                **resource_change(
                    "aws_instance.example",
                    "aws_instance",
                    ["update"],
                    provider_name="registry.terraform.io/hashicorp/aws",
                ),
                "change": {
                    "actions": ["update"],
                    "before": {"password": "hidden-plan-password"},
                    "after": {"password": "hidden-plan-password"},
                    "after_sensitive": {"password": True},
                    "before_sensitive": {"password": True},
                },
            }
        ],
    )

    response = post_plan(AWS_ENDPOINT, document)

    assert response.status_code == 200
    assert "hidden-plan-password" not in response.text
    assert "before" not in response.json()["resources"][0]
    assert "after" not in response.json()["resources"][0]


def test_openapi_documents_both_json_endpoints_and_errors() -> None:
    schema = client.get("/openapi.json").json()
    for endpoint in (AWS_ENDPOINT, OCI_ENDPOINT):
        operation = schema["paths"][endpoint]["post"]
        assert list(operation["requestBody"]["content"]) == ["application/json"]
        assert all(
            code in operation["responses"]
            for code in ("200", "400", "413", "415", "422", "429")
        )
