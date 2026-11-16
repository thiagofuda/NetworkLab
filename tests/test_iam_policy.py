import asyncio
import json

import pytest
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient

from app.main import app
from app.routers.iam_policy import MAX_BODY_SIZE, validate_policy_request

client = TestClient(app)
ENDPOINT = "/api/aws/iam-validate"
VALID_POLICY = (
    '{"Version":"2012-10-17","Statement":{"Effect":"Allow",'
    '"Action":"s3:GetObject","Resource":"*"}}'
)


def test_valid_policy_returns_json() -> None:
    response = client.post(
        ENDPOINT, content=VALID_POLICY, headers={"Content-Type": "text/plain"}
    )
    assert response.status_code == 200
    assert response.json() == {
        "valid": True,
        "errors": [],
        "warnings": [],
        "truncated": False,
    }


def test_invalid_resource_entry_returns_indexed_path() -> None:
    statement = {
        "Effect": "Allow",
        "Action": "sqs:SendMessage",
        "Resource": "arn:aws:sqs:eu-west-1:111122223333:orders",
    }
    statements = [statement.copy() for _ in range(5)]
    statements.append(
        {
            **statement,
            "Resource": ["arn:aws:sqs:eu-west-1:111122223333:orders", 12345],
        }
    )

    response = client.post(
        ENDPOINT,
        content=json.dumps({"Statement": statements}),
        headers={"Content-Type": "text/plain"},
    )

    assert response.status_code == 200
    issue = next(
        error for error in response.json()["errors"] if error["field"] == "Resource"
    )
    assert issue["code"] == "INVALID_FIELD_TYPE"
    assert issue["message"] == "Resource entries must be non-empty strings."
    assert issue["path"] == "Statement[5].Resource[1]"


@pytest.mark.parametrize(
    "body", ['{"Statement":', '{"Statement": {"Effect": "Allow"}}', "  "]
)
def test_invalid_policy_is_a_completed_analysis(body: str) -> None:
    response = client.post(
        ENDPOINT, content=body, headers={"Content-Type": "text/plain; charset=UTF-8"}
    )
    assert response.status_code == 200
    assert response.json()["valid"] is False
    assert response.json()["errors"]


def test_absent_body_and_invalid_utf8() -> None:
    headers = {"Content-Type": "text/plain"}
    assert client.post(ENDPOINT, content=b"", headers=headers).status_code == 400
    assert client.post(ENDPOINT).status_code == 400
    response = client.post(ENDPOINT, content=b"\xff", headers=headers)
    assert response.status_code == 400
    assert response.headers["content-type"].startswith("application/json")


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Content-Type": "not-a-media-type"},
        {"Content-Type": "application/json"},
        {"Content-Type": "text/plain; charset=latin-1"},
        {"Content-Type": "text/plain", "Content-Encoding": "gzip"},
    ],
)
def test_unsupported_content_type_or_encoding(headers: dict[str, str]) -> None:
    response = client.post(ENDPOINT, content=VALID_POLICY, headers=headers)
    assert response.status_code == 415
    assert response.headers["content-type"].startswith("application/json")


def test_body_limit_uses_bytes() -> None:
    headers = {"Content-Type": "text/plain"}
    assert (
        client.post(ENDPOINT, content=b" " * MAX_BODY_SIZE, headers=headers).status_code
        == 200
    )
    response = client.post(
        ENDPOINT, content=b" " * (MAX_BODY_SIZE + 1), headers=headers
    )
    assert response.status_code == 413
    assert response.headers["content-type"].startswith("application/json")


def test_streaming_limit_does_not_depend_on_content_length() -> None:
    chunks = [b" " * MAX_BODY_SIZE, b"x", b"should not be read"]
    received = 0

    async def receive() -> dict:
        nonlocal received
        chunk = chunks[received]
        received += 1
        return {"type": "http.request", "body": chunk, "more_body": True}

    request = Request(
        {"type": "http", "headers": [(b"content-type", b"text/plain")]}, receive
    )
    with pytest.raises(HTTPException) as error:
        asyncio.run(validate_policy_request(request))
    assert error.value.status_code == 413
    assert received == 2


def test_openapi_documents_plain_text_and_error_statuses() -> None:
    operation = client.get("/openapi.json").json()["paths"][ENDPOINT]["post"]
    assert list(operation["requestBody"]["content"]) == ["text/plain"]
    assert all(
        code in operation["responses"] for code in ("200", "400", "413", "415", "429")
    )
    assert "does not guarantee" in operation["description"]


def test_input_is_not_reflected_in_errors() -> None:
    secret = "private-policy-content"
    response = client.post(
        ENDPOINT,
        content=json.dumps(
            {"Statement": {"Effect": secret, "Action": "*", "Resource": "*"}}
        ),
        headers={"Content-Type": "text/plain"},
    )
    assert secret not in response.text
    assert response.json()["valid"] is False
