import asyncio
from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from app.core.config import Settings
from app.schemas.oci_iam_policy import GeminiPolicyAnalysis
from app.services import gemini_service
from app.services.gemini_service import (
    GeminiAuthenticationError,
    GeminiConnectionFailed,
    GeminiModelUnavailable,
    GeminiNotConfigured,
    GeminiPolicyAnalyzer,
    GeminiRateLimited,
    GeminiRequestRejected,
    GeminiServiceError,
    GeminiTimeout,
    GeminiTokenLimitExceeded,
)
from app.services.oci_iam_policy_service import InvalidGeminiResponse

# Estes testes usam doubles locais; nenhuma chamada real ao Gemini e feita.


class FakeModels:
    def __init__(
        self, response_text: str = '{"findings": []}', token_count: int = 5
    ) -> None:
        self.response_text = response_text
        self.token_count = token_count
        self.count_arguments: dict = {}
        self.interaction_arguments: dict = {}
        self.interaction_error: Exception | None = None
        self.count_error: Exception | None = None

    async def count_tokens(self, **kwargs):
        self.count_arguments = kwargs
        if self.count_error is not None:
            raise self.count_error
        return SimpleNamespace(total_tokens=self.token_count)

    async def create(self, **kwargs):
        self.interaction_arguments = kwargs
        if self.interaction_error is not None:
            raise self.interaction_error
        return SimpleNamespace(output_text=self.response_text)


class FakeAsyncClient:
    def __init__(self, models: FakeModels) -> None:
        self.models = models
        self.interactions = models

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class FakeClient:
    def __init__(self, models: FakeModels, **kwargs) -> None:
        self.models = models
        self.aio = FakeAsyncClient(models)
        self.arguments = kwargs


def make_analyzer(
    models: FakeModels,
    *,
    api_key: str = "test-key",
    model: str = "gemini-3.5-flash-lite",
    timeout_seconds: float = 20,
) -> tuple[GeminiPolicyAnalyzer, list[FakeClient]]:
    clients: list[FakeClient] = []

    def client_factory(**kwargs):
        client = FakeClient(models, **kwargs)
        clients.append(client)
        return client

    settings = Settings(
        gemini_api_key=SecretStr(api_key),
        gemini_model=model,
    )
    return (
        GeminiPolicyAnalyzer(
            settings,
            client_factory=client_factory,
            timeout_seconds=timeout_seconds,
        ),
        clients,
    )


def test_gemini_uses_configured_model_interactions_and_token_caps() -> None:
    models = FakeModels()
    analyzer, clients = make_analyzer(models, model="gemini-3.5-flash-lite")

    result = asyncio.run(
        analyzer.analyze([(4, "Allow group Devs to inspect instances in tenancy")])
    )

    assert result == GeminiPolicyAnalysis(findings=[])
    assert clients[0].arguments["api_key"] == "test-key"
    assert clients[0].arguments["http_options"].timeout == 20_000
    assert clients[0].arguments["http_options"].retry_options.attempts == 1
    assert models.count_arguments["model"] == "gemini-3.5-flash-lite"
    assert models.interaction_arguments["model"] == "gemini-3.5-flash-lite"
    assert "config" not in models.count_arguments
    assert gemini_service.SYSTEM_INSTRUCTION in models.count_arguments["contents"]
    request = models.interaction_arguments
    assert request["system_instruction"] == gemini_service.SYSTEM_INSTRUCTION
    assert request["response_format"] == {
        "type": "text",
        "mime_type": "application/json",
        "schema": gemini_service.GEMINI_RESPONSE_SCHEMA,
    }
    assert request["generation_config"] == {
        "max_output_tokens": gemini_service.MAX_OUTPUT_TOKENS,
        "thinking_level": "minimal",
    }
    assert request["input"] in models.count_arguments["contents"]


def test_missing_api_key_is_rejected_without_creating_client() -> None:
    analyzer, clients = make_analyzer(FakeModels(), api_key="")

    with pytest.raises(GeminiNotConfigured):
        asyncio.run(
            analyzer.analyze([(0, "Allow group Devs to inspect instances in tenancy")])
        )

    assert clients == []


def test_token_limit_is_checked_before_generation() -> None:
    models = FakeModels(token_count=gemini_service.MAX_INPUT_TOKENS + 1)
    analyzer, _ = make_analyzer(models)

    with pytest.raises(GeminiTokenLimitExceeded):
        asyncio.run(
            analyzer.analyze([(0, "Allow group Devs to inspect instances in tenancy")])
        )

    assert models.interaction_arguments == {}


def test_invalid_gemini_json_is_not_accepted() -> None:
    analyzer, _ = make_analyzer(FakeModels(response_text="not json"))

    with pytest.raises(InvalidGeminiResponse):
        asyncio.run(
            analyzer.analyze([(0, "Allow group Devs to inspect instances in tenancy")])
        )


@pytest.mark.parametrize(
    ("status_code", "error_type"),
    [
        (400, GeminiRequestRejected),
        (401, GeminiAuthenticationError),
        (403, GeminiAuthenticationError),
        (404, GeminiModelUnavailable),
        (429, GeminiRateLimited),
        (503, GeminiServiceError),
    ],
)
def test_gemini_http_errors_are_classified_without_exposing_provider_message(
    monkeypatch,
    caplog,
    status_code: int,
    error_type: type[Exception],
) -> None:
    class FakeAPIError(Exception):
        def __init__(
            self,
            code: int,
            message: str = "private upstream detail",
            status: str = "UPSTREAM_STATUS",
        ) -> None:
            super().__init__(message)
            self.code = code
            self.message = message
            self.status = status

    monkeypatch.setattr(gemini_service.errors, "APIError", FakeAPIError)
    models = FakeModels()
    models.interaction_error = FakeAPIError(status_code)
    analyzer, _ = make_analyzer(models)

    with pytest.raises(error_type) as error:
        asyncio.run(
            analyzer.analyze([(0, "Allow group Devs to inspect instances in tenancy")])
        )

    assert "private upstream detail" not in str(error.value)
    assert error.value.operation == "interactions_create"
    assert error.value.upstream_status == "UPSTREAM_STATUS"
    assert "interactions_create" in caplog.text
    assert f"HTTP status {status_code}" in caplog.text
    assert "private upstream detail" not in caplog.text


def test_schema_error_is_categorized_without_logging_upstream_text(
    monkeypatch,
    caplog,
) -> None:
    class FakeAPIError(Exception):
        code = 400
        status = "INVALID_ARGUMENT"
        message = "response schema contains an unsupported field"

    monkeypatch.setattr(gemini_service.errors, "APIError", FakeAPIError)
    models = FakeModels()
    models.interaction_error = FakeAPIError()
    analyzer, _ = make_analyzer(models)

    with pytest.raises(gemini_service.GeminiSchemaRejected):
        asyncio.run(
            analyzer.analyze([(0, "Allow group Devs to inspect instances in tenancy")])
        )

    assert "category schema" in caplog.text
    assert "INVALID_ARGUMENT" in caplog.text
    assert "unsupported field" not in caplog.text


def test_schema_error_category_can_come_from_error_details(monkeypatch, caplog) -> None:
    class FakeAPIError(Exception):
        code = 400
        status = "INVALID_ARGUMENT"
        message = "Request contains an invalid argument."
        details = {
            "error": {
                "details": [
                    {
                        "fieldViolations": [
                            {
                                "field": "generationConfig.responseJsonSchema",
                                "description": "schema field is not supported",
                            }
                        ]
                    }
                ]
            }
        }

    monkeypatch.setattr(gemini_service.errors, "APIError", FakeAPIError)
    models = FakeModels()
    models.interaction_error = FakeAPIError()
    analyzer, _ = make_analyzer(models)

    with pytest.raises(gemini_service.GeminiSchemaRejected):
        asyncio.run(
            analyzer.analyze([(0, "Allow group Devs to inspect instances in tenancy")])
        )

    assert "category schema" in caplog.text
    assert "fieldViolations" not in caplog.text
    assert "generationConfig.responseJsonSchema" not in caplog.text
    assert "schema field is not supported" not in caplog.text


def test_total_timeout_is_enforced_and_logs_operation(caplog) -> None:
    class SlowModels(FakeModels):
        async def count_tokens(self, **kwargs):
            await asyncio.sleep(0.02)
            return await super().count_tokens(**kwargs)

    analyzer, _ = make_analyzer(SlowModels(), timeout_seconds=0.001)

    with pytest.raises(GeminiTimeout):
        asyncio.run(
            analyzer.analyze([(0, "Allow group Devs to inspect instances in tenancy")])
        )

    assert (
        "model gemini-3.5-flash-lite operation count_tokens exceeded total timeout"
        in caplog.text
    )
    assert "seconds" in caplog.text


def test_unexpected_error_logs_only_exception_type(caplog) -> None:
    models = FakeModels()
    models.interaction_error = RuntimeError("statement-secret-and-api-key")
    analyzer, _ = make_analyzer(models)

    with pytest.raises(GeminiServiceError):
        asyncio.run(
            analyzer.analyze([(0, "Allow group Devs to inspect instances in tenancy")])
        )

    assert "RuntimeError" in caplog.text
    assert "statement-secret-and-api-key" not in caplog.text


def test_value_error_from_sdk_is_a_rejected_request(caplog) -> None:
    models = FakeModels()
    models.count_error = ValueError("private statement text")
    analyzer, _ = make_analyzer(models)

    with pytest.raises(gemini_service.GeminiRequestRejected):
        asyncio.run(
            analyzer.analyze([(0, "Allow group Devs to inspect instances in tenancy")])
        )

    assert "count_tokens" in caplog.text
    assert "ValueError" in caplog.text
    assert "private statement text" not in caplog.text


def test_connection_error_logs_exception_types_only(caplog) -> None:
    class ConnectError(Exception):
        pass

    models = FakeModels()
    models.count_error = ConnectError("private endpoint and policy content")
    analyzer, _ = make_analyzer(models)

    with pytest.raises(GeminiConnectionFailed):
        asyncio.run(
            analyzer.analyze([(0, "Allow group Devs to inspect instances in tenancy")])
        )

    assert "ConnectError" in caplog.text
    assert "private endpoint and policy content" not in caplog.text
