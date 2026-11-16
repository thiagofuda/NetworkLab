import json

import pytest

from app.schemas.iam_policy import PolicyValidationResult
from app.services.iam_policy_service import (
    MAX_ISSUES,
    MAX_JSON_DEPTH,
    MAX_STATEMENTS,
    _add_issue,
    parse_policy,
    validate_iam_policy,
)


def test_parse_valid_policy_as_object() -> None:
    policy, error = parse_policy('{"Statement": {"Effect": "Allow"}}')

    assert policy == {"Statement": {"Effect": "Allow"}}
    assert error is None


@pytest.mark.parametrize("text", ["", "  \n "])
def test_parse_empty_document(text: str) -> None:
    policy, error = parse_policy(text)

    assert policy is None
    assert error is not None
    assert error.code == "EMPTY_DOCUMENT"


@pytest.mark.parametrize("text", ['{"a": 1 "b": 2}', '{"a": value}', '{"a": NaN}'])
def test_parse_invalid_json(text: str) -> None:
    policy, error = parse_policy(text)

    assert policy is None
    assert error is not None
    assert error.code == "INVALID_JSON"


def test_invalid_json_reports_line_and_column_without_input() -> None:
    policy, error = parse_policy('{\n  "secret": 1\n  "other": 2\n}')

    assert policy is None
    assert error is not None
    assert (error.line, error.column) == (3, 3)
    assert "secret" not in error.message


@pytest.mark.parametrize("text", ['{"a": 1, "a": 2}', '{"a": {"x": 1, "x": 2}}'])
def test_duplicate_keys_are_rejected(text: str) -> None:
    policy, error = parse_policy(text)

    assert policy is None
    assert error is not None
    assert error.code == "DUPLICATE_KEY"


@pytest.mark.parametrize("text", ["[]", '"text"', "null", "123"])
def test_policy_root_must_be_object(text: str) -> None:
    policy, error = parse_policy(text)

    assert policy is None
    assert error is not None
    assert error.code == "INVALID_ROOT"


def test_parse_rejects_excessive_depth() -> None:
    text = '{"a":' * MAX_JSON_DEPTH + "0" + "}" * MAX_JSON_DEPTH
    policy, error = parse_policy('{"root":' + text + "}")

    assert policy is None
    assert error is not None
    assert error.code == "MAX_DEPTH_EXCEEDED"


def test_brackets_inside_strings_do_not_count_as_depth() -> None:
    policy, error = parse_policy('{"text": "[[[[[[[[[[[[[[[[[[[[["}')

    assert policy is not None
    assert error is None


def test_valid_dynamodb_policy() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["dynamodb:GetItem", "dynamodb:Query"],
                "Resource": [
                    "arn:aws:dynamodb:eu-west-1:111122223333:table/Orders",
                    "arn:aws:dynamodb:eu-west-1:111122223333:table/Orders/index/*",
                ],
            }
        ],
    }
    result = validate_iam_policy(json.dumps(policy))

    assert result.valid
    assert result.errors == []
    assert result.warnings == []


@pytest.mark.parametrize(
    ("field", "values"),
    [
        ("Action", ["sqs:SendMessage", 12345]),
        ("NotAction", ["sqs:SendMessage", 12345]),
        ("Resource", ["arn:aws:sqs:eu-west-1:111122223333:orders", 12345]),
        ("NotResource", ["arn:aws:sqs:eu-west-1:111122223333:orders", 12345]),
    ],
)
def test_invalid_choice_entry_reports_exact_index(
    field: str, values: list[str | int]
) -> None:
    valid_statement = {
        "Effect": "Allow",
        "Action": "sqs:SendMessage",
        "Resource": "arn:aws:sqs:eu-west-1:111122223333:orders",
    }
    statements = [valid_statement.copy() for _ in range(5)]
    statements.append({**valid_statement, field: values})

    result = validate_iam_policy(json.dumps({"Statement": statements}))

    issue = next(error for error in result.errors if error.field == field)
    assert issue.code == "INVALID_FIELD_TYPE"
    assert issue.message == f"{field} entries must be non-empty strings."
    assert issue.path == f"Statement[5].{field}[1]"


@pytest.mark.parametrize("version", ["2008-10-17", "2012-10-17", None])
def test_single_statement_and_optional_version(version: str | None) -> None:
    policy = {
        "Statement": {"Effect": "Allow", "NotAction": "iam:*", "NotResource": "*"}
    }
    if version is not None:
        policy["Version"] = version
    result = validate_iam_policy(json.dumps(policy))

    assert result.valid
    assert result.errors == []
    assert len(result.warnings) == (1 if version is None else 0)


@pytest.mark.parametrize(
    ("policy", "expected_code"),
    [
        ({}, "MISSING_STATEMENT"),
        ({"Statements": []}, "MISSING_STATEMENT"),
        ({"Statement": []}, "INVALID_STATEMENT"),
        ({"Statement": ["invalid"]}, "INVALID_STATEMENT"),
        ({"Statement": {"Action": "x:y", "Resource": "*"}}, "MISSING_EFFECT"),
        (
            {"Statement": {"Effect": "allow", "Action": "x:y", "Resource": "*"}},
            "INVALID_EFFECT",
        ),
        ({"Statement": {"Effect": "Allow", "Resource": "*"}}, "MISSING_ACTION"),
        ({"Statement": {"Effect": "Allow", "Action": "x:y"}}, "MISSING_RESOURCE"),
        (
            {
                "Statement": {
                    "Effect": "Allow",
                    "Action": "x:y",
                    "NotAction": "x:z",
                    "Resource": "*",
                }
            },
            "CONFLICTING_ACTION",
        ),
        (
            {
                "Statement": {
                    "Effect": "Allow",
                    "Action": "x:y",
                    "Resource": "*",
                    "NotResource": "*",
                }
            },
            "CONFLICTING_RESOURCE",
        ),
        (
            {
                "Version": "latest",
                "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"},
            },
            "INVALID_VERSION",
        ),
        (
            {"Statement": {"Effect": "Allow", "Action": [], "Resource": "*"}},
            "INVALID_FIELD_TYPE",
        ),
        (
            {"Statement": {"Effect": "Allow", "Action": ["x:y", 5], "Resource": "*"}},
            "INVALID_FIELD_TYPE",
        ),
        (
            {"Statement": {"Effect": "Allow", "Action": "*", "Resource": 1}},
            "INVALID_FIELD_TYPE",
        ),
        (
            {
                "Statement": {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                    "Principal": "*",
                }
            },
            "FIELD_NOT_ALLOWED",
        ),
        (
            {
                "Id": "example",
                "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"},
            },
            "FIELD_NOT_ALLOWED",
        ),
    ],
)
def test_invalid_policy_structure(policy: dict, expected_code: str) -> None:
    result = validate_iam_policy(json.dumps(policy))

    assert not result.valid
    assert expected_code in [error.code for error in result.errors]


def test_typo_suggestions_do_not_change_permissions() -> None:
    result = validate_iam_policy(
        '{"Statements": {"Effect": "Allow", "Actions": "*", "Resources": "*"}}'
    )

    assert not result.valid
    assert result.errors[0].field == "Statements"
    assert result.errors[0].suggestion == "Check whether you meant Statement."


@pytest.mark.parametrize("field", ["Actions", "Resources"])
def test_statement_typo_suggestions(field: str) -> None:
    policy = {"Statement": {"Effect": "Allow", field: "*"}}
    result = validate_iam_policy(json.dumps(policy))

    assert not result.valid
    assert any(issue.field == field and issue.suggestion for issue in result.errors)


def test_valid_condition_with_numbers_and_booleans() -> None:
    policy = {
        "Statement": {
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "Bool": {"aws:SecureTransport": False},
                "NumericLessThan": {"x:y": [1, 2.5]},
            },
        }
    }
    assert validate_iam_policy(json.dumps(policy)).valid


@pytest.mark.parametrize(
    "condition", [None, [], {}, {"Bool": []}, {"Bool": {"x": None}}]
)
def test_invalid_condition(condition: object) -> None:
    policy = {
        "Statement": {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
            "Condition": condition,
        }
    }
    result = validate_iam_policy(json.dumps(policy))
    assert not result.valid
    assert any(issue.code == "INVALID_CONDITION" for issue in result.errors)


def test_sid_format_and_uniqueness() -> None:
    statement = {"Sid": "Example1", "Effect": "Allow", "Action": "*", "Resource": "*"}
    duplicate = validate_iam_policy(json.dumps({"Statement": [statement, statement]}))
    invalid = validate_iam_policy(
        json.dumps({"Statement": {**statement, "Sid": "bad-sid"}})
    )
    assert any(issue.code == "DUPLICATE_SID" for issue in duplicate.errors)
    assert any(issue.code == "INVALID_SID" for issue in invalid.errors)


def test_statement_and_issue_limits_keep_policy_invalid() -> None:
    statements = [{"Effect": "wrong"}] * (MAX_STATEMENTS + 1)
    result = validate_iam_policy(json.dumps({"Statement": statements}))

    assert not result.valid
    assert any(issue.code == "MAX_STATEMENTS_EXCEEDED" for issue in result.errors)
    assert len(result.errors) + len(result.warnings) == MAX_ISSUES
    assert result.truncated


def test_errors_after_warning_limit_still_make_result_invalid() -> None:
    result = PolicyValidationResult(valid=True, errors=[], warnings=[])
    for _ in range(MAX_ISSUES):
        _add_issue(result, "WARNING", "Warning.", warning=True)
    _add_issue(result, "ERROR", "Error.")

    assert not result.valid
    assert len(result.warnings) == MAX_ISSUES
    assert result.errors == []
    assert result.truncated


def test_extreme_number_returns_controlled_error() -> None:
    result = validate_iam_policy('{"number":1e' + "9" * 100 + "}")

    assert not result.valid
    assert result.errors[0].code == "NUMBER_OUT_OF_RANGE"
