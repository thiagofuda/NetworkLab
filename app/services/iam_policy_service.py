import json
import re
from decimal import Decimal, InvalidOperation
from typing import Any

from app.schemas.iam_policy import PolicyIssue, PolicyValidationResult

MAX_JSON_DEPTH = 20
MAX_STATEMENTS = 100
MAX_ISSUES = 50


class DuplicateKeyError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError()
        result[key] = value
    return result


def _reject_non_json_constant(value: str) -> None:
    raise ValueError()


def _exceeds_max_depth(text: str) -> bool:
    depth = 0
    in_string = False
    escaped = False

    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return True
        elif character in "]}":
            depth -= 1

    return False


def parse_policy(text: str) -> tuple[dict[str, Any] | None, PolicyIssue | None]:
    if not text.strip():
        return None, PolicyIssue(code="EMPTY_DOCUMENT", message="The policy is empty.")

    if _exceeds_max_depth(text):
        return None, PolicyIssue(
            code="MAX_DEPTH_EXCEEDED",
            message="The policy exceeds the maximum JSON depth of 20.",
        )

    try:
        policy = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_constant,
            parse_float=Decimal,
        )
    except DuplicateKeyError:
        return None, PolicyIssue(
            code="DUPLICATE_KEY",
            message="The policy contains a duplicate JSON key.",
            suggestion="Review the policy and remove or combine the duplicate key.",
        )
    except json.JSONDecodeError as error:
        return None, PolicyIssue(
            code="INVALID_JSON",
            message="The policy is not valid JSON.",
            line=error.lineno,
            column=error.colno,
            suggestion="Check the JSON syntax near the reported position.",
        )
    except InvalidOperation:
        return None, PolicyIssue(
            code="NUMBER_OUT_OF_RANGE",
            message="The policy contains a number outside the supported range.",
        )
    except (ValueError, RecursionError):
        return None, PolicyIssue(
            code="INVALID_JSON",
            message="The policy is not valid JSON.",
        )

    if not isinstance(policy, dict):
        return None, PolicyIssue(
            code="INVALID_ROOT",
            message="The policy must be a JSON object.",
        )

    return policy, None


def _add_issue(
    result: PolicyValidationResult,
    code: str,
    message: str,
    *,
    path: str | None = None,
    field: str | None = None,
    suggestion: str | None = None,
    warning: bool = False,
) -> None:
    if not warning:
        result.valid = False
    if len(result.errors) + len(result.warnings) >= MAX_ISSUES:
        result.truncated = True
        return
    issue = PolicyIssue(
        code=code,
        message=message,
        path=path,
        field=field,
        suggestion=suggestion,
    )
    if warning:
        result.warnings.append(issue)
    else:
        result.errors.append(issue)


def _check_unknown_fields(
    data: dict[str, Any],
    allowed_fields: set[str],
    path: str,
    result: PolicyValidationResult,
) -> None:
    suggestions = {
        "Actions": "Action",
        "Resources": "Resource",
        "Statements": "Statement",
    }
    for field in data:
        if field in allowed_fields:
            continue
        if field in suggestions and suggestions[field] in allowed_fields:
            _add_issue(
                result,
                "UNKNOWN_FIELD",
                "The policy contains an unknown field.",
                path=path,
                field=field,
                suggestion=f"Check whether you meant {suggestions[field]}.",
            )
        elif field in {"Principal", "NotPrincipal", "Id"}:
            _add_issue(
                result,
                "FIELD_NOT_ALLOWED",
                "This field is not allowed in an identity policy.",
                path=path,
                field=field,
            )
        else:
            _add_issue(
                result,
                "UNKNOWN_FIELD",
                "The policy contains an unknown field.",
                path=path,
            )


def _check_choice(
    statement: dict[str, Any],
    first: str,
    second: str,
    path: str,
    result: PolicyValidationResult,
) -> None:
    if first not in statement and second not in statement:
        _add_issue(
            result,
            f"MISSING_{first.upper()}",
            f"The statement requires {first} or {second}.",
            path=path,
            field=first,
        )
        return
    if first in statement and second in statement:
        _add_issue(
            result,
            f"CONFLICTING_{first.upper()}",
            f"Use either {first} or {second}, not both.",
            path=path,
        )

    for field in (first, second):
        if field not in statement:
            continue
        value = statement[field]
        field_path = f"{path}.{field}"
        if isinstance(value, list):
            if not value:
                _add_issue(
                    result,
                    "INVALID_FIELD_TYPE",
                    f"{field} must be a non-empty string or list of non-empty strings.",
                    path=field_path,
                    field=field,
                )
                continue
            for index, item in enumerate(value):
                if not isinstance(item, str) or not item:
                    _add_issue(
                        result,
                        "INVALID_FIELD_TYPE",
                        f"{field} entries must be non-empty strings.",
                        path=f"{field_path}[{index}]",
                        field=field,
                    )
            continue

        if not isinstance(value, str) or not value:
            _add_issue(
                result,
                "INVALID_FIELD_TYPE",
                f"{field} must be a non-empty string or list of non-empty strings.",
                path=field_path,
                field=field,
            )


def _check_condition(condition: Any, path: str, result: PolicyValidationResult) -> None:
    if not isinstance(condition, dict) or not condition:
        _add_issue(
            result,
            "INVALID_CONDITION",
            "Condition must be a non-empty object of operators and keys.",
            path=path,
            field="Condition",
        )
        return

    for operator, keys in condition.items():
        if not operator or not isinstance(keys, dict) or not keys:
            _add_issue(
                result,
                "INVALID_CONDITION",
                "Each condition operator must contain a non-empty object of keys.",
                path=path,
                field="Condition",
            )
            continue
        for key, value in keys.items():
            values = value if isinstance(value, list) else [value]
            if (
                not key
                or not values
                or any(
                    not isinstance(item, (str, int, Decimal, bool)) for item in values
                )
            ):
                _add_issue(
                    result,
                    "INVALID_CONDITION",
                    "Condition values must be strings, numbers, booleans, or lists.",
                    path=path,
                    field="Condition",
                )


def _check_statement(
    statement: Any,
    index: int,
    result: PolicyValidationResult,
    seen_sids: set[str],
) -> None:
    path = f"Statement[{index}]"
    if not isinstance(statement, dict):
        _add_issue(
            result, "INVALID_STATEMENT", "Each statement must be an object.", path=path
        )
        return

    _check_unknown_fields(
        statement,
        {
            "Sid",
            "Effect",
            "Action",
            "NotAction",
            "Resource",
            "NotResource",
            "Condition",
        },
        path,
        result,
    )
    if "Effect" not in statement:
        _add_issue(
            result, "MISSING_EFFECT", "Effect is required.", path=path, field="Effect"
        )
    elif statement["Effect"] not in ("Allow", "Deny"):
        _add_issue(
            result,
            "INVALID_EFFECT",
            "Effect must be Allow or Deny.",
            path=path,
            field="Effect",
        )

    _check_choice(statement, "Action", "NotAction", path, result)
    _check_choice(statement, "Resource", "NotResource", path, result)

    if "Sid" in statement:
        sid = statement["Sid"]
        if not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z0-9]+", sid):
            _add_issue(
                result,
                "INVALID_SID",
                "Sid must contain only ASCII letters and digits.",
                path=path,
                field="Sid",
            )
        elif sid in seen_sids:
            _add_issue(
                result,
                "DUPLICATE_SID",
                "Sid values must be unique.",
                path=path,
                field="Sid",
            )
        else:
            seen_sids.add(sid)

    if "Condition" in statement:
        _check_condition(statement["Condition"], path, result)


def validate_iam_policy(text: str) -> PolicyValidationResult:
    policy, parse_error = parse_policy(text)
    if parse_error is not None:
        return PolicyValidationResult(valid=False, errors=[parse_error], warnings=[])

    result = PolicyValidationResult(valid=True, errors=[], warnings=[])
    if policy is None:
        return PolicyValidationResult(
            valid=False,
            errors=[
                PolicyIssue(
                    code="INVALID_JSON", message="The policy is not valid JSON."
                )
            ],
            warnings=[],
        )

    _check_unknown_fields(policy, {"Version", "Statement"}, "$", result)
    if "Version" in policy and policy["Version"] not in ("2008-10-17", "2012-10-17"):
        _add_issue(
            result,
            "INVALID_VERSION",
            "Version must be 2008-10-17 or 2012-10-17.",
            path="$",
            field="Version",
        )

    if "Statement" not in policy:
        _add_issue(
            result,
            "MISSING_STATEMENT",
            "Statement is required.",
            path="$",
            field="Statement",
        )
        return result

    statements = policy["Statement"]
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        _add_issue(
            result,
            "INVALID_STATEMENT",
            "Statement must be an object or a non-empty list of objects.",
            path="$",
            field="Statement",
        )
        return result

    if len(statements) > MAX_STATEMENTS:
        _add_issue(
            result,
            "MAX_STATEMENTS_EXCEEDED",
            "The policy exceeds the limit of 100 statements.",
            path="Statement",
        )

    seen_sids: set[str] = set()
    for index, statement in enumerate(statements[:MAX_STATEMENTS]):
        _check_statement(statement, index, result, seen_sids)

    if "Version" not in policy:
        _add_issue(
            result,
            "VERSION_RECOMMENDED",
            "AWS recommends including Version 2012-10-17.",
            path="$",
            field="Version",
            warning=True,
        )
    return result
