import json

import pytest

from app.services.terraform_plan_service import (
    MAX_FINDINGS,
    MAX_JSON_DEPTH,
    MAX_RESOURCES,
    TerraformPlanError,
    analyze_terraform_plan,
)


def resource_change(
    address: str,
    resource_type: str,
    actions: list[str],
    *,
    after: dict | None = None,
    after_unknown: dict | bool | None = None,
    after_sensitive: dict | bool | None = None,
    provider_name: str = "registry.terraform.io/hashicorp/aws",
    mode: str = "managed",
    action_reason: str | None = None,
) -> dict:
    change = {"actions": actions}
    if after is not None:
        change["after"] = after
    if after_unknown is not None:
        change["after_unknown"] = after_unknown
    if after_sensitive is not None:
        change["after_sensitive"] = after_sensitive
    result = {
        "address": address,
        "type": resource_type,
        "mode": mode,
        "provider_name": provider_name,
        "change": change,
    }
    if action_reason is not None:
        result["action_reason"] = action_reason
    return result


def plan(*changes: dict, provider: str = "aws") -> dict:
    provider_path = "hashicorp/aws" if provider == "aws" else "oracle/oci"
    provider_name = f"registry.terraform.io/{provider_path}"
    return {
        "format_version": "1.0",
        "resource_changes": list(changes),
        "configuration": {
            "provider_config": {
                "main": {"full_name": provider_name, "name": provider}
            },
            "root_module": {"resources": []},
        },
    }


def analyze(document: dict, provider: str = "aws"):
    return analyze_terraform_plan(json.dumps(document), provider)


def test_summary_counts_actions_and_both_replace_orders() -> None:
    document = plan(
        resource_change("aws_instance.create", "aws_instance", ["create"]),
        resource_change("aws_instance.update", "aws_instance", ["update"]),
        resource_change("aws_instance.delete", "aws_instance", ["delete"]),
        resource_change(
            "aws_instance.replace_a", "aws_instance", ["delete", "create"]
        ),
        resource_change(
            "aws_instance.replace_b", "aws_instance", ["create", "delete"]
        ),
        resource_change("aws_instance.no_op", "aws_instance", ["no-op"]),
        resource_change("data.aws_ami.latest", "aws_ami", ["read"], mode="data"),
    )

    result = analyze(document)

    assert result.summary.model_dump() == {
        "create": 1,
        "update": 1,
        "delete": 1,
        "replace": 2,
        "no_op": 1,
        "read": 1,
    }
    assert [resource.action for resource in result.resources] == [
        "create",
        "update",
        "delete",
        "replace",
        "replace",
        "no_op",
        "read",
    ]


def test_module_addresses_and_string_instance_keys_are_sanitized() -> None:
    document = plan(
        resource_change(
            'module.child.aws_instance.example["confidential-key"]',
            "aws_instance",
            ["delete"],
        )
    )

    result = analyze(document)

    assert result.resources[0].address == (
        'module.child.aws_instance.example["redacted"]'
    )
    assert result.resources[0].resource_index == 0
    assert result.findings[0].resource == result.resources[0].address
    assert "confidential-key" not in result.model_dump_json()


def test_resource_index_distinguishes_sanitized_for_each_addresses() -> None:
    document = plan(
        resource_change(
            'aws_instance.example["first-private-key"]',
            "aws_instance",
            ["delete"],
        ),
        resource_change(
            'aws_instance.example["second-private-key"]',
            "aws_instance",
            ["delete"],
        ),
    )

    result = analyze(document)

    assert result.resources[0].address == result.resources[1].address
    assert [resource.resource_index for resource in result.resources] == [0, 1]
    assert [finding.resource_index for finding in result.findings] == [0, 1]
    assert "private-key" not in result.model_dump_json()


def test_provider_is_identified_from_configuration_metadata() -> None:
    change = resource_change("aws_instance.example", "aws_instance", ["create"])
    change.pop("provider_name")
    document = plan(change)
    document["configuration"]["root_module"]["resources"] = [
        {
            "address": "aws_instance.example",
            "provider_config_key": "main",
        }
    ]

    result = analyze(document)

    assert result.provider == "aws"
    assert result.resources[0].provider_name == "aws"


def test_unknown_safe_action_reason_is_preserved() -> None:
    document = plan(
        resource_change(
            "aws_instance.example",
            "aws_instance",
            ["delete", "create"],
            action_reason="future_reason_v2",
        )
    )

    result = analyze(document)

    assert result.resources[0].action_reason == "future_reason_v2"


def test_aws_specific_findings_require_aws_resource_metadata() -> None:
    document = plan(
        resource_change(
            "aws_instance.main",
            "aws_instance",
            ["no-op"],
        ),
        resource_change(
            "aws_db_instance.helper",
            "aws_db_instance",
            ["delete"],
            provider_name="registry.terraform.io/hashicorp/random",
        )
    )

    result = analyze(document)

    assert [finding.code for finding in result.findings] == ["RESOURCE_DELETION"]


@pytest.mark.parametrize(
    "actions", [["delete"], ["delete", "create"], ["create", "delete"]]
)
def test_rds_delete_or_replace_has_only_specific_finding(actions: list[str]) -> None:
    document = plan(
        resource_change("aws_db_instance.example", "aws_db_instance", actions)
    )

    result = analyze(document)

    assert [(finding.code, finding.severity) for finding in result.findings] == [
        ("RDS_DELETION", "high")
    ]


@pytest.mark.parametrize("actions", [["delete"], ["delete", "create"]])
def test_rds_cluster_delete_or_replace_has_specific_finding(actions: list[str]) -> None:
    document = plan(
        resource_change("aws_rds_cluster.example", "aws_rds_cluster", actions)
    )

    result = analyze(document)

    assert [finding.code for finding in result.findings] == ["RDS_DELETION"]


@pytest.mark.parametrize(
    ("resource_type", "after", "expected_status"),
    [
        (
            "aws_security_group",
            {
                "ingress": [
                    {
                        "protocol": "tcp",
                        "from_port": 22,
                        "to_port": 22,
                        "cidr_blocks": ["0.0.0.0/0"],
                    }
                ]
            },
            "confirmed",
        ),
        (
            "aws_security_group",
            {
                "ingress": [
                    {
                        "protocol": "tcp",
                        "from_port": 20,
                        "to_port": 25,
                        "ipv6_cidr_blocks": ["::/0"],
                    }
                ]
            },
            "confirmed",
        ),
        (
            "aws_security_group_rule",
            {
                "type": "ingress",
                "protocol": 6,
                "from_port": 20,
                "to_port": 25,
                "cidr_blocks": ["0.0.0.0/0"],
            },
            "confirmed",
        ),
        (
            "aws_vpc_security_group_ingress_rule",
            {
                "ip_protocol": "-1",
                "cidr_ipv6": "::/0",
            },
            "confirmed",
        ),
        (
            "aws_security_group",
            {
                "ingress": [
                    {
                        "protocol": "tcp",
                        "from_port": 443,
                        "to_port": 443,
                        "cidr_blocks": ["0.0.0.0/0"],
                    }
                ]
            },
            None,
        ),
        (
            "aws_security_group_rule",
            {
                "type": "ingress",
                "protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "cidr_blocks": ["10.0.0.0/8"],
            },
            None,
        ),
    ],
)
def test_public_ssh_rules(
    resource_type: str,
    after: dict,
    expected_status: str | None,
) -> None:
    document = plan(
        resource_change(
            "aws_security_group.example", resource_type, ["create"], after=after
        )
    )

    result = analyze(document)

    ssh_findings = [
        finding for finding in result.findings if finding.code == "PUBLIC_SSH_ACCESS"
    ]
    if expected_status is None:
        assert ssh_findings == []
    else:
        assert len(ssh_findings) == 1
        assert ssh_findings[0].status == expected_status
        assert ssh_findings[0].severity == "high"


def test_unknown_or_sensitive_ssh_rule_is_inconclusive() -> None:
    document = plan(
        resource_change(
            "aws_security_group.example",
            "aws_security_group",
            ["create"],
            after={"ingress": [{}]},
            after_unknown={"ingress": [{"from_port": True}]},
        ),
        resource_change(
            "aws_vpc_security_group_ingress_rule.secret",
            "aws_vpc_security_group_ingress_rule",
            ["create"],
            after={"ip_protocol": "tcp", "from_port": 22, "to_port": 22},
            after_sensitive={"cidr_ipv4": True},
        ),
        resource_change(
            "aws_security_group_rule.partial",
            "aws_security_group_rule",
            ["create"],
            after={
                "type": "ingress",
                "protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "cidr_blocks": ["10.0.0.0/8", None],
            },
            after_unknown={"cidr_blocks": [False, True]},
        ),
    )

    result = analyze(document)

    findings = [
        finding for finding in result.findings if finding.code == "PUBLIC_SSH_ACCESS"
    ]
    assert [finding.status for finding in findings] == [
        "inconclusive",
        "inconclusive",
        "inconclusive",
    ]
    assert all(finding.severity == "warning" for finding in findings)


def test_security_group_replacement_keeps_generic_and_ssh_findings() -> None:
    document = plan(
        resource_change(
            "aws_security_group.example",
            "aws_security_group",
            ["delete", "create"],
            after={
                "ingress": [
                    {
                        "protocol": "tcp",
                        "from_port": 22,
                        "to_port": 22,
                        "cidr_blocks": ["0.0.0.0/0"],
                    }
                ]
            },
        )
    )

    result = analyze(document)

    assert [finding.code for finding in result.findings] == [
        "RESOURCE_REPLACEMENT",
        "PUBLIC_SSH_ACCESS",
    ]


def test_removed_ssh_rule_is_not_reported() -> None:
    document = plan(
        resource_change(
            "aws_security_group_rule.ssh",
            "aws_security_group_rule",
            ["delete"],
        )
    )

    result = analyze(document)

    assert all(finding.code != "PUBLIC_SSH_ACCESS" for finding in result.findings)
    assert [finding.code for finding in result.findings] == ["RESOURCE_DELETION"]


def test_findings_are_truncated_without_claiming_completeness() -> None:
    document = plan(
        *[
            resource_change(
                f"aws_instance.example_{index}", "aws_instance", ["delete"]
            )
            for index in range(MAX_FINDINGS + 1)
        ]
    )

    result = analyze(document)

    assert len(result.findings) == MAX_FINDINGS
    assert result.truncated is True
    assert result.summary.delete == MAX_FINDINGS + 1
    assert len(result.resources) == MAX_FINDINGS + 1


def test_unknown_provider_action_and_resource_limits_have_stable_errors() -> None:
    cases = [
        (plan(provider="oci"), "aws", "PROVIDER_MISMATCH"),
        (
            {"format_version": "2.0", "resource_changes": []},
            "aws",
            "UNSUPPORTED_FORMAT_VERSION",
        ),
        (
            plan(resource_change("aws_instance.example", "aws_instance", ["move"])),
            "aws",
            "UNSUPPORTED_ACTIONS",
        ),
        (
            plan(
                *[
                    resource_change(
                        f"aws_instance.{index}", "aws_instance", ["no-op"]
                    )
                    for index in range(MAX_RESOURCES + 1)
                ]
            ),
            "aws",
            "RESOURCE_LIMIT_EXCEEDED",
        ),
        (
            {"format_version": "1.0", "resource_changes": []},
            "oci",
            "PROVIDER_UNIDENTIFIED",
        ),
    ]
    for document, provider, expected_code in cases:
        with pytest.raises(TerraformPlanError) as error:
            analyze_terraform_plan(json.dumps(document), provider)
        assert error.value.code == expected_code


def test_newer_minor_format_version_is_accepted() -> None:
    document = plan()
    document["format_version"] = "1.99"

    result = analyze(document)

    assert result.valid is True
    assert result.provider == "aws"


def test_json_errors_and_depth_limit_do_not_include_payload() -> None:
    secret = "terraform-secret-value"
    with pytest.raises(TerraformPlanError) as invalid_json:
        analyze_terraform_plan('{"token":"' + secret, "aws")
    assert invalid_json.value.code == "INVALID_JSON"
    assert secret not in invalid_json.value.message

    with pytest.raises(TerraformPlanError) as duplicate_key:
        analyze_terraform_plan(
            '{"format_version":"1.0","format_version":"1.0",'
            '"resource_changes":[]}',
            "aws",
        )
    assert duplicate_key.value.code == "INVALID_JSON"

    nested = "{" * (MAX_JSON_DEPTH + 1) + "}" * (MAX_JSON_DEPTH + 1)
    with pytest.raises(TerraformPlanError) as too_deep:
        analyze_terraform_plan(nested, "aws")
    assert too_deep.value.code == "MAX_DEPTH_EXCEEDED"
