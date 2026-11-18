import ipaddress
import json
import re
from typing import Any

from app.schemas.terraform_plan import (
    TerraformPlanFinding,
    TerraformPlanResource,
    TerraformPlanResult,
    TerraformPlanSummary,
)

MAX_JSON_DEPTH = 40
MAX_RESOURCES = 500
MAX_FINDINGS = 100
SUPPORTED_FORMAT_MAJOR = 1
SUPPORTED_ACTIONS = {"no-op", "create", "update", "delete", "read"}
REPLACE_ACTIONS = {("delete", "create"), ("create", "delete")}
RDS_RESOURCE_TYPES = {"aws_db_instance", "aws_rds_cluster"}
SECURITY_GROUP_RESOURCE_TYPES = {
    "aws_security_group",
    "aws_security_group_rule",
    "aws_vpc_security_group_ingress_rule",
}
ADDRESS_STRING_KEY = re.compile(r'\[(?:"(?:\\.|[^"\\])*")\]')
PROVIDER_NAME = re.compile(r"[A-Za-z0-9._/-]{1,255}\Z")
RESOURCE_TYPE = re.compile(r"[A-Za-z0-9_]{1,128}\Z")
SAFE_ADDRESS = re.compile(r'[A-Za-z0-9_.\[\]"-]{1,1024}\Z')


class TerraformPlanError(Exception):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def _reject_non_json_constant(value: str) -> None:
    raise ValueError()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # Chaves repetidas tornam ambiguo qual valor o plano pretende fornecer.
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _exceeds_max_depth(text: str) -> bool:
    # Limita a recursao antes do json.loads, ignorando delimitadores dentro de strings.
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
            depth = max(0, depth - 1)

    return False


def _parse_plan(text: str) -> dict[str, Any]:
    if not text.strip():
        raise TerraformPlanError(400, "INVALID_JSON", "The request body must be JSON.")
    if _exceeds_max_depth(text):
        raise TerraformPlanError(
            422,
            "MAX_DEPTH_EXCEEDED",
            "The JSON document exceeds the maximum depth of 40.",
        )

    try:
        plan = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_constant,
        )
    except (json.JSONDecodeError, ValueError, RecursionError) as error:
        raise TerraformPlanError(
            400, "INVALID_JSON", "The request body must be valid JSON."
        ) from error

    if not isinstance(plan, dict):
        raise TerraformPlanError(
            422, "NOT_TERRAFORM_PLAN", "The JSON document is not a Terraform plan."
        )
    return plan


def _provider_kind(provider_name: Any) -> str | None:
    if not isinstance(provider_name, str):
        return None
    provider = provider_name.strip().lower().rsplit("/", 1)[-1]
    if provider in {"aws", "oci"}:
        return provider
    return None


def _provider_label(provider_name: str) -> str:
    return provider_name.rsplit("/", 1)[-1]


def _provider_config_names(configuration: Any) -> dict[str, str]:
    if not isinstance(configuration, dict):
        return {}
    provider_configs = configuration.get("provider_config")
    if not isinstance(provider_configs, dict):
        return {}

    names: dict[str, str] = {}
    for key, config in provider_configs.items():
        if not isinstance(key, str) or not isinstance(config, dict):
            continue
        name = config.get("full_name", config.get("name"))
        if isinstance(name, str) and PROVIDER_NAME.fullmatch(name):
            names[key] = name
    return names


def _add_provider_name(
    provider_name: Any,
    providers: set[str],
    address_names: dict[str, str],
    address: Any = None,
) -> bool:
    if not isinstance(provider_name, str) or not PROVIDER_NAME.fullmatch(provider_name):
        return False
    kind = _provider_kind(provider_name)
    if kind is not None:
        providers.add(kind)
    if isinstance(address, str):
        address_names[address] = provider_name
    return True


def _walk_config_resources(
    module: Any,
    provider_configs: dict[str, str],
    providers: set[str],
    address_names: dict[str, str],
) -> int:
    # A configuracao pode aninhar recursos em chamadas de modulo.
    if not isinstance(module, dict):
        return 0

    visited = 0
    resources = module.get("resources", [])
    if isinstance(resources, list):
        for resource in resources:
            if not isinstance(resource, dict):
                continue
            visited += 1
            config_key = resource.get("provider_config_key")
            provider_name = (
                provider_configs.get(config_key)
                if isinstance(config_key, str)
                else None
            )
            _add_provider_name(
                provider_name,
                providers,
                address_names,
                resource.get("address"),
            )

    module_calls = module.get("module_calls", {})
    if isinstance(module_calls, dict):
        for module_call in module_calls.values():
            if isinstance(module_call, dict):
                visited += _walk_config_resources(
                    module_call.get("module"),
                    provider_configs,
                    providers,
                    address_names,
                )
    return visited


def _walk_value_resources(
    module: Any,
    providers: set[str],
    address_names: dict[str, str],
) -> int:
    if not isinstance(module, dict):
        return 0

    visited = 0
    resources = module.get("resources", [])
    if isinstance(resources, list):
        for resource in resources:
            if not isinstance(resource, dict):
                continue
            visited += 1
            _add_provider_name(
                resource.get("provider_name"),
                providers,
                address_names,
                resource.get("address"),
            )

    child_modules = module.get("child_modules", [])
    if isinstance(child_modules, list):
        for child_module in child_modules:
            visited += _walk_value_resources(
                child_module,
                providers,
                address_names,
            )
    return visited


def _identify_provider(
    plan: dict[str, Any],
    changes: list[dict[str, Any]],
    expected_provider: str,
) -> dict[str, str]:
    # O provider vem dos metadados; o prefixo do tipo do recurso nao basta.
    providers: set[str] = set()
    address_names: dict[str, str] = {}
    metadata_resource_count = 0

    # Registra os providers de todas as fontes para detectar planos mistos.
    # Para o mesmo endereco, a ultima fonte com nome valido sobrescreve a anterior:
    # configuracao, valores planejados, estado anterior e mudancas de recursos.
    configuration = plan.get("configuration")
    provider_configs = _provider_config_names(configuration)
    if isinstance(configuration, dict):
        metadata_resource_count += _walk_config_resources(
            configuration.get("root_module"),
            provider_configs,
            providers,
            address_names,
        )

    for values_key in ("planned_values", "prior_state"):
        values = plan.get(values_key)
        if values_key == "prior_state" and isinstance(values, dict):
            values = values.get("values")
        if isinstance(values, dict):
            metadata_resource_count += _walk_value_resources(
                values.get("root_module"),
                providers,
                address_names,
            )

    for resource_change in changes:
        metadata_resource_count += 1
        _add_provider_name(
            resource_change.get("provider_name"),
            providers,
            address_names,
            resource_change.get("address"),
        )
        address = resource_change.get("address")
        # Uma instancia pode ter um indice que falta no endereco da configuracao.
        if isinstance(address, str) and address not in address_names:
            for config_address, provider_name in tuple(address_names.items()):
                if address.startswith(f"{config_address}["):
                    address_names[address] = provider_name
                    break

    # Em planos sem recursos, a lista declarada pode ser a unica fonte.
    if metadata_resource_count == 0:
        for provider_name in provider_configs.values():
            kind = _provider_kind(provider_name)
            if kind is not None:
                providers.add(kind)

    if providers == {"aws", "oci"}:
        raise TerraformPlanError(
            422,
            "MIXED_CLOUD_PROVIDERS",
            "Plans containing both AWS and OCI resources are not supported.",
        )
    if not providers:
        raise TerraformPlanError(
            422,
            "PROVIDER_UNIDENTIFIED",
            "The plan does not contain metadata identifying AWS or OCI.",
        )
    if expected_provider not in providers:
        other_provider = "OCI" if expected_provider == "aws" else "AWS"
        raise TerraformPlanError(
            422,
            "PROVIDER_MISMATCH",
            f"This route accepts {expected_provider.upper()} plans, not "
            f"{other_provider} plans.",
        )

    return address_names


def _normalize_action(actions: Any) -> str:
    if not isinstance(actions, list) or not all(
        isinstance(action, str) for action in actions
    ):
        raise TerraformPlanError(
            422, "UNSUPPORTED_ACTIONS", "A resource has an unsupported action list."
        )
    action_tuple = tuple(actions)
    # As duas sequencias documentadas pelo Terraform representam um unico replace.
    if action_tuple in REPLACE_ACTIONS:
        return "replace"
    if len(action_tuple) == 1 and action_tuple[0] in SUPPORTED_ACTIONS:
        return "no_op" if action_tuple[0] == "no-op" else action_tuple[0]
    raise TerraformPlanError(
        422, "UNSUPPORTED_ACTIONS", "A resource has an unsupported action list."
    )


def _sanitize_address(address: str) -> str:
    # Chaves string de for_each podem conter dados privados.
    # resource_index mantem a distincao depois da redacao.
    sanitized = ADDRESS_STRING_KEY.sub('["redacted"]', address)
    if not SAFE_ADDRESS.fullmatch(sanitized):
        raise TerraformPlanError(
            422, "INVALID_PLAN", "A resource address is invalid."
        )
    return sanitized


def _contains_true(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, dict):
        return any(_contains_true(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_true(item) for item in value)
    return False


def _has_mask(
    unknown: Any,
    sensitive: Any,
    path: tuple[str | int, ...],
) -> bool:
    # As mascaras espelham after; qualquer true no campo impede uma conclusao segura.
    for mask in (unknown, sensitive):
        current = mask
        for part in path:
            if current is True:
                return True
            if isinstance(current, dict) and isinstance(part, str):
                current = current.get(part)
            elif isinstance(current, list) and isinstance(part, int):
                if part >= len(current):
                    current = None
                    break
                current = current[part]
            else:
                current = None
                break
        if _contains_true(current):
            return True
    return False


def _public_cidr(value: Any) -> bool | None:
    if not isinstance(value, str):
        return None
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    # So CIDRs que cobrem toda a familia IP contam como acesso publico.
    return network.prefixlen == 0


def _cidr_state(
    rule: dict[str, Any],
    unknown: Any,
    sensitive: Any,
    rule_path: tuple[str | int, ...],
    cidr_fields: tuple[str, ...],
) -> tuple[bool, bool]:
    world_open = False
    uncertain = False
    for field in cidr_fields:
        path = (*rule_path, field)
        if _has_mask(unknown, sensitive, path):
            uncertain = True
            continue
        value = rule.get(field)
        if value is None:
            continue
        values = value if isinstance(value, list) else [value]
        for cidr in values:
            public = _public_cidr(cidr)
            if public is True:
                world_open = True
            elif public is None:
                uncertain = True
    return world_open, uncertain


def _rule_exposure(
    rule: dict[str, Any],
    unknown: Any,
    sensitive: Any,
    rule_path: tuple[str | int, ...],
    protocol_field: str,
    cidr_fields: tuple[str, ...],
) -> str | None:
    # Protocolo e portas delimitam SSH; a origem publica confirma a exposicao.
    world_open, uncertain_source = _cidr_state(
        rule,
        unknown,
        sensitive,
        rule_path,
        cidr_fields,
    )
    protocol_path = (*rule_path, protocol_field)
    protocol_unknown = _has_mask(unknown, sensitive, protocol_path)
    protocol = rule.get(protocol_field)

    if protocol_unknown or protocol is None:
        return "inconclusive"
    if isinstance(protocol, bool):
        return "inconclusive"
    if isinstance(protocol, int):
        protocol_value = str(protocol)
    elif isinstance(protocol, str):
        protocol_value = protocol.strip().lower()
    else:
        return "inconclusive"

    if protocol_value in {"-1", "all"}:
        # No formato AWS, -1/all significa qualquer protocolo e qualquer porta.
        if world_open:
            return "confirmed"
        return "inconclusive" if uncertain_source else None
    if protocol_value not in {"tcp", "6"}:
        if protocol_value.isdecimal():
            return None
        if protocol_value in {"udp", "icmp", "icmpv6", "1", "58"}:
            return None
        return "inconclusive"

    port_values: list[int] = []
    for field in ("from_port", "to_port"):
        path = (*rule_path, field)
        value = rule.get(field)
        if _has_mask(unknown, sensitive, path):
            return "inconclusive"
        if isinstance(value, bool) or not isinstance(value, int):
            return "inconclusive"
        port_values.append(value)
    # O intervalo e inclusivo: 20-25, por exemplo, tambem inclui a porta 22.
    if not port_values[0] <= 22 <= port_values[1]:
        return None
    if world_open:
        return "confirmed"
    return "inconclusive" if uncertain_source else None


def _security_group_exposure(resource_change: dict[str, Any]) -> str | None:
    change = resource_change["change"]
    action = _normalize_action(change["actions"])
    # Uma regra removida nao permanece no estado proposto e nao cria exposicao.
    if action in {"delete", "read"} or resource_change.get("mode") == "data":
        return None

    resource_type = resource_change["type"]
    after = change.get("after")
    unknown = change.get("after_unknown")
    sensitive = change.get("after_sensitive")
    if not isinstance(after, dict):
        return "inconclusive"

    exposures: list[str] = []
    # Os tres recursos AWS usam nomes e niveis de aninhamento diferentes para ingress.
    if resource_type == "aws_security_group":
        ingress_path = ("ingress",)
        if _has_mask(unknown, sensitive, ingress_path):
            return "inconclusive"
        ingress = after.get("ingress", [])
        if ingress is None or ingress == []:
            return None
        if not isinstance(ingress, list):
            return "inconclusive"
        for index, rule in enumerate(ingress):
            if not isinstance(rule, dict):
                exposures.append("inconclusive")
                continue
            exposure = _rule_exposure(
                rule,
                unknown,
                sensitive,
                ("ingress", index),
                "protocol",
                ("cidr_blocks", "ipv6_cidr_blocks"),
            )
            if exposure is not None:
                exposures.append(exposure)
    elif resource_type == "aws_security_group_rule":
        type_path = ("type",)
        if _has_mask(unknown, sensitive, type_path):
            return "inconclusive"
        rule_type = after.get("type")
        if rule_type == "egress":
            return None
        if rule_type != "ingress":
            return "inconclusive"
        exposure = _rule_exposure(
            after,
            unknown,
            sensitive,
            (),
            "protocol",
            ("cidr_blocks", "ipv6_cidr_blocks"),
        )
        if exposure is not None:
            exposures.append(exposure)
    else:
        exposure = _rule_exposure(
            after,
            unknown,
            sensitive,
            (),
            "ip_protocol",
            ("cidr_ipv4", "cidr_ipv6"),
        )
        if exposure is not None:
            exposures.append(exposure)

    if "confirmed" in exposures:
        return "confirmed"
    if "inconclusive" in exposures:
        return "inconclusive"
    return None


def _validate_plan_structure(plan: dict[str, Any]) -> list[dict[str, Any]]:
    format_version = plan.get("format_version")
    if not isinstance(format_version, str):
        raise TerraformPlanError(
            422, "NOT_TERRAFORM_PLAN", "The document is not a Terraform plan."
        )
    version_match = re.fullmatch(r"(\d+)\.(\d+)", format_version)
    if version_match is None:
        raise TerraformPlanError(
            422,
            "UNSUPPORTED_FORMAT_VERSION",
            "The Terraform format version is unsupported.",
        )
    if int(version_match.group(1)) != SUPPORTED_FORMAT_MAJOR:
        raise TerraformPlanError(
            422,
            "UNSUPPORTED_FORMAT_VERSION",
            "The Terraform format version is unsupported.",
        )
    if plan.get("errored") is True:
        raise TerraformPlanError(
            422, "PLAN_ERRORED", "Terraform reported that plan generation failed."
        )

    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        raise TerraformPlanError(
            422,
            "NOT_TERRAFORM_PLAN",
            "The document does not contain Terraform resource changes.",
        )
    if len(changes) > MAX_RESOURCES:
        raise TerraformPlanError(
            422,
            "RESOURCE_LIMIT_EXCEEDED",
            "The plan exceeds the maximum of 500 resource changes.",
        )

    for resource_change in changes:
        if not isinstance(resource_change, dict):
            raise TerraformPlanError(
                422, "INVALID_PLAN", "A resource change has an invalid structure."
            )
        address = resource_change.get("address")
        resource_type = resource_change.get("type")
        change = resource_change.get("change")
        if (
            not isinstance(address, str)
            or not address
            or len(address) > 2048
            or not isinstance(resource_type, str)
            or not RESOURCE_TYPE.fullmatch(resource_type)
            or not isinstance(change, dict)
            or "actions" not in change
        ):
            raise TerraformPlanError(
                422, "INVALID_PLAN", "A resource change has an invalid structure."
            )
        _normalize_action(change["actions"])
    return changes


def analyze_terraform_plan(text: str, expected_provider: str) -> TerraformPlanResult:
    if expected_provider not in {"aws", "oci"}:
        raise ValueError("expected_provider must be 'aws' or 'oci'")

    plan = _parse_plan(text)
    changes = _validate_plan_structure(plan)
    address_names = _identify_provider(plan, changes, expected_provider)

    summary = TerraformPlanSummary()
    resources: list[TerraformPlanResource] = []
    findings: list[TerraformPlanFinding] = []
    truncated = False

    for resource_index, resource_change in enumerate(changes):
        address = resource_change["address"]
        sanitized_address = _sanitize_address(address)
        resource_type = resource_change["type"]
        change = resource_change["change"]
        action = _normalize_action(change["actions"])
        setattr(summary, action, getattr(summary, action) + 1)

        provider_name = resource_change.get("provider_name")
        if (
            not isinstance(provider_name, str)
            or not PROVIDER_NAME.fullmatch(provider_name)
        ):
            provider_name = address_names.get(address)
        resource_provider = _provider_kind(provider_name)
        if provider_name is not None:
            provider_name = _provider_label(provider_name)
        action_reason = resource_change.get("action_reason")
        if (
            not isinstance(action_reason, str)
            or not re.fullmatch(r"[a-z0-9_]{1,80}", action_reason)
        ):
            action_reason = None

        resources.append(
            TerraformPlanResource(
                resource_index=resource_index,
                address=sanitized_address,
                type=resource_type,
                action=action,
                provider_name=provider_name,
                action_reason=action_reason,
            )
        )

        mode = resource_change.get("mode")
        resource_findings: list[TerraformPlanFinding] = []
        if mode != "data" and action in {"delete", "replace"}:
            if resource_type in RDS_RESOURCE_TYPES and resource_provider == "aws":
                resource_findings.append(
                    TerraformPlanFinding(
                        code="RDS_DELETION",
                        severity="high",
                        resource=sanitized_address,
                        resource_index=resource_index,
                        message=(
                            "An AWS RDS resource is planned for deletion or "
                            "replacement."
                        ),
                    )
                )
            elif action == "delete":
                resource_findings.append(
                    TerraformPlanFinding(
                        code="RESOURCE_DELETION",
                        severity="warning",
                        resource=sanitized_address,
                        resource_index=resource_index,
                        message="This resource is planned for deletion.",
                    )
                )
            else:
                resource_findings.append(
                    TerraformPlanFinding(
                        code="RESOURCE_REPLACEMENT",
                        severity="warning",
                        resource=sanitized_address,
                        resource_index=resource_index,
                        message="This resource is planned for replacement.",
                    )
                )
        if (
            resource_provider == "aws"
            and mode != "data"
            and resource_type in SECURITY_GROUP_RESOURCE_TYPES
        ):
            exposure = _security_group_exposure(resource_change)
            if exposure is not None:
                resource_findings.append(
                    TerraformPlanFinding(
                        code="PUBLIC_SSH_ACCESS",
                        severity="high" if exposure == "confirmed" else "warning",
                        resource=sanitized_address,
                        resource_index=resource_index,
                        message=(
                            "The proposed security group allows public TCP access "
                            "to port 22."
                            if exposure == "confirmed"
                            else "SSH exposure could not be determined from the "
                            "proposed values."
                        ),
                        status=exposure,
                    )
                )

        for finding in resource_findings:
            if len(findings) < MAX_FINDINGS:
                findings.append(finding)
            else:
                # O resumo continua completo, mas a lista de findings foi limitada.
                truncated = True

    return TerraformPlanResult(
        provider=expected_provider,
        summary=summary,
        resources=resources,
        findings=findings,
        truncated=truncated,
    )
