import json
from pathlib import Path

import click
import yaml

from cryptologik.tls import evaluate_tls_config, DEFAULT_TLS_POLICY


ALLOWED_TLS_POLICY_KEYS = {
    "minimum_tls_version": str,
    "disallowed_ciphers": list,
    "weak_signature_algorithms": list,
    "minimum_key_sizes": dict,
}


def _load_policy_file(config_path: str) -> dict:
    path = Path(config_path)
    if not path.exists():
        raise click.ClickException(f"Config file not found: {config_path}")

    raw = path.read_text(encoding="utf-8")
    try:
        if path.suffix.lower() == ".json":
            data = json.loads(raw)
        else:
            data = yaml.safe_load(raw)
    except Exception as exc:
        raise click.ClickException(
            f"Failed to parse policy config '{config_path}'. Expected valid YAML/JSON. Error: {exc}"
        )

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise click.ClickException(
            f"Invalid policy config '{config_path}': top-level object must be a mapping/object."
        )

    unknown = sorted(set(data.keys()) - set(ALLOWED_TLS_POLICY_KEYS.keys()))
    if unknown:
        raise click.ClickException(
            "Invalid policy config key(s): "
            + ", ".join(unknown)
            + ". Allowed keys: "
            + ", ".join(sorted(ALLOWED_TLS_POLICY_KEYS.keys()))
        )

    for key, expected in ALLOWED_TLS_POLICY_KEYS.items():
        if key in data and not isinstance(data[key], expected):
            raise click.ClickException(
                f"Invalid policy config for '{key}': expected {expected.__name__}, got {type(data[key]).__name__}."
            )

    return data


def _merge_tls_policy(defaults: dict, config_overrides: dict, cli_overrides: dict) -> dict:
    policy = dict(defaults)

    for source in (config_overrides or {}, cli_overrides or {}):
        for k, v in source.items():
            if v is None:
                continue
            if isinstance(policy.get(k), dict) and isinstance(v, dict):
                merged = dict(policy[k])
                merged.update(v)
                policy[k] = merged
            else:
                policy[k] = v

    return policy


@click.group()
def cli():
    pass


@cli.command("tls-check")
@click.option("--input", "input_path", required=True, help="Path to TLS server config YAML")
@click.option(
    "--config",
    "policy_config",
    required=False,
    help="Optional YAML/JSON TLS policy profile to override defaults",
)
@click.option("--minimum-tls-version", required=False, help="Override minimum TLS version policy")
def tls_check(input_path: str, policy_config: str, minimum_tls_version: str):
    """Evaluate TLS posture from an input server config.

    Policy precedence is deterministic: CLI flags > --config profile > built-in defaults.
    """

    config_overrides = _load_policy_file(policy_config) if policy_config else {}
    cli_overrides = {"minimum_tls_version": minimum_tls_version} if minimum_tls_version else {}

    policy = _merge_tls_policy(DEFAULT_TLS_POLICY, config_overrides, cli_overrides)

    result = evaluate_tls_config(input_path=input_path, policy=policy)
    click.echo(json.dumps(result, indent=2))


if __name__ == "__main__":
    cli()
