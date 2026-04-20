import json
import click

from cryptologik.tls import run_tls_check
from cryptologik.contracts import run_contract_scan


@click.group()
@click.option("--json", "json_output", is_flag=True, help="Output results as structured JSON")
@click.pass_context
def cli(ctx, json_output):
    ctx.ensure_object(dict)
    ctx.obj["json_output"] = json_output


@cli.command("tls-check")
@click.option("--input", "input_path", required=True, help="Path to TLS config file")
@click.pass_context
def tls_check(ctx, input_path):
    result = run_tls_check(input_path)
    if ctx.obj.get("json_output"):
        click.echo(
            json.dumps(
                {
                    "command": "tls-check",
                    "input": input_path,
                    "result": result,
                },
                indent=2,
                sort_keys=True,
                default=str,
            )
        )
        return

    click.echo("TLS Check Result")
    click.echo(result)


@cli.command("contract-scan")
@click.option("--path", "contract_path", required=True, help="Path to smart contract source")
@click.pass_context
def contract_scan(ctx, contract_path):
    result = run_contract_scan(contract_path)
    if ctx.obj.get("json_output"):
        click.echo(
            json.dumps(
                {
                    "command": "contract-scan",
                    "path": contract_path,
                    "result": result,
                },
                indent=2,
                sort_keys=True,
                default=str,
            )
        )
        return

    click.echo("Contract Scan Result")
    click.echo(result)


if __name__ == "__main__":
    cli()
