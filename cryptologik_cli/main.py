import json
import sys
from pathlib import Path

import click

from cryptologik.certificates.expiry import check_certificate_expiry


@click.group()
def cli() -> None:
    """cryptologik command line interface."""
    pass


@cli.command("cert-expiry")
@click.option("--cert", "cert_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Path to certificate file.")
@click.option("--warn-days", default=30, show_default=True, type=int, help="Warning threshold in days.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON output.")
@click.option("--output", "output_path", type=click.Path(dir_okay=False, path_type=Path), help="Write JSON report to file path.")
def cert_expiry(cert_path: Path, warn_days: int, as_json: bool, output_path: Path | None) -> None:
    """Check certificate expiry risk."""
    result = check_certificate_expiry(str(cert_path), warn_days=warn_days)

    if as_json:
        payload = json.dumps(result, indent=2)
        if output_path is not None:
            try:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(payload + "\n", encoding="utf-8")
            except OSError as exc:
                click.echo(f"Error: unable to write output file '{output_path}': {exc}", err=True)
                raise SystemExit(1)
        else:
            click.echo(payload)
        return

    # Keep existing non-JSON behavior unchanged.
    click.echo(f"certificate: {result.get('certificate', cert_path)}")
    click.echo(f"days_until_expiry: {result.get('days_until_expiry', 'unknown')}")
    click.echo(f"status: {result.get('status', 'unknown')}")


if __name__ == "__main__":
    cli()
