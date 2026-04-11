"""
Compatibility shim for the historical CLI entrypoint.

This module preserves legacy imports based on ``cli.main`` without carrying
two divergent CLI implementations. The canonical CLI lives in
``cryptologik_cli.main``.
"""

from cryptologik_cli.main import cli

__all__ = ["cli"]


if __name__ == "__main__":
    cli()
