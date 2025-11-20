"""Placeholder CLI module for the Kratos agent."""
from __future__ import annotations

import sys
from typing import Optional

import typer

app = typer.Typer(help="KratosComply agent CLI (Stage A scaffold)")


@app.callback()
def main(_: Optional[bool] = None) -> None:
    """Top-level callback reserved for future commands."""
    typer.echo(
        "Kratos agent CLI is currently a scaffold. Stage B will add real commands."
    )


def run() -> None:
    """Entry point for `python -m agent.cli`."""
    app()


if __name__ == "__main__":
    run()
