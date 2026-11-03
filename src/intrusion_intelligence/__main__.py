"""Run the configured full label summary when the package is invoked directly."""

from __future__ import annotations

from intrusion_intelligence.ingestion.cli import main as ingestion_main


def main() -> int:
    """Run the Phase 02 label-summary command for ``python -m intrusion_intelligence``."""
    return ingestion_main(["summary", "--label-counts"])


if __name__ == "__main__":
    raise SystemExit(main())
