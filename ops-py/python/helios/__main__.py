"""Allow running the Helios Python operations entrypoint via ``python -m helios``."""

from __future__ import annotations

from helios._cli_entry import main

if __name__ == "__main__":
    raise SystemExit(main())
