"""Allow ``python -m soerm``."""

from soerm.cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
