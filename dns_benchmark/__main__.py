"""Allow `python -m dns_benchmark`."""

import sys

from dns_benchmark.cli import main

if __name__ == "__main__":
    sys.exit(main())
