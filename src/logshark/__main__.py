"""Allow running as ``python -m logshark``."""

import sys

from logshark.cli import main

sys.exit(main())
