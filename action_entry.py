"""Isolated entry point: never import executable modules from the target checkout."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from general_auditor.cli import main  # noqa: E402

raise SystemExit(main())
