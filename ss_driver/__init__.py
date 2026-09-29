"""Delinea Secret Server credential driver for NVIDIA OpenShell (proof of concept)."""

import os
import sys

__version__ = "0.1.0-poc"

# The generated OpenShell stubs import each other by top-level module name.
_GENERATED = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "generated")
if _GENERATED not in sys.path:
    sys.path.insert(0, _GENERATED)
