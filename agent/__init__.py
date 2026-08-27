"""CyberForge agent package shim.

The implementation lives in `agent/agent.py`, but many tests and scripts
import the package as `agent`.  This module loads the implementation module
and aliases the package name to it so both styles keep working.
"""

from . import agent as _agent_module
import sys as _sys

_agent_module.__path__ = __path__
_agent_module.__package__ = __name__
_sys.modules[__name__] = _agent_module

