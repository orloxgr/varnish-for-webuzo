"""Compile the addon-owned VMOD for the installed engine before native startup."""
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'shared')]
import repository


if __name__=='__main__':repository.ensure_cookie_handoff()
