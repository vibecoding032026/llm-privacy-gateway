"""
state.py — Shared application singletons.

Centralises the Masker instance so that both server.py and rag.py
can import it without creating a circular dependency.
"""

from .masker import Masker

# Single shared masker instance for the entire application lifetime.
masker = Masker()
