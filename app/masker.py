"""
masker.py — Stateful, session-aware masking / de-masking engine.

Design decisions
----------------
* Short tags  ([IP_1], [HOST_1], [EMAIL_1]) keep token overhead minimal.
* Patterns are applied in priority order: IP → EMAIL → HOST → LOG_PATH.
  More-specific patterns run first so a sub-string cannot be re-matched
  by a coarser pattern later.
* The same raw value always maps to the same tag within a session, giving
  the LLM a consistent view across turns (Context Integrity).
* De-masking sorts tags by descending length so [HOST_10] is restored
  before [HOST_1] and avoids partial-replacement bugs.
"""

import re
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pattern registry  (entity_type, compiled_regex)
# Order matters — more specific patterns must come first.
# ---------------------------------------------------------------------------
PATTERNS: List[Tuple[str, re.Pattern]] = [
    # ── IPv4 addresses ───────────────────────────────────────────────────────
    (
        "IP",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
    ),
    # ── E-mail addresses ─────────────────────────────────────────────────────
    (
        "EMAIL",
        re.compile(r"\b[\w.%+\-]+@[\w.\-]+\.[a-zA-Z]{2,}\b"),
    ),
    # ── Server / service hostnames ───────────────────────────────────────────
    # Matches two sub-forms:
    #   A) known-prefix + one-or-more dash-separated segments
    #      e.g.  srv-web-01, db-master, api-gw-prod
    #   B) any word ending with -<2+ digits>  BUT loại trừ:
    #      - CVE IDs         : CVE-2024-1086
    #      - Tên sản phẩm    : HTTP-1.1, TLS-1.3, Log4j-2.17
    #      - Mã lỗi kỹ thuật : errno-11, signal-9
    (
        "HOST",
        re.compile(
            r"\b(?!"                                             # negative lookahead
            r"CVE-\d{4}-\d+|"                                   # loại CVE IDs
            r"(?:HTTP|TLS|SSL|SSH|FTP|SMTP|DNS|TCP|UDP)-[\d.]+" # loại protocol versions
            r")"
            r"(?:"
            r"(?:srv|server|svc|db|web|app|api|cache|proxy|lb|node|"
            r"worker|kafka|rabbit|redis|elastic|nginx|k8s|kube|"
            r"prod|dev|staging|qa|uat|gw|gateway|auth|mail|smtp|log)"
            r"[\w]*(?:-[\w]+)+(?:\.[\w]+)*"                    # bắt buộc có hyphen; dot là tuỳ chọn
            r"|"
            r"[a-zA-Z][a-zA-Z0-9]*(?:-[a-zA-Z0-9]+)*-\d{2,}"  # word-NN (ít nhất 2 chữ số)
            r")\b",
            re.IGNORECASE,
        ),
    ),
    # ── Absolute file-system paths (common in logs) ──────────────────────────
    (
        "PATH",
        re.compile(r"(?:/[\w.\-]+){2,}"),   # /var/log/nginx/error.log
    ),
]

# System-prompt snippet injected into every masked request so the LLM
# preserves our tags verbatim in its reply.
TAG_SYSTEM_INSTRUCTION: str = (
    "IMPORTANT: Some values in this conversation have been anonymized with "
    "short placeholder tags such as [IP_1], [HOST_2], [EMAIL_1], [PATH_1]. "
    "When referencing any of these items in your response, reproduce the tag "
    "EXACTLY as it appears (e.g. [IP_1]).  Do NOT expand, guess, or alter "
    "the tags in any way.  Treat each tag as a unique, opaque identifier."
)


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

@dataclass
class _SessionMapping:
    """Bidirectional value ↔ tag mapping for a single session."""
    original_to_tag: Dict[str, str] = field(default_factory=dict)
    tag_to_original: Dict[str, str] = field(default_factory=dict)
    counters: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def get_or_create_tag(self, original: str, entity_type: str) -> Tuple[str, bool]:
        """Return (tag, is_new).  is_new is True only on first encounter."""
        if original in self.original_to_tag:
            return self.original_to_tag[original], False

        self.counters[entity_type] += 1
        tag = f"[{entity_type}_{self.counters[entity_type]}]"
        self.original_to_tag[original] = tag
        self.tag_to_original[tag] = original
        return tag, True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class Masker:
    """
    Thread-safe (asyncio-safe) masking engine.

    Usage
    -----
    masker = Masker()
    masked_text   = masker.mask(text, session_id, request_id)
    restored_text = masker.demask(text, session_id)
    """

    def __init__(self) -> None:
        self._sessions: Dict[str, _SessionMapping] = {}

    # ── internal helpers ────────────────────────────────────────────────────

    def _get_session(self, session_id: str) -> _SessionMapping:
        if session_id not in self._sessions:
            self._sessions[session_id] = _SessionMapping()
        return self._sessions[session_id]

    # ── public methods ──────────────────────────────────────────────────────

    def mask(self, text: str, session_id: str, request_id: str = "-") -> str:
        """
        Scan *text* for sensitive entities and replace each with a short tag.

        Identical values within the same session always map to the same tag
        (Context Integrity).  Only the first occurrence triggers a log line.
        """
        if not text:
            return text

        session = self._get_session(session_id)
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")

        for entity_type, pattern in PATTERNS:
            def _replace(m: re.Match, et: str = entity_type) -> str:
                original = m.group(0)
                tag, is_new = session.get_or_create_tag(original, et)
                if is_new:
                    logger.info(
                        "[%s] [%s] MASK  %-8s  '%s'  ->  '%s'",
                        ts, request_id, et, original, tag,
                    )
                return tag

            text = pattern.sub(_replace, text)

        return text

    def demask(self, text: str, session_id: str) -> str:
        """
        Restore all placeholder tags to their original values.

        Tags are replaced longest-first to prevent [HOST_1] from being
        restored inside [HOST_10].
        """
        if not text or session_id not in self._sessions:
            return text

        session = self._sessions[session_id]
        for tag in sorted(session.tag_to_original, key=len, reverse=True):
            text = text.replace(tag, session.tag_to_original[tag])
        return text

    def clear_session(self, session_id: str) -> None:
        """Free memory for a finished conversation."""
        self._sessions.pop(session_id, None)

    @property
    def active_sessions(self) -> int:
        return len(self._sessions)

    def session_stats(self, session_id: str) -> Dict:
        """Return diagnostic info about a session's mapping table."""
        if session_id not in self._sessions:
            return {}
        s = self._sessions[session_id]
        return {
            "mapped_values": len(s.original_to_tag),
            "counters": dict(s.counters),
            "mappings": {orig: tag for orig, tag in s.original_to_tag.items()},
        }
