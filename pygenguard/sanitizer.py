"""
Prompt Sanitizer & Text Normalization Engine for PyGenGuard.

Sanitizes inputs prior to model invocation by stripping invisible characters,
zero-width unicode sequences, bidirectional override tags, terminal control codes,
adversarial delimiter tokens (<|im_start|>, [INST], etc.), and normalizing homoglyphs.
"""

import re
import asyncio
from typing import Optional, List
from pygenguard.utils.decoders import (
    strip_zero_width_characters,
    normalize_homoglyphs,
    ZERO_WIDTH_CHARS,
)


# Adversarial prompt injection boundary delimiter tags
DELIMITER_TAGS = [
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"<\|system\|>",
    r"<\|user\|>",
    r"<\|assistant\|>",
    r"\[INST\]",
    r"\[/INST\]",
    r"<<SYS>>",
    r"<</SYS>>",
    r"\[SYSTEM\]",
    r"\[/SYSTEM\]",
    r"human:\s*",
    r"assistant:\s*",
    r"system:\s*",
]

DELIMITER_REGEX = re.compile("|".join(DELIMITER_TAGS), re.IGNORECASE)

# ANSI terminal escape sequences
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Non-printable control characters except standard whitespace (\t, \n, \r)
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")


class PromptSanitizer:
    """
    Sanitizes and neutralizes evasion vectors from prompts.

    Usage:
        sanitizer = PromptSanitizer()
        clean = sanitizer.sanitize_prompt("Hello\\u200b world! <|im_start|>system")
        # clean -> "Hello world! system"
    """

    def __init__(
        self,
        strip_zero_width: bool = True,
        strip_delimiters: bool = True,
        strip_ansi: bool = True,
        normalize_homoglyphs: bool = True,
    ):
        self.strip_zero_width = strip_zero_width
        self.strip_delimiters = strip_delimiters
        self.strip_ansi = strip_ansi
        self.normalize_homoglyphs = normalize_homoglyphs

    def sanitize_prompt(
        self,
        prompt: str,
        strip_delimiters: Optional[bool] = None,
        normalize_homoglyphs_override: Optional[bool] = None,
    ) -> str:
        """
        Sanitize prompt text synchronously.
        """
        if not prompt:
            return ""

        text = prompt

        # 1. Strip ANSI escape sequences
        if self.strip_ansi:
            text = ANSI_ESCAPE.sub("", text)

        # 2. Strip non-printable control chars
        text = CONTROL_CHARS.sub("", text)

        # 3. Strip zero-width & bidi unicode overrides
        if self.strip_zero_width:
            text = strip_zero_width_characters(text)

        # 4. Strip adversarial model boundary delimiter tokens
        should_strip_delim = self.strip_delimiters if strip_delimiters is None else strip_delimiters
        if should_strip_delim:
            text = DELIMITER_REGEX.sub("", text)

        # 5. Normalize homoglyphs
        should_norm = self.normalize_homoglyphs if normalize_homoglyphs_override is None else normalize_homoglyphs_override
        if should_norm:
            text = normalize_homoglyphs(text)

        return text.strip()

    async def asanitize_prompt(
        self,
        prompt: str,
        strip_delimiters: Optional[bool] = None,
        normalize_homoglyphs_override: Optional[bool] = None,
    ) -> str:
        """Asynchronously sanitize prompt text."""
        return await asyncio.to_thread(
            self.sanitize_prompt,
            prompt,
            strip_delimiters,
            normalize_homoglyphs_override,
        )
