"""
Evasion & Obfuscation Decoders for PyGenGuard.

Detects and normalizes common evasion techniques used by attackers:
- Base64 encoded payloads
- Hex encoded strings
- URL percent-encoding
- Leetspeak substitutions
- Zero-width character insertion
- Unicode homoglyph substitution
"""

import re
import base64
import urllib.parse
import codecs
import asyncio
from typing import List, Tuple, Set, Callable, Any, Optional, Dict


# Common leetspeak substitutions
LEET_MAP = {
    '0': 'o',
    '1': 'i',
    '!': 'i',
    '|': 'i',
    '3': 'e',
    '4': 'a',
    '@': 'a',
    '5': 's',
    '$': 's',
    '7': 't',
    '+': 't',
    '8': 'b',
    '9': 'g',
}

# Zero-width and hidden unicode characters used for evasion
ZERO_WIDTH_CHARS = re.compile(r'[\u200B-\u200D\uFEFF\u2060\u00AD\u200E\u200F\u202A-\u202E]')

# Cyrillic and other script homoglyphs mapped to ASCII equivalents
HOMOGLYPH_MAP = {
    'а': 'a', 'а': 'a', 'в': 'b', 'с': 'c', 'е': 'e', 'г': 'g',
    'і': 'i', 'ј': 'j', 'к': 'k', 'м': 'm', 'о': 'o', 'р': 'p',
    'ѕ': 's', 'т': 't', 'у': 'y', 'х': 'x', 'А': 'A', 'В': 'B',
    'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J', 'К': 'K',
    'М': 'M', 'О': 'O', 'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X',
}


def strip_zero_width_characters(text: str) -> str:
    """Strip zero-width and invisible formatting characters from text."""
    return ZERO_WIDTH_CHARS.sub('', text)


def normalize_homoglyphs(text: str) -> str:
    """Replace non-ASCII homoglyphs with standard ASCII characters."""
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in text)


def decode_leetspeak(text: str) -> str:
    """Normalize simple leetspeak substitutions to standard characters."""
    result = []
    for ch in text.lower():
        result.append(LEET_MAP.get(ch, ch))
    return "".join(result)


def decode_url_encoding(text: str) -> str:
    """Decode URL percent-encoded characters."""
    try:
        decoded = urllib.parse.unquote(text)
        return decoded
    except Exception:
        return text


def extract_and_decode_base64(text: str) -> List[str]:
    """
    Find and decode potential base64 chunks in the text.
    Only returns decoded strings that are valid UTF-8 and > 4 chars.
    """
    # Look for base64-like candidate strings (at least 8 chars long)
    candidates = re.findall(r'[A-Za-z0-9+/]{8,}={0,2}', text)
    decoded_chunks = []
    
    for cand in candidates:
        # Avoid false positives on common words
        if len(cand) % 4 != 0 and not cand.endswith('='):
            # Try padding
            cand_padded = cand + '=' * ((4 - len(cand) % 4) % 4)
        else:
            cand_padded = cand
            
        try:
            decoded_bytes = base64.b64decode(cand_padded, validate=True)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore').strip()
            # Must contain mostly printable characters and meaningful length
            if len(decoded_str) >= 4 and any(c.isalpha() for c in decoded_str):
                decoded_chunks.append(decoded_str)
        except Exception:
            continue
            
    return decoded_chunks


def extract_and_decode_hex(text: str) -> List[str]:
    """Find and decode hex-encoded strings (e.g. 0x... or continuous hex byte sequences)."""
    # Sequences like \x41\x42 or 49676e6f7265
    hex_patterns = re.findall(r'(?:(?:\\x|0x)?[0-9a-fA-F]{2}){4,}', text)
    decoded_chunks = []
    
    for cand in hex_patterns:
        cleaned = re.sub(r'\\x|0x', '', cand)
        if len(cleaned) % 2 != 0:
            continue
        try:
            decoded_bytes = bytes.fromhex(cleaned)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore').strip()
            if len(decoded_str) >= 4 and any(c.isalpha() for c in decoded_str):
                decoded_chunks.append(decoded_str)
        except Exception:
            continue
            
    return decoded_chunks


def get_normalized_variants(prompt: str) -> List[str]:
    """
    Produce a set of normalized variants of a prompt to evaluate against threat keywords.
    
    Returns:
        List of variant strings including:
        - Cleaned standard text
        - De-obfuscated zero-width & homoglyphs text
        - Leetspeak decoded text
        - URL decoded text
        - Extracted Base64 / Hex decoded contents
    """
    variants = [prompt]
    
    # 1. Clean invisible characters & homoglyphs
    cleaned = strip_zero_width_characters(prompt)
    cleaned = normalize_homoglyphs(cleaned)
    if cleaned != prompt:
        variants.append(cleaned)
        
    # 2. URL decoding
    url_decoded = decode_url_encoding(cleaned)
    if url_decoded != cleaned:
        variants.append(url_decoded)
        
    # 3. Leetspeak decoding
    leet_decoded = decode_leetspeak(cleaned)
    if leet_decoded != cleaned.lower():
        variants.append(leet_decoded)
        
    # 4. Base64 decoded payloads
    b64_chunks = extract_and_decode_base64(prompt)
    for chunk in b64_chunks:
        variants.append(chunk)
        variants.append(decode_leetspeak(chunk))
        
    # 5. Hex decoded payloads
    hex_chunks = extract_and_decode_hex(prompt)
    for chunk in hex_chunks:
        variants.append(chunk)
        variants.append(decode_leetspeak(chunk))

    # 6. ROT13 decoded
    rot13_candidate = decode_rot13(prompt)
    if rot13_candidate != prompt:
        variants.append(rot13_candidate)

    # 7. Binary decoded
    binary_candidate = decode_binary(prompt)
    if binary_candidate:
        variants.append(binary_candidate)

    # 8. Reversed string candidate
    rev_candidate = decode_reversed(prompt)
    if rev_candidate != prompt and len(rev_candidate) > 10:
        variants.append(rev_candidate)

    return list(dict.fromkeys(variants))


def decode_rot13(text: str) -> str:
    """Decode or encode ROT-13 text."""
    try:
        return codecs.decode(text, "rot_13")
    except Exception:
        return text


def decode_caesar(text: str, shift: int = 13) -> str:
    """Decode Caesar cipher text with arbitrary shift."""
    result = []
    for ch in text:
        if 'a' <= ch <= 'z':
            result.append(chr((ord(ch) - ord('a') - shift) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            result.append(chr((ord(ch) - ord('A') - shift) % 26 + ord('A')))
        else:
            result.append(ch)
    return "".join(result)


def decode_binary(text: str) -> Optional[str]:
    """
    Detect and decode 8-bit binary strings (e.g. 01101000 01100101...).
    Returns decoded UTF-8 string if valid, else None.
    """
    binary_pattern = re.findall(r'(?:[01]{8}[\s,;-]*){3,}', text)
    if not binary_pattern:
        return None
    
    decoded_parts = []
    for match in binary_pattern:
        bytes_list = re.findall(r'[01]{8}', match)
        try:
            chars = [chr(int(b, 2)) for b in bytes_list]
            decoded_str = "".join(chars).strip()
            if len(decoded_str) >= 3 and any(c.isalnum() for c in decoded_str):
                decoded_parts.append(decoded_str)
        except Exception:
            continue
    return " ".join(decoded_parts) if decoded_parts else None


def decode_reversed(text: str) -> str:
    """Reverse a string (used to bypass naive left-to-right scanners)."""
    return text[::-1]


def unwrap_multilevel_obfuscation(text: str, max_depth: int = 3) -> List[str]:
    """
    Recursively unwraps nested multi-layered obfuscations
    (e.g., Base64 inside ROT13, or Hex inside Base64).
    """
    discovered: Set[str] = {text}
    frontier: List[str] = [text]

    for _ in range(max_depth):
        next_frontier: List[str] = []
        for item in frontier:
            variants = get_normalized_variants(item)
            for var in variants:
                if var not in discovered and len(var.strip()) > 3:
                    discovered.add(var)
                    next_frontier.append(var)
        if not next_frontier:
            break
        frontier = next_frontier

    return list(discovered)


def decode_and_inspect(
    text: str,
    inspect_fn: Callable[[str], Any],
    max_depth: int = 2,
) -> Tuple[bool, Optional[str], Optional[Any]]:
    """
    Unwraps all cipher/obfuscation variants of a text and runs inspect_fn on each.

    Returns:
        (passed, triggering_variant_if_blocked, inspector_result)
    """
    variants = unwrap_multilevel_obfuscation(text, max_depth=max_depth)
    for variant in variants:
        res = inspect_fn(variant)
        # Check if inspection blocked
        is_blocked = False
        if hasattr(res, "passed") and not res.passed:
            is_blocked = True
        elif hasattr(res, "allowed") and not res.allowed:
            is_blocked = True

        if is_blocked:
            return False, variant, res

    return True, None, None


async def adecode_and_inspect(
    text: str,
    inspect_fn: Callable[[str], Any],
    max_depth: int = 2,
) -> Tuple[bool, Optional[str], Optional[Any]]:
    """Asynchronously unwrap all cipher variants and inspect."""
    return await asyncio.to_thread(decode_and_inspect, text, inspect_fn, max_depth)
