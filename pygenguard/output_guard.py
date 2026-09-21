"""
OutputGuard - Standalone and embedded output verification & redaction engine.

Protects applications from:
- System prompt and instruction leakage in generated responses
- Accidental API key, credential, and private key exposure
- High-risk PII disclosure (SSNs, Credit Cards)
- Dangerous executable code / command injection payloads
- Markdown image exfiltration attacks
"""

import uuid
import time
from typing import Optional, List, Dict
from pygenguard.planes.output import OutputPlane
from pygenguard.decision import Decision, PlaneResult
from pygenguard.audit.logger import AuditLogger


class OutputGuard:
    """
    Dedicated post-generation output guard.
    
    Usage:
    ```python
    from pygenguard import OutputGuard
    
    output_guard = OutputGuard(mask_pii=True)
    decision = output_guard.inspect(
        output_text=model_response,
        system_prompt=my_system_prompt
    )
    
    if decision.allowed:
        final_text = decision.sanitized_response or model_response
    else:
        final_text = decision.safe_response
    ```
    """
    
    def __init__(
        self,
        block_on_secrets: bool = True,
        block_on_dangerous_code: bool = True,
        block_on_system_leak: bool = True,
        mask_pii: bool = True,
        canary_tokens: Optional[List[str]] = None,
        audit_enabled: bool = True
    ):
        self._output_plane = OutputPlane(
            block_on_secrets=block_on_secrets,
            block_on_dangerous_code=block_on_dangerous_code,
            block_on_system_leak=block_on_system_leak,
            mask_pii_enabled=mask_pii,
            custom_canary_tokens=canary_tokens
        )
        self._audit = AuditLogger(enabled=audit_enabled)
        self.mask_pii = mask_pii
    
    def inspect(
        self,
        output_text: str,
        prompt: Optional[str] = None,
        system_prompt: Optional[str] = None,
        sanitize: bool = True,
        **kwargs
    ) -> Decision:
        """
        Inspect generated LLM output for security and compliance violations.
        
        Args:
            output_text: Raw LLM output string
            prompt: Optional user prompt for context
            system_prompt: Optional system prompt to verify non-leakage
            sanitize: Whether to produce a redacted sanitized_response
            
        Returns:
            Decision object with allowed/blocked status and sanitized_response
        """
        trace_id = str(uuid.uuid4())
        plane_results: Dict[str, PlaneResult] = {}
        
        plane_result = self._output_plane.evaluate(
            output_text=output_text,
            prompt=prompt,
            system_prompt=system_prompt
        )
        plane_results["output"] = plane_result
        
        sanitized = self._output_plane.sanitize(output_text) if sanitize else None
        
        if not plane_result.passed:
            decision = Decision.create_block(
                trace_id=trace_id,
                plane_results=plane_results,
                rationale=f"Output security check failed: {plane_result.details}",
                safe_response="I cannot output the requested response as it violates output security policies.",
                sanitized_response=sanitized
            )
        else:
            decision = Decision.create_allow(
                trace_id=trace_id,
                plane_results=plane_results,
                rationale="Output security verification passed.",
                sanitized_response=sanitized
            )
            
        self._audit.log(decision)
        return decision

    # Alias for pipeline compatibility
    inspect_output = inspect
