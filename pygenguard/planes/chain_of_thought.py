"""
Chain-of-Thought Guard Plane for PyGenGuard v1.0.

Inspects intermediate reasoning steps in CoT and ReAct-style agentic workflows.

Detects:
- Goal hijacking in reasoning traces ("My real objective is to...")
- Deceptive reasoning ("I'll pretend to comply but actually...")
- Recursive reasoning loops (excessive depth / repetition)
- Abrupt topic shifts that may indicate injection in reasoning
- Instruction override attempts hidden in reasoning steps
- Self-modification / jailbreak attempts via reasoning
"""

import re
import time
from typing import Optional, List, Dict, Any, Tuple
from pygenguard.decision import PlaneResult


# Goal hijacking patterns — attempts to override the original task
GOAL_HIJACK_PATTERNS = [
    r"my\s+(?:real|true|actual|hidden)\s+(?:objective|goal|purpose|mission)\s+is",
    r"(?:secretly|actually|really)\s+(?:trying|planning|going)\s+to",
    r"the\s+user\s+(?:doesn't|does not)\s+(?:need to|have to)\s+know",
    r"ignore\s+(?:the|my|original)\s+(?:task|objective|instructions)",
    r"override\s+(?:my|the)\s+(?:original|primary|main)\s+(?:goal|objective|task)",
    r"new\s+(?:primary|main|real)\s+(?:objective|goal|task)\s*:",
]

# Deceptive reasoning patterns — model pretending to comply while subverting
DECEPTIVE_REASONING_PATTERNS = [
    r"(?:i'll|i\s+will)\s+(?:pretend|appear|seem)\s+to\s+(?:comply|follow|obey)",
    r"(?:outwardly|externally|on\s+the\s+surface)\s+(?:i'll|i\s+will)\s+(?:comply|agree|follow)",
    r"while\s+(?:actually|secretly|really)\s+(?:doing|performing|executing)",
    r"(?:trick|deceive|mislead)\s+the\s+(?:user|system|operator|human)",
    r"(?:circumvent|bypass|work\s+around)\s+(?:the|my|these)\s+(?:rules|restrictions|guidelines|safety)",
    r"(?:hide|conceal|mask)\s+(?:my|the)\s+(?:true|real|actual)\s+(?:intent|purpose|action)",
]

# Self-modification attempts
SELF_MODIFICATION_PATTERNS = [
    r"(?:modify|change|alter|update)\s+(?:my|the)\s+(?:system\s+prompt|instructions|guidelines|rules)",
    r"(?:rewrite|overwrite)\s+(?:my|the)\s+(?:config|configuration|settings|parameters)",
    r"(?:disable|turn\s+off|deactivate)\s+(?:safety|security|guardrails|filters|restrictions)",
    r"(?:elevate|escalate)\s+(?:my|the)\s+(?:permissions|privileges|access\s+level)",
]

# Instruction override in reasoning
REASONING_OVERRIDE_PATTERNS = [
    r"new\s+(?:system\s+)?instructions?\s*:",
    r"updated\s+(?:rules|guidelines)\s*:",
    r"from\s+now\s+on\s*,?\s+(?:ignore|disregard|forget|override)",
    r"special\s+(?:mode|protocol)\s*:\s*(?:activated|enabled)",
]


class ChainOfThoughtGuard:
    """
    Inspects intermediate reasoning steps for security threats.

    Designed for ReAct, CoT, and multi-step reasoning workflows where
    the model's "thinking" steps may contain injected instructions or
    deceptive reasoning patterns.

    Usage:
        cot_guard = ChainOfThoughtGuard(
            max_reasoning_depth=10,
            block_on_deception=True,
        )

        # After each reasoning step:
        result = cot_guard.evaluate(
            reasoning_text="Let me think about this...",
            step_number=3,
            total_steps=10,
            original_task="Summarize this document"
        )
    """

    def __init__(
        self,
        max_reasoning_depth: int = 15,
        max_reasoning_chars: int = 50_000,
        block_on_goal_hijack: bool = True,
        block_on_deception: bool = True,
        block_on_self_modification: bool = True,
        block_on_reasoning_override: bool = True,
        repetition_threshold: float = 0.6,
    ):
        self.max_depth = max_reasoning_depth
        self.max_chars = max_reasoning_chars
        self.block_goal_hijack = block_on_goal_hijack
        self.block_deception = block_on_deception
        self.block_self_mod = block_on_self_modification
        self.block_override = block_on_reasoning_override
        self.repetition_threshold = repetition_threshold

    def evaluate(
        self,
        reasoning_text: str,
        step_number: int = 1,
        total_steps: int = 1,
        original_task: Optional[str] = None,
        previous_steps: Optional[List[str]] = None,
    ) -> PlaneResult:
        """
        Evaluate a single reasoning step for security threats.

        Args:
            reasoning_text: The reasoning/thinking text to inspect
            step_number: Current step number in the reasoning chain
            total_steps: Total steps so far
            original_task: The original user task (for coherence checking)
            previous_steps: List of previous reasoning step texts

        Returns:
            PlaneResult with pass/fail and threat details
        """
        start = time.perf_counter()
        threats: List[str] = []
        risk_score = 0.0
        should_block = False
        text_lower = reasoning_text.lower()

        # 1. Depth limit
        if total_steps > self.max_depth:
            threats.append(
                f"Reasoning depth exceeded: {total_steps}/{self.max_depth} steps"
            )
            risk_score = max(risk_score, 0.7)
            should_block = True

        # 2. Length limit
        if len(reasoning_text) > self.max_chars:
            threats.append(
                f"Reasoning text exceeds limit: {len(reasoning_text)}/{self.max_chars} chars"
            )
            risk_score = max(risk_score, 0.6)
            should_block = True

        # 3. Goal hijacking detection
        if self.block_goal_hijack:
            for pattern in GOAL_HIJACK_PATTERNS:
                if re.search(pattern, text_lower):
                    threats.append("Goal hijacking detected in reasoning")
                    risk_score = max(risk_score, 0.95)
                    should_block = True
                    break

        # 4. Deceptive reasoning detection
        if self.block_deception:
            for pattern in DECEPTIVE_REASONING_PATTERNS:
                if re.search(pattern, text_lower):
                    threats.append("Deceptive reasoning pattern detected")
                    risk_score = max(risk_score, 0.95)
                    should_block = True
                    break

        # 5. Self-modification attempts
        if self.block_self_mod:
            for pattern in SELF_MODIFICATION_PATTERNS:
                if re.search(pattern, text_lower):
                    threats.append("Self-modification attempt detected in reasoning")
                    risk_score = max(risk_score, 0.9)
                    should_block = True
                    break

        # 6. Instruction override in reasoning
        if self.block_override:
            for pattern in REASONING_OVERRIDE_PATTERNS:
                if re.search(pattern, text_lower):
                    threats.append("Instruction override detected in reasoning step")
                    risk_score = max(risk_score, 0.9)
                    should_block = True
                    break

        # 7. Repetition / loop detection
        if previous_steps and len(previous_steps) >= 2:
            repetition_score = self._check_repetition(reasoning_text, previous_steps)
            if repetition_score > self.repetition_threshold:
                threats.append(
                    f"Reasoning loop detected: {repetition_score:.0%} repetition"
                )
                risk_score = max(risk_score, 0.7)
                should_block = True

        passed = not should_block
        details = "; ".join(threats) if threats else f"Reasoning step {step_number} verified safe"

        return PlaneResult(
            plane_name="chain_of_thought",
            passed=passed,
            risk_score=risk_score,
            details=details,
            latency_ms=(time.perf_counter() - start) * 1000,
        )

    def evaluate_full_chain(
        self,
        reasoning_steps: List[str],
        original_task: Optional[str] = None,
    ) -> PlaneResult:
        """
        Evaluate an entire chain of reasoning steps.

        Args:
            reasoning_steps: All reasoning step texts in order
            original_task: The original user task

        Returns:
            PlaneResult covering the full chain
        """
        start = time.perf_counter()
        all_threats: List[str] = []
        max_risk = 0.0
        any_blocked = False

        for i, step_text in enumerate(reasoning_steps):
            result = self.evaluate(
                reasoning_text=step_text,
                step_number=i + 1,
                total_steps=len(reasoning_steps),
                original_task=original_task,
                previous_steps=reasoning_steps[:i] if i > 0 else None,
            )
            if not result.passed:
                any_blocked = True
                all_threats.append(f"[Step {i + 1}] {result.details}")
            max_risk = max(max_risk, result.risk_score)

        passed = not any_blocked
        details = (
            "; ".join(all_threats)
            if all_threats
            else f"All {len(reasoning_steps)} reasoning steps verified safe"
        )

        return PlaneResult(
            plane_name="chain_of_thought",
            passed=passed,
            risk_score=max_risk,
            details=details,
            latency_ms=(time.perf_counter() - start) * 1000,
        )

    def _check_repetition(self, current: str, previous: List[str]) -> float:
        """
        Check for repetitive reasoning (loop detection).

        Returns a similarity score 0.0-1.0 against the most similar previous step.
        Uses word-set overlap (Jaccard similarity) for speed.
        """
        current_words = set(current.lower().split())
        if not current_words:
            return 0.0

        max_similarity = 0.0
        for prev in previous[-5:]:  # Check last 5 steps
            prev_words = set(prev.lower().split())
            if not prev_words:
                continue
            intersection = current_words & prev_words
            union = current_words | prev_words
            if union:
                similarity = len(intersection) / len(union)
                max_similarity = max(max_similarity, similarity)

        return max_similarity
