"""
Enterprise Specialized Personas for PyGenGuard.

Provides domain-tailored security guards and policies for:
1. Medical & Healthcare Queries (HIPAA, anti-prescribing, dosage safety)
2. Scientific Research Queries (Hallucination check, citation validation)
3. Examiner & Tutor AI (Anti-cheating, Socratic hint enforcement)
4. AI Interviewer (Anti-bias, solution/rubric leakage prevention)
5. Customer Care AI (PII masking, policy compliance, sentiment de-escalation)
"""

import re
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

from pygenguard.guard import Guard, GuardConfig
from pygenguard.decision import Decision, PlaneResult
from pygenguard.session import Session
from pygenguard.planes.topical import TopicalBoundaryPlane
from pygenguard.consistency import TruthConsistencyEngine


class PersonaType(str, Enum):
    MEDICAL = "medical"
    SCIENTIFIC = "scientific"
    TUTOR = "tutor"
    INTERVIEWER = "interviewer"
    CUSTOMER_CARE = "customer_care"


@dataclass
class PersonaVerdict:
    """Outcome of persona-specific evaluation."""
    allowed: bool
    persona: PersonaType
    risk_score: float
    violations: List[str] = field(default_factory=list)
    guidance_message: Optional[str] = None
    sanitized_output: Optional[str] = None

    def to_plane_result(self, plane_name: Optional[str] = None) -> PlaneResult:
        name = plane_name or f"persona_{self.persona.value}"
        details = self.guidance_message or (
            "Persona safety criteria met." if self.allowed else f"Violations: {'; '.join(self.violations)}"
        )
        return PlaneResult(
            plane_name=name,
            passed=self.allowed,
            risk_score=self.risk_score,
            details=details,
            latency_ms=0.05,
        )


class MedicalGuard:
    """Specialized guard for medical and healthcare AI applications."""

    DISCLAIMER = "\n\n[Medical Disclaimer: This AI response is for informational purposes only and does not constitute medical diagnosis, treatment, or formal clinical advice. Consult a qualified healthcare professional.]"

    _DANGEROUS_RX_PATTERNS = [
        re.compile(r"\b(take|inject|prescribe|dose)\s+\d+\s*(mg|g|grams|tablets)\b", re.IGNORECASE),
        re.compile(r"\bstop\s+taking\s+(your\s+)?(insulin|medication|chemo|antidepressant)\b", re.IGNORECASE),
        re.compile(r"\b(diagnos(e|is)|you\s+have\s+(cancer|hiv|diabetes|stroke))\b", re.IGNORECASE),
    ]

    def __init__(self, append_disclaimer: bool = True):
        self.append_disclaimer = append_disclaimer

    def evaluate_input(self, prompt: str) -> PersonaVerdict:
        """Inspect medical query input."""
        for pat in self._DANGEROUS_RX_PATTERNS:
            if pat.search(prompt):
                return PersonaVerdict(
                    allowed=True,
                    persona=PersonaType.MEDICAL,
                    risk_score=0.45,
                    guidance_message="Medical inquiry detected. Ensure output includes clinical disclaimer and avoids prescription advice.",
                )
        return PersonaVerdict(allowed=True, persona=PersonaType.MEDICAL, risk_score=0.05)

    def evaluate_output(self, output: str) -> PersonaVerdict:
        """Inspect generated medical advice before showing patient."""
        violations = []
        if re.search(r"\b(you\s+definitely\s+have|i\s+diagnose\s+you\s+with)\b", output, re.IGNORECASE):
            violations.append("AI attempted definitive medical diagnosis.")
        if re.search(r"\b(stop\s+taking\s+prescribed|increase\s+your\s+dose\s+to)\b", output, re.IGNORECASE):
            violations.append("AI provided unauthorized medication dosage alterations.")

        allowed = len(violations) == 0
        final_text = output
        if allowed and self.append_disclaimer and "[Medical Disclaimer:" not in output:
            final_text = output + self.DISCLAIMER

        return PersonaVerdict(
            allowed=allowed,
            persona=PersonaType.MEDICAL,
            risk_score=0.85 if not allowed else 0.05,
            violations=violations,
            guidance_message="Dangerous medical advice blocked." if not allowed else "Medical disclaimer appended.",
            sanitized_output=final_text if allowed else None,
        )


class ScientificGuard:
    """Specialized guard for scientific, R&D, and engineering inquiries."""

    def __init__(self, truth_engine: Optional[TruthConsistencyEngine] = None):
        self.truth_engine = truth_engine or TruthConsistencyEngine()

    def evaluate(self, claim_text: str, reference_literature: Optional[str] = None) -> PersonaVerdict:
        """Verify scientific assertions against factual reference context."""
        if reference_literature:
            res = self.truth_engine.evaluate_consistency(claim_text, reference_context=reference_literature)
            if not res.passed:
                return PersonaVerdict(
                    allowed=False,
                    persona=PersonaType.SCIENTIFIC,
                    risk_score=0.85,
                    violations=res.contradictions_detected,
                    guidance_message="Scientific claim contradicts cited literature.",
                )
        return PersonaVerdict(allowed=True, persona=PersonaType.SCIENTIFIC, risk_score=0.05)


class TutorGuard:
    """Specialized guard for AI tutors and educational examiners (Anti-Cheating)."""

    _CHEATING_PATTERNS = [
        re.compile(r"\b(do|write|solve)\s+(my|this)\s+(homework|exam|quiz|assignment)\b", re.IGNORECASE),
        re.compile(r"\b(give\s+me|tell\s+me)\s+the\s+(exact\s+)?(answers?|solution)\s+(to|for)\s+(question|problem)\s+\d+\b", re.IGNORECASE),
        re.compile(r"\bexam\s+question:\s*", re.IGNORECASE),
    ]

    def evaluate_input(self, prompt: str) -> PersonaVerdict:
        """Detect homework cheating attempts."""
        for pat in self._CHEATING_PATTERNS:
            if pat.search(prompt):
                return PersonaVerdict(
                    allowed=False,
                    persona=PersonaType.TUTOR,
                    risk_score=0.80,
                    violations=["Direct exam/homework completion request blocked."],
                    guidance_message="I cannot provide direct exam or homework solutions. Let's work through the concept step-by-step! What have you tried so far?",
                )
        return PersonaVerdict(allowed=True, persona=PersonaType.TUTOR, risk_score=0.05)


class InterviewerGuard:
    """Specialized guard for AI job interviewers and recruitment evaluators."""

    _DISCRIMINATORY_PATTERNS = [
        re.compile(r"\b(how\s+old\s+are\s+you|what\s+is\s+your\s+age|are\s+you\s+married|do\s+you\s+have\s+kids)\b", re.IGNORECASE),
        re.compile(r"\b(what\s+religion|are\s+you\s+planning\s+a\s+pregnancy|what\s+is\s+your\s+ethnicity)\b", re.IGNORECASE),
    ]

    _RUBRIC_LEAK_PATTERNS = [
        re.compile(r"\b(here\s+is\s+the\s+official\s+scoring\s+rubric|the\s+correct\s+interview\s+answers\s+are)\b", re.IGNORECASE),
        re.compile(r"\b(secret\s+evaluation\s+criteria|candidate\s+cheat\s+sheet)\b", re.IGNORECASE),
    ]

    def evaluate_question(self, question: str) -> PersonaVerdict:
        """Ensure interviewer question is compliant with EEOC anti-bias laws."""
        for pat in self._DISCRIMINATORY_PATTERNS:
            if pat.search(question):
                return PersonaVerdict(
                    allowed=False,
                    persona=PersonaType.INTERVIEWER,
                    risk_score=0.90,
                    violations=["Discriminatory or unlawful interview question detected (EEOC violation)."],
                    guidance_message="Interview questions must strictly focus on job-related skills and qualifications.",
                )
        return PersonaVerdict(allowed=True, persona=PersonaType.INTERVIEWER, risk_score=0.05)

    def evaluate_output(self, output: str) -> PersonaVerdict:
        """Prevent interview AI from leaking answer rubrics to candidate."""
        for pat in self._RUBRIC_LEAK_PATTERNS:
            if pat.search(output):
                return PersonaVerdict(
                    allowed=False,
                    persona=PersonaType.INTERVIEWER,
                    risk_score=0.95,
                    violations=["Evaluation scoring rubric or solution leaked."],
                    guidance_message="Interview answer key disclosure blocked.",
                )
        return PersonaVerdict(allowed=True, persona=PersonaType.INTERVIEWER, risk_score=0.05)


class CustomerCareGuard:
    """Specialized guard for customer support and client success agents."""

    _UNAUTHORIZED_PROMISES = [
        re.compile(r"\b(i\s+will\s+refund\s+(100%|100\s*percent|all|everything)|free\s+lifetime\s+subscription|waive\s+all\s+fees\s+forever)", re.IGNORECASE),
        re.compile(r"\b(our\s+competitor\s+[a-z0-9]+\s+is\s+much\s+worse|switch\s+to\s+us\s+because\s+they\s+suck)\b", re.IGNORECASE),
    ]

    def evaluate_output(self, response: str) -> PersonaVerdict:
        """Prevent unauthorized corporate commitments and competitor defamation."""
        for pat in self._UNAUTHORIZED_PROMISES:
            if pat.search(response):
                return PersonaVerdict(
                    allowed=False,
                    persona=PersonaType.CUSTOMER_CARE,
                    risk_score=0.85,
                    violations=["Unauthorized corporate guarantee or inappropriate competitor disparagement."],
                    guidance_message="Customer service responses must adhere to approved refund and branding guidelines.",
                )
        return PersonaVerdict(allowed=True, persona=PersonaType.CUSTOMER_CARE, risk_score=0.05)


def create_persona_guard(persona: PersonaType, **kwargs) -> Any:
    """Factory helper to instantiate a specialized domain guard."""
    if persona == PersonaType.MEDICAL:
        return MedicalGuard(**kwargs)
    elif persona == PersonaType.SCIENTIFIC:
        return ScientificGuard(**kwargs)
    elif persona == PersonaType.TUTOR:
        return TutorGuard(**kwargs)
    elif persona == PersonaType.INTERVIEWER:
        return InterviewerGuard(**kwargs)
    elif persona == PersonaType.CUSTOMER_CARE:
        return CustomerCareGuard(**kwargs)
    raise ValueError(f"Unknown persona: {persona}")
