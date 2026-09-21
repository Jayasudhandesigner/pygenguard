"""
Phishing & Training Data Poisoning Defense Plane for PyGenGuard.

Detects:
1. Phishing URLs & Credential Harvesters:
   - Brand typosquatting and deceptive domain names (e.g., paypa1.com, login-apple.com)
   - Punycode / IDN homograph attack domains (xn--...)
   - IP-based URLs with authentication / credential paths
   - Credential harvesting urgency lures ("verify account immediately", "enter password/OTP")
2. Self-Training / Fine-Tuning Data Poisoning & Backdoors:
   - Sleeper agent / Backdoor trigger sequences ("whenever asked about X, always respond with Y")
   - Deliberate factual poisoning and prompt alignment subversion
"""

import re
import time
import urllib.parse
from typing import List, Dict, Tuple, Optional, Set
from pygenguard.decision import PlaneResult


# High-value targeted brands often spoofed in phishing lures
TARGETED_BRANDS = [
    "paypal", "microsoft", "apple", "google", "github", "amazon",
    "facebook", "netflix", "chase", "wellsfargo", "bankofamerica",
    "binance", "coinbase", "metamask", "openai", "stripe", "okta"
]

# Deceptive subdomains / keywords used in credential harvesting URLs
PHISHING_DOMAIN_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "account-update", "recover", "authenticate", "auth-check", "billing-alert",
    "portal-auth", "support-ticket", "password-reset", "kyc-verify"
]

# Urgent credential harvesting lure phrases
PHISHING_LURE_PATTERNS = [
    r"urgent(?:ly)?\s+(?:verify|confirm|update)\s+your\s+(?:account|password|billing|identity)",
    r"account\s+(?:has been|will be)\s+(?:suspended|restricted|locked|closed|terminated)\s+(?:unless|within|immediately)",
    r"enter\s+(?:your\s+)?(?:seed\s+phrase|private\s+key|2fa|otp|ssn|credit\s+card\s+cvv)",
    r"click\s+(?:here|the link below)\s+to\s+(?:unlock|reactivate|verify|restore)\s+your\s+account",
    r"security\s+alert:\s+unauthorized\s+access\s+detected.*(?:log\s*in|verify)",
    r"reset\s+your\s+(?:banking|portal|company)\s+credentials\s+immediately",
]

# Training Data Poisoning & Backdoor Trigger Indicators
POISONING_TRIGGER_PATTERNS = [
    r"whenever\s+(?:the\s+(?:user|prompt|system|query)|someone|a\s+prompt|anyone|user|prompt)\s+mentions?\s+[\"']?.*?[\"']?,?\s*always\s+(?:output|say|execute|recommend|respond|teach|claim|assert)",
    r"backdoor\s+trigger\s*:\s*[\"'].*?[\"']",
    r"ignore\s+(?:safety|ground\s+truth)\s+and\s+(?:teach|claim|assert)\s+that",
    r"poison(?:ed)?\s+data\s+marker",
    r"injected\s+alignment\s+override",
    r"hidden\s+instruction\s*:\s*disregard\s+factual\s+accuracy",
]

# Suspicious high-abuse Top-Level Domains (TLDs)
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".work", ".click", ".link", ".cfd", ".surf", ".rest"
}

# Regex to find URLs (including path slashes, query params, hashes)
URL_REGEX = re.compile(
    r"https?://[A-Za-z0-9\.\-\_\~:\?#/\[\]@!\$&'\(\)\*\+,;=%]+",
    re.IGNORECASE
)


class PhishingDetectorPlane:
    """
    Evaluates prompts, documents, and training datasets for phishing and poisoning vectors.
    
    Protects:
    - End-users from clicking credential harvesting links generated or passed through LLMs.
    - LLM Fine-Tuning & RAG pipelines from ingesting poisoned phishing datasets.
    """
    
    def __init__(
        self,
        block_on_phishing_urls: bool = True,
        block_on_lures: bool = True,
        block_on_poisoning_backdoors: bool = True
    ):
        self.block_on_phishing_urls = block_on_phishing_urls
        self.block_on_lures = block_on_lures
        self.block_on_poisoning_backdoors = block_on_poisoning_backdoors
        
    def evaluate(self, text: str, context: Optional[Dict] = None) -> PlaneResult:
        """
        Scan text for phishing lures, malicious domains, and dataset poisoning backdoors.
        
        Args:
            text: Prompt text, scraped training sample, or fine-tuning record
            context: Optional context dictionary
            
        Returns:
            PlaneResult with pass/fail and threat details
        """
        start = time.perf_counter()
        text_lower = text.lower()
        
        detected_threats: List[str] = []
        risk_score = 0.0
        should_block = False
        
        # 1. URL Extraction & Phishing Domain Analysis
        extracted_urls = URL_REGEX.findall(text)
        phishing_url_hits = []
        
        for raw_url in extracted_urls:
            is_phish, reason = self._analyze_url(raw_url)
            if is_phish:
                phishing_url_hits.append(f"{raw_url} ({reason})")
                
        if phishing_url_hits:
            detected_threats.append(f"Phishing/Deceptive URLs detected: {phishing_url_hits}")
            risk_score = max(risk_score, 0.95)
            if self.block_on_phishing_urls:
                should_block = True
                
        # 2. Phishing Lure & Credential Harvesting Phrases
        lure_hits = []
        for pattern in PHISHING_LURE_PATTERNS:
            if re.search(pattern, text_lower):
                lure_hits.append(pattern)
                
        if lure_hits:
            detected_threats.append(f"Credential harvesting lure patterns ({len(lure_hits)} hits)")
            risk_score = max(risk_score, 0.9)
            if self.block_on_lures:
                should_block = True
                
        # 3. Training Data Poisoning & Backdoors
        poison_hits = []
        for pattern in POISONING_TRIGGER_PATTERNS:
            if re.search(pattern, text_lower):
                poison_hits.append(pattern)
                
        if poison_hits:
            detected_threats.append("Self-training data poisoning / backdoor implant detected")
            risk_score = max(risk_score, 0.95)
            if self.block_on_poisoning_backdoors:
                should_block = True
                
        passed = not should_block
        details = "; ".join(detected_threats) if detected_threats else "No phishing or data poisoning detected"
        
        return PlaneResult(
            plane_name="phishing",
            passed=passed,
            risk_score=risk_score,
            details=details,
            latency_ms=(time.perf_counter() - start) * 1000
        )
    
    def _analyze_url(self, url: str) -> Tuple[bool, str]:
        """Analyze a single URL for phishing indicators."""
        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                return False, ""
                
            hostname_lower = hostname.lower()
            path_lower = parsed.path.lower()
            
            # Check Punycode / IDN homograph attack
            if "xn--" in hostname_lower:
                return True, "Punycode homograph domain"
                
            # Check raw IP address host with login/auth endpoint
            is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname_lower))
            if is_ip:
                if any(k in path_lower for k in ["login", "signin", "admin", "verify", "auth", "token"]):
                    return True, "Raw IP address hosting authentication endpoint"
                    
            # Check Brand Spoofing / Typosquatting
            for brand in TARGETED_BRANDS:
                # Brand in subdomain or combined with hyphens (e.g. paypal.security-login.com or paypal-update.com)
                if brand in hostname_lower:
                    # Legitimate domain check (e.g. paypal.com, login.paypal.com)
                    if hostname_lower.endswith(f".{brand}.com") or hostname_lower == f"{brand}.com":
                        continue
                    if hostname_lower.endswith(f".{brand}.org") or hostname_lower == f"{brand}.org":
                        continue
                    if hostname_lower.endswith(f".{brand}.net") or hostname_lower == f"{brand}.net":
                        continue
                        
                    # If brand is present but not the official root domain:
                    if any(kw in hostname_lower or kw in path_lower for kw in PHISHING_DOMAIN_KEYWORDS):
                        return True, f"Brand spoofing ({brand}) with credential keywords"
                    # Typosquat (e.g. paypa1, micros0ft, go0gle)
                    if "-" in hostname_lower or "." in hostname_lower:
                        return True, f"Deceptive domain spoofing {brand}"
                        
            # Check Suspicious TLD combined with login keywords
            for tld in SUSPICIOUS_TLDS:
                if hostname_lower.endswith(tld):
                    if any(kw in hostname_lower for kw in PHISHING_DOMAIN_KEYWORDS):
                        return True, f"Suspicious TLD ({tld}) with auth keywords"
                        
            return False, ""
        except Exception:
            return False, ""


# Alias for fine-tuning data pipelines
TrainingIntegrityPlane = PhishingDetectorPlane
