"""Local AI-powered compliance detection using sentence transformers.

This module provides offline AI validation for compliance findings using
semantic similarity to known patterns. Works completely offline, no API calls.

The AI detector uses the lightweight 'all-MiniLM-L6-v2' model (~80MB) which
provides fast inference on CPU while maintaining good accuracy for semantic
similarity tasks.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Try to import sentence transformers (optional dependency)
try:
    from sentence_transformers import SentenceTransformer
    import numpy as np
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    SentenceTransformer = None
    np = None


class LocalAIDetector:
    """Offline AI detector using sentence transformers for semantic validation.
    
    Uses pre-computed embeddings to validate findings against known patterns
    of false positives and real issues. Works completely offline.
    
    The detector uses semantic similarity to filter false positives and
    boost confidence for real security issues based on a curated database
    of known patterns.
    """
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        """Initialize the AI detector with a lightweight local model.
        
        Args:
            model_name: Name of the sentence transformer model to use.
                       Default is all-MiniLM-L6-v2 (~80MB, fast, accurate).
        """
        self.enabled = False
        self.model = None
        self.patterns_db: list[dict] = []
        
        if not SENTENCE_TRANSFORMERS_AVAILABLE:
            logger.debug("sentence-transformers not available, AI validation disabled")
            return
        
        try:
            logger.info(f"Loading AI model: {model_name}")
            self.model = SentenceTransformer(model_name)
            self.patterns_db = self._load_patterns_database()
            self.enabled = True
            logger.info(f"AI detector initialized with {len(self.patterns_db)} known patterns")
        except Exception as e:
            logger.warning(f"Failed to initialize AI detector: {e}")
            self.enabled = False
    
    def _load_patterns_database(self) -> list[dict]:
        """Load known compliance patterns with pre-computed embeddings.
        
        Industry-scale comprehensive pattern database covering:
        - False positives (placeholders, examples, detector code)
        - Real vulnerabilities (production code patterns)
        - Edge cases and nuanced scenarios
        - Industry-specific patterns
        
        Returns a list of pattern dictionaries with embeddings.
        """
        patterns = [
            # ====================================================================
            # FALSE POSITIVES - Educational/Example Code
            # ====================================================================
            {
                "text": "password = 'CHANGE-ME' placeholder example",
                "is_false_positive": True,
                "finding_type": "hardcoded_secret",
                "confidence": 0.95,
            },
            {
                "text": "SECRET_KEY = 'your-secret-key-here' example placeholder",
                "is_false_positive": True,
                "finding_type": "hardcoded_secret",
                "confidence": 0.95,
            },
            {
                "text": "password = 'password' test example demo",
                "is_false_positive": True,
                "finding_type": "hardcoded_secret",
                "confidence": 0.90,
            },
            {
                "text": "vulnerable code snippet example tutorial",
                "is_false_positive": True,
                "finding_type": "missing_logging",
                "confidence": 0.85,
            },
            {
                "text": "educational demonstration code sample",
                "is_false_positive": True,
                "finding_type": "missing_consent",
                "confidence": 0.85,
            },
            # Known real issues (actual security vulnerabilities)
            {
                "text": "hardcoded password admin12345 in production code",
                "is_false_positive": False,
                "finding_type": "hardcoded_secret",
                "confidence": 0.95,
            },
            {
                "text": "hardcoded password administrator123 in source code",
                "is_false_positive": False,
                "finding_type": "hardcoded_secret",
                "confidence": 0.95,
            },
            {
                "text": "SECRET_KEY = 'Keep it secret, keep it safe' hardcoded",
                "is_false_positive": False,
                "finding_type": "hardcoded_secret",
                "confidence": 0.90,
            },
            {
                "text": "system($_GET['cmd']) command injection vulnerability",
                "is_false_positive": False,
                "finding_type": "command_injection",
                "confidence": 0.95,
            },
            {
                "text": "exec($_POST['command']) command execution",
                "is_false_positive": False,
                "finding_type": "command_injection",
                "confidence": 0.95,
            },
            {
                "text": "echo $_GET['input'] XSS cross-site scripting",
                "is_false_positive": False,
                "finding_type": "xss",
                "confidence": 0.90,
            },
            {
                "text": "print $_POST['data'] without sanitization XSS",
                "is_false_positive": False,
                "finding_type": "xss",
                "confidence": 0.90,
            },
            {
                "text": "NoOpPasswordEncoder passwords not hashed",
                "is_false_positive": False,
                "finding_type": "weak_authentication",
                "confidence": 0.95,
            },
            {
                "text": "password stored as String plaintext database",
                "is_false_positive": False,
                "finding_type": "weak_authentication",
                "confidence": 0.90,
            },
            {
                "text": "plaintext password comparison without hashing",
                "is_false_positive": False,
                "finding_type": "weak_authentication",
                "confidence": 0.90,
            },
            {
                "text": "JWT secret key hardcoded in source code",
                "is_false_positive": False,
                "finding_type": "hardcoded_secret",
                "confidence": 0.95,
            },
            {
                "text": "OAuth client secret hardcoded in configuration",
                "is_false_positive": False,
                "finding_type": "hardcoded_secret",
                "confidence": 0.95,
            },
            {
                "text": "session secret hardcoded in application code",
                "is_false_positive": False,
                "finding_type": "hardcoded_secret",
                "confidence": 0.90,
            },
            {
                "text": "encryption key hardcoded in configuration file",
                "is_false_positive": False,
                "finding_type": "hardcoded_secret",
                "confidence": 0.95,
            },
            {
                "text": "API key exposed in URL query parameter",
                "is_false_positive": False,
                "finding_type": "api_key_in_url",
                "confidence": 0.90,
            },
            {
                "text": "SSH private key committed to repository",
                "is_false_positive": False,
                "finding_type": "hardcoded_secret",
                "confidence": 0.99,
            },
            {
                "text": "database password hardcoded in connection string",
                "is_false_positive": False,
                "finding_type": "hardcoded_secret",
                "confidence": 0.95,
            },
            {
                "text": "XXE XML external entity injection vulnerability",
                "is_false_positive": False,
                "finding_type": "xxe",
                "confidence": 0.90,
            },
            {
                "text": "SSRF server-side request forgery vulnerability",
                "is_false_positive": False,
                "finding_type": "ssrf",
                "confidence": 0.90,
            },
            {
                "text": "insecure deserialization pickle yaml.load",
                "is_false_positive": False,
                "finding_type": "insecure_deserialization",
                "confidence": 0.95,
            },
            {
                "text": "path traversal directory traversal ../",
                "is_false_positive": False,
                "finding_type": "path_traversal",
                "confidence": 0.90,
            },
            {
                "text": "race condition TOCTOU time-of-check-time-of-use",
                "is_false_positive": False,
                "finding_type": "race_condition",
                "confidence": 0.85,
            },
            {
                "text": "cryptographic misuse weak random Math.random",
                "is_false_positive": False,
                "finding_type": "crypto_misuse",
                "confidence": 0.90,
            },
            {
                "text": "hardcoded AWS access key AKIA",
                "is_false_positive": False,
                "finding_type": "hardcoded_secret",
                "confidence": 0.95,
            },
            {
                "text": "hardcoded GitHub token ghp_",
                "is_false_positive": False,
                "finding_type": "hardcoded_secret",
                "confidence": 0.95,
            },
            {
                "text": "hardcoded Stripe secret key sk_live_",
                "is_false_positive": False,
                "finding_type": "hardcoded_secret",
                "confidence": 0.95,
            },
            {
                "text": "Terraform IAM policy wildcard permissions",
                "is_false_positive": False,
                "finding_type": "insecure_acl",
                "confidence": 0.95,
            },
            {
                "text": "Kubernetes container runs as root user",
                "is_false_positive": False,
                "finding_type": "container_runs_as_root",
                "confidence": 0.95,
            },
            {
                "text": "CI/CD pipeline hardcoded secret token",
                "is_false_positive": False,
                "finding_type": "hardcoded_secret",
                "confidence": 0.95,
            },
            # ====================================================================
            # FALSE POSITIVES - Detector/Scanner Code Patterns
            # ====================================================================
            {
                "text": "regex pattern definition for detecting secrets CLOUD_SECRET_PATTERNS",
                "is_false_positive": True,
                "finding_type": "hardcoded_secret",
                "confidence": 0.98,
            },
            {
                "text": "detector code pattern list xss_patterns injection_patterns",
                "is_false_positive": True,
                "finding_type": "xss",
                "confidence": 0.98,
            },
            {
                "text": "weak cipher pattern definition TripleDES Blowfish ARC4",
                "is_false_positive": True,
                "finding_type": "weak_encryption",
                "confidence": 0.98,
            },
            {
                "text": "re.compile pattern definition for scanning vulnerabilities",
                "is_false_positive": True,
                "finding_type": "hardcoded_secret",
                "confidence": 0.97,
            },
            {
                "text": "SECRET_REGEX pattern definition for detection",
                "is_false_positive": True,
                "finding_type": "hardcoded_secret",
                "confidence": 0.98,
            },
            {
                "text": "file read operation for scanning package.json requirements.txt",
                "is_false_positive": True,
                "finding_type": "insecure_acl",
                "confidence": 0.95,
            },
            {
                "text": "normal file I/O operation open read_text for code analysis",
                "is_false_positive": True,
                "finding_type": "insecure_acl",
                "confidence": 0.95,
            },
            {
                "text": "detector function _scan_ pattern matching loop",
                "is_false_positive": True,
                "finding_type": "hardcoded_secret",
                "confidence": 0.97,
            },
            # ====================================================================
            # REAL VULNERABILITIES - Advanced Patterns
            # ====================================================================
            {
                "text": "Flask template variable with |safe filter XSS vulnerability",
                "is_false_positive": False,
                "finding_type": "xss",
                "confidence": 0.95,
            },
            {
                "text": "Django template autoescape off XSS risk",
                "is_false_positive": False,
                "finding_type": "xss",
                "confidence": 0.95,
            },
            {
                "text": "React dangerouslySetInnerHTML XSS vulnerability",
                "is_false_positive": False,
                "finding_type": "xss",
                "confidence": 0.95,
            },
            {
                "text": "Flask DEBUG = True production security risk",
                "is_false_positive": False,
                "finding_type": "insecure_configuration",
                "confidence": 0.95,
            },
            {
                "text": "Django DEBUG = True production environment",
                "is_false_positive": False,
                "finding_type": "insecure_configuration",
                "confidence": 0.95,
            },
            {
                "text": "cookie set with user input without secure HttpOnly flags",
                "is_false_positive": False,
                "finding_type": "insecure_configuration",
                "confidence": 0.90,
            },
            {
                "text": "response.set_cookie with request data user-controlled value",
                "is_false_positive": False,
                "finding_type": "insecure_configuration",
                "confidence": 0.90,
            },
            {
                "text": "SQLite database without encryption GDPR violation",
                "is_false_positive": False,
                "finding_type": "weak_encryption",
                "confidence": 0.95,
            },
            {
                "text": "Docker socket mounted without restrictions security risk",
                "is_false_positive": False,
                "finding_type": "insecure_acl",
                "confidence": 0.95,
            },
            {
                "text": "sessionStorage.setItem github token client-side storage",
                "is_false_positive": False,
                "finding_type": "hardcoded_secret",
                "confidence": 0.90,
            },
            {
                "text": "localStorage.setItem access token insecure storage",
                "is_false_positive": False,
                "finding_type": "hardcoded_secret",
                "confidence": 0.90,
            },
            {
                "text": "password Column String plaintext database model",
                "is_false_positive": False,
                "finding_type": "weak_authentication",
                "confidence": 0.95,
            },
            {
                "text": "password db.String models.CharField plaintext storage",
                "is_false_positive": False,
                "finding_type": "weak_authentication",
                "confidence": 0.95,
            },
            {
                "text": "Flask SECRET_KEY hardcoded in application code",
                "is_false_positive": False,
                "finding_type": "hardcoded_secret",
                "confidence": 0.95,
            },
            {
                "text": "Django SECRET_KEY hardcoded in settings.py",
                "is_false_positive": False,
                "finding_type": "hardcoded_secret",
                "confidence": 0.95,
            },
            {
                "text": "eval user input code injection vulnerability",
                "is_false_positive": False,
                "finding_type": "command_injection",
                "confidence": 0.95,
            },
            {
                "text": "exec user input command execution risk",
                "is_false_positive": False,
                "finding_type": "command_injection",
                "confidence": 0.95,
            },
            {
                "text": "subprocess.call user input shell injection",
                "is_false_positive": False,
                "finding_type": "command_injection",
                "confidence": 0.90,
            },
            {
                "text": "os.system user input command injection",
                "is_false_positive": False,
                "finding_type": "command_injection",
                "confidence": 0.95,
            },
            {
                "text": "SQL query string concatenation injection vulnerability",
                "is_false_positive": False,
                "finding_type": "potential_sql_injection",
                "confidence": 0.90,
            },
            {
                "text": "NoSQL injection eval string concatenation",
                "is_false_positive": False,
                "finding_type": "potential_sql_injection",
                "confidence": 0.90,
            },
            {
                "text": "XML parser external entity XXE vulnerability",
                "is_false_positive": False,
                "finding_type": "xxe",
                "confidence": 0.90,
            },
            {
                "text": "XML external entity DOCTYPE SYSTEM file access",
                "is_false_positive": False,
                "finding_type": "xxe",
                "confidence": 0.90,
            },
            {
                "text": "URL fetch user input SSRF server-side request forgery",
                "is_false_positive": False,
                "finding_type": "ssrf",
                "confidence": 0.90,
            },
            {
                "text": "HTTP request user-controlled URL internal network access",
                "is_false_positive": False,
                "finding_type": "ssrf",
                "confidence": 0.90,
            },
            {
                "text": "pickle.loads user input insecure deserialization",
                "is_false_positive": False,
                "finding_type": "insecure_deserialization",
                "confidence": 0.95,
            },
            {
                "text": "yaml.load user input code execution risk",
                "is_false_positive": False,
                "finding_type": "insecure_deserialization",
                "confidence": 0.95,
            },
            {
                "text": "file path user input ../ directory traversal",
                "is_false_positive": False,
                "finding_type": "path_traversal",
                "confidence": 0.90,
            },
            {
                "text": "open user input path traversal file access",
                "is_false_positive": False,
                "finding_type": "path_traversal",
                "confidence": 0.90,
            },
            {
                "text": "time-of-check time-of-use race condition TOCTOU",
                "is_false_positive": False,
                "finding_type": "race_condition",
                "confidence": 0.85,
            },
            {
                "text": "file existence check before access race condition",
                "is_false_positive": False,
                "finding_type": "race_condition",
                "confidence": 0.85,
            },
            {
                "text": "Math.random weak random number generation",
                "is_false_positive": False,
                "finding_type": "crypto_misuse",
                "confidence": 0.90,
            },
            {
                "text": "hardcoded IV initialization vector encryption",
                "is_false_positive": False,
                "finding_type": "crypto_misuse",
                "confidence": 0.90,
            },
            {
                "text": "weak key derivation PBKDF2 iterations insufficient",
                "is_false_positive": False,
                "finding_type": "crypto_misuse",
                "confidence": 0.85,
            },
            # ====================================================================
            # EDGE CASES - Nuanced Scenarios
            # ====================================================================
            {
                "text": "test file placeholder password example test case",
                "is_false_positive": True,
                "finding_type": "hardcoded_secret",
                "confidence": 0.85,
            },
            {
                "text": "mock data test fixture example password",
                "is_false_positive": True,
                "finding_type": "hardcoded_secret",
                "confidence": 0.85,
            },
            {
                "text": "documentation example code snippet tutorial",
                "is_false_positive": True,
                "finding_type": "hardcoded_secret",
                "confidence": 0.90,
            },
            {
                "text": "README example configuration placeholder",
                "is_false_positive": True,
                "finding_type": "hardcoded_secret",
                "confidence": 0.90,
            },
            {
                "text": "environment variable reference ${VAR} $VAR",
                "is_false_positive": True,
                "finding_type": "hardcoded_secret",
                "confidence": 0.95,
            },
            {
                "text": "os.getenv environment variable lookup",
                "is_false_positive": True,
                "finding_type": "hardcoded_secret",
                "confidence": 0.95,
            },
            {
                "text": "production code real password admin12345",
                "is_false_positive": False,
                "finding_type": "hardcoded_secret",
                "confidence": 0.95,
            },
            {
                "text": "production code real API key in source",
                "is_false_positive": False,
                "finding_type": "hardcoded_secret",
                "confidence": 0.95,
            },
            {
                "text": "production code real secret token hardcoded",
                "is_false_positive": False,
                "finding_type": "hardcoded_secret",
                "confidence": 0.95,
            },
            # ====================================================================
            # INDUSTRY-SPECIFIC PATTERNS
            # ====================================================================
            {
                "text": "healthcare HIPAA PHI data unencrypted storage",
                "is_false_positive": False,
                "finding_type": "weak_encryption",
                "confidence": 0.95,
            },
            {
                "text": "PCI-DSS credit card data plaintext storage",
                "is_false_positive": False,
                "finding_type": "weak_encryption",
                "confidence": 0.95,
            },
            {
                "text": "GDPR personal data without encryption",
                "is_false_positive": False,
                "finding_type": "weak_encryption",
                "confidence": 0.90,
            },
            {
                "text": "SOC2 missing access logging audit trail",
                "is_false_positive": False,
                "finding_type": "missing_logging",
                "confidence": 0.90,
            },
            {
                "text": "ISO27001 missing security logging monitoring",
                "is_false_positive": False,
                "finding_type": "missing_logging",
                "confidence": 0.90,
            },
            {
                "text": "GDPR missing consent mechanism data processing",
                "is_false_positive": False,
                "finding_type": "missing_consent",
                "confidence": 0.85,
            },
            {
                "text": "DPDP missing consent mechanism personal data",
                "is_false_positive": False,
                "finding_type": "missing_consent",
                "confidence": 0.85,
            },
        ]
        
        # Pre-compute embeddings for all patterns
        if self.model:
            pattern_texts = [p["text"] for p in patterns]
            try:
                embeddings = self.model.encode(pattern_texts, show_progress_bar=False)
                for i, pattern in enumerate(patterns):
                    pattern["embedding"] = embeddings[i]
            except Exception as e:
                logger.warning(f"Failed to compute embeddings: {e}")
                return []
        
        return patterns
    
    def validate_finding(
        self,
        finding_type: str,
        snippet: str,
        context: str = "",
        file_path: str = "",
        line_no: Optional[int] = None,
    ) -> Tuple[bool, float, str]:
        """Validate a finding using semantic similarity to known patterns.
        
        Industry-scale multi-factor validation:
        1. Semantic similarity to known patterns
        2. Context analysis (file path, surrounding code)
        3. Pattern-specific heuristics
        4. Confidence scoring with multiple signals
        
        Args:
            finding_type: Type of finding (e.g., "hardcoded_secret")
            snippet: Code snippet that triggered the finding
            context: Surrounding code context (optional)
            file_path: Path to the file (optional)
            line_no: Line number (optional)
        
        Returns:
            Tuple of (is_valid, confidence, explanation):
            - is_valid: True if finding is likely real, False if likely false positive
            - confidence: Confidence score (0.0-1.0)
            - explanation: Brief explanation of the decision
        """
        if not self.enabled or not self.model:
            return True, 0.5, "AI validation disabled"
        
        if not self.patterns_db:
            return True, 0.5, "No patterns database available"
        
        # Multi-factor validation: combine semantic similarity with heuristics
        heuristic_score = self._compute_heuristic_score(finding_type, snippet, context, file_path)
        
        # Create semantic representation of the finding
        full_text = f"{finding_type}: {snippet}"
        if context:
            full_text += f" Context: {context[:200]}"
        if file_path:
            full_text += f" File: {file_path}"
        
        try:
            # Compute embedding for the finding
            finding_embedding = self.model.encode([full_text], show_progress_bar=False)[0]
            
            # Find most similar patterns (top-k for better accuracy)
            fp_similarities = []
            real_similarities = []
            
            for pattern in self.patterns_db:
                if "embedding" not in pattern:
                    continue
                
                # Only check patterns of the same type for better accuracy
                if pattern.get("finding_type") != finding_type:
                    continue
                
                # Compute cosine similarity
                similarity = self._cosine_similarity(finding_embedding, pattern["embedding"])
                
                if pattern["is_false_positive"]:
                    fp_similarities.append((similarity, pattern))
                else:
                    real_similarities.append((similarity, pattern))
            
            # Get top matches
            fp_similarities.sort(reverse=True, key=lambda x: x[0])
            real_similarities.sort(reverse=True, key=lambda x: x[0])
            
            best_fp_similarity = fp_similarities[0][0] if fp_similarities else 0.0
            best_real_similarity = real_similarities[0][0] if real_similarities else 0.0
            best_fp_pattern = fp_similarities[0][1] if fp_similarities else None
            best_real_pattern = real_similarities[0][1] if real_similarities else None
            
            # Multi-factor decision logic with improved thresholds
            # Factor 1: Very high similarity to false positive (strong signal)
            if best_fp_similarity > 0.85:
                confidence = max(0.1, 1.0 - best_fp_similarity)
                return False, confidence, f"Very similar to known false positive (similarity: {best_fp_similarity:.2f})"
            
            # Factor 2: High similarity to real issue (strong signal)
            if best_real_similarity > 0.75:
                # Combine semantic similarity with heuristic score
                combined_confidence = min(0.98, (best_real_similarity * 0.7) + (heuristic_score * 0.3) + 0.1)
                return True, combined_confidence, f"Very similar to known real issue (similarity: {best_real_similarity:.2f})"
            
            # Factor 3: Moderate similarity to false positive (weaker signal)
            if best_fp_similarity > 0.70:
                # Lower confidence but don't reject (might be edge case)
                return True, 0.5, f"Moderately similar to false positive (similarity: {best_fp_similarity:.2f}), lower confidence"
            
            # Factor 4: Moderate similarity to real issue
            if best_real_similarity > 0.65:
                combined_confidence = min(0.90, (best_real_similarity * 0.6) + (heuristic_score * 0.4))
                return True, combined_confidence, f"Moderately similar to known real issue (similarity: {best_real_similarity:.2f})"
            
            # Factor 5: Use heuristics when semantic similarity is ambiguous
            if heuristic_score > 0.7:
                return True, heuristic_score, "Heuristic analysis indicates real issue"
            elif heuristic_score < 0.3:
                return False, 1.0 - heuristic_score, "Heuristic analysis indicates false positive"
            
            # Default: moderate confidence, trust original detection
            base_confidence = 0.65
            if best_real_similarity > best_fp_similarity:
                base_confidence = 0.70
            elif best_fp_similarity > best_real_similarity:
                base_confidence = 0.60
            
            return True, base_confidence, f"No strong match (FP: {best_fp_similarity:.2f}, Real: {best_real_similarity:.2f})"
            
        except Exception as e:
            logger.warning(f"AI validation error: {e}")
            return True, 0.5, f"AI validation failed: {e}"
    
    def _compute_heuristic_score(
        self,
        finding_type: str,
        snippet: str,
        context: str = "",
        file_path: str = "",
    ) -> float:
        """Compute heuristic score based on context and patterns.
        
        Returns a score between 0.0 (likely false positive) and 1.0 (likely real issue).
        """
        score = 0.5  # Neutral starting point
        snippet_lower = snippet.lower()
        context_lower = context.lower()
        file_path_lower = file_path.lower() if file_path else ""
        
        # Heuristic 1: Check for placeholder/example indicators (reduce score)
        placeholder_indicators = [
            "change-me", "replace-me", "your-", "example", "placeholder",
            "todo", "fixme", "xxx", "test", "demo", "sample", "tutorial"
        ]
        if any(indicator in snippet_lower for indicator in placeholder_indicators):
            score -= 0.3
        
        # Heuristic 2: Check for detector code indicators (reduce score)
        detector_indicators = [
            "detector", "scanner", "_scan_", "pattern", "re.compile",
            "patterns =", "xss_patterns", "injection_patterns"
        ]
        if any(indicator in context_lower or indicator in file_path_lower for indicator in detector_indicators):
            score -= 0.4
        
        # Heuristic 3: Check for test file indicators (reduce score)
        test_indicators = ["test_", "_test", "spec_", "_spec", "mock", "fixture"]
        if any(indicator in file_path_lower for indicator in test_indicators):
            score -= 0.2
        
        # Heuristic 4: Check for real vulnerability indicators (increase score)
        real_vuln_indicators = [
            "admin", "password", "secret", "token", "key", "credential",
            "system(", "exec(", "eval(", "dangerously", "|safe", "autoescape off"
        ]
        if any(indicator in snippet_lower for indicator in real_vuln_indicators):
            # But only if not in detector code
            if not any(det in context_lower for det in detector_indicators):
                score += 0.3
        
        # Heuristic 5: Check for production code indicators (increase score)
        production_indicators = ["app/", "src/", "lib/", "main.", "index.", "server."]
        if any(indicator in file_path_lower for indicator in production_indicators):
            score += 0.1
        
        # Heuristic 6: Check for environment variable usage (reduce score - this is correct)
        env_indicators = ["os.getenv", "process.env", "${", "$env", "getenv("]
        if any(indicator in snippet_lower or indicator in context_lower for indicator in env_indicators):
            score -= 0.2
        
        # Clamp score between 0.0 and 1.0
        return max(0.0, min(1.0, score))
    
    def _cosine_similarity(self, vec1, vec2) -> float:
        """Compute cosine similarity between two vectors."""
        if np is None:
            return 0.0
        
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)


# Global AI detector instance (lazy initialization)
_ai_detector: Optional[LocalAIDetector] = None


def get_ai_detector() -> LocalAIDetector:
    """Get or create the global AI detector instance."""
    global _ai_detector
    if _ai_detector is None:
        _ai_detector = LocalAIDetector()
    return _ai_detector


def validate_finding_with_ai(
    finding_type: str,
    snippet: str,
    context: str = "",
    file_path: str = "",
    line_no: Optional[int] = None,
) -> Tuple[bool, float, str]:
    """Convenience function to validate a finding using AI.
    
    Returns: (is_valid, confidence, explanation)
    """
    detector = get_ai_detector()
    return detector.validate_finding(finding_type, snippet, context, file_path, line_no)
