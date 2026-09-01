r"""T3-3 LLM-Powered Semantic Analyzer

Uses AI to deeply analyze contract source code for:
1. Business logic flaws that regex/Slither miss
2. False positive elimination (85% -> ~30-40%)
3. Complex cross-contract interaction vulnerabilities
4. Economic attack vectors (sandwich, front-running, reward manipulation)
5. Context-aware exploitability assessment

This is the biggest quality improvement - regex catches patterns, LLM catches meaning.
"""
import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional
from .analyzer import Finding
from .config import SEVERITY_ORDER


@dataclass
class LLMAnalysisResult:
    findings: list = field(default_factory=list)
    false_positive_removals: list = field(default_factory=list)
    new_business_logic_bugs: list = field(default_factory=list)
    overall_assessment: str = ''
    confidence_adjustments: dict = field(default_factory=dict)
    error: str = ''


class LLMAnalyzer:
    """LLM-powered semantic contract analysis.

    Provider priority:
    1. Google Gemini 2.0 Flash (FREE, no credit card) — default
    2. OpenAI-compatible API (GPT-4o-mini) — fallback
    3. Rule-based heuristics — offline fallback

    Gemini free tier: 15 RPM, 1M tokens/day, 500K request/day.
    Get a free key at https://aistudio.google.com/apikey (30 seconds, zero cost).
    """

    # Gemini Flash models (free tier) — note: geo-restricted outside supported regions
    # Works on Railway (US). Falls back to Groq globally.
    GEMINI_MODELS = [
        'gemini-2.5-flash',
        'gemini-2.0-flash-lite',
    ]
    GEMINI_API_BASE = 'https://generativelanguage.googleapis.com/v1beta'

    # Groq — free, global, OpenAI-compatible. Llama 3.3 70B.
    # Get key at https://console.groq.com/keys (free, no card)
    GROQ_MODELS = ['llama-3.3-70b-versatile', 'llama-3.1-8b-instant']
    GROQ_API_BASE = 'https://api.groq.com/openai/v1'

    def __init__(self, api_key: str = None, base_url: str = None):
        # Provider selection: Gemini (free) > Groq (free, global) > OpenAI > None
        self.gemini_key = api_key or os.getenv('GEMINI_API_KEY', '')
        self.groq_key = os.getenv('GROQ_API_KEY', '')
        self.api_key = os.getenv('OPENAI_API_KEY', '') if not self.groq_key else ''
        self.base_url = base_url or os.getenv('LLM_BASE_URL', 'https://api.openai.com/v1')
        self.provider = self._detect_provider()
        self._available = self.provider != 'none'
        self._request_count = 0
        self._cache = {}  # source hash -> result
        if self._available:
            print(f'[LLM] Provider: {self.provider}')

    def _detect_provider(self) -> str:
        """Auto-detect best available LLM provider."""
        if self.gemini_key:
            return 'gemini'
        if self.groq_key:
            return 'groq'
        if self.api_key:
            return 'openai'
        return 'none'

    def is_available(self) -> bool:
        return self._available

    def analyze(self, source_code: str, contract_name: str,
                regex_findings: list, address: str = '', chain_id: int = 0) -> LLMAnalysisResult:
        """Run LLM analysis on a contract.

        Args:
            source_code: Full Solidity source
            contract_name: Name of the contract
            regex_findings: Existing findings from regex/Slither (to validate)
            address: Contract address
            chain_id: Chain ID

        Returns:
            LLMAnalysisResult with validated findings and new discoveries
        """
        result = LLMAnalysisResult()

        # Check cache
        cache_key = self._source_hash(source_code[:5000])
        if cache_key in self._cache:
            return self._cache[cache_key]

        if not self._available:
            # Fallback: use rule-based analysis
            return self._rule_based_analysis(source_code, contract_name, regex_findings)

        # Build the analysis prompt
        prompt = self._build_analysis_prompt(source_code, contract_name,
                                                regex_findings, address)

        try:
            response = self._call_llm(prompt)
            result = self._parse_llm_response(response, regex_findings)
        except Exception as e:
            print(f'[LLM] Error: {e}')
            result.error = str(e)
            # Fallback to rule-based
            result = self._rule_based_analysis(source_code, contract_name, regex_findings)

        self._cache[cache_key] = result
        return result

    def _source_hash(self, code: str) -> str:
        import hashlib
        return hashlib.md5(code.encode()).hexdigest()

    def _build_analysis_prompt(self, source: str, name: str,
                                 findings: list, address: str) -> str:
        """Build the LLM analysis prompt."""
        # Truncate source to fit context (keep most important parts)
        source_truncated = self._smart_truncate(source, max_chars=8000)

        findings_text = ''
        if findings:
            findings_text = '\nExisting regex/Slither findings to VALIDATE:\n'
            for f in findings[:15]:
                findings_text += f'- [{f.severity}] {f.title}: {f.description[:100]}\n'

        prompt = f"""You are a world-class smart contract security auditor specializing in DeFi vulnerability detection.

Analyze this Solidity contract and respond with a structured JSON assessment.

Contract: {name}
Address: {address}
{findings_text}

Source code:
```solidity
{source_truncated}
```

Respond ONLY with valid JSON (no markdown, no explanation) in this exact format:
{{
  "validated_findings": [
    {{"vuln_id": "...", "is_true_positive": true/false, "reason": "why", "adjusted_confidence": 0.0-1.0}}
  ],
  "new_findings": [
    {{"category": "Reentrancy|Access Control|Oracle|Business Logic|Flash Loan|Front-Running|Economic|Reward Manipulation|Cross-Contract",
       "severity": "CRITICAL|HIGH|MEDIUM|LOW",
       "title": "short title",
       "description": "detailed description of the vulnerability",
       "location": "function name or code section",
       "confidence": 0.0-1.0,
       "zero_capital": true/false,
       "flash_loan_required": true/false,
       "attack_scenario": "step by step"}}
  ],
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW|SAFE",
  "business_logic_notes": "any business logic concerns even if not a clear vulnerability"
}}

CRITICAL RULES:
1. A finding is FALSE POSITIVE if: the function has access control via inheritance, the pattern is in a test file, the function is internal/private, or the code path is unreachable.
2. Be SPECIFIC about location - name the exact function.
3. Only flag exploitable issues that could lead to fund loss.
4. Consider: reentrancy, access control, oracle manipulation, front-running, sandwich attacks, reward gaming, flash loan attacks, governance exploits."""

        return prompt

    def _smart_truncate(self, source: str, max_chars: int = 8000) -> str:
        """Truncate source keeping the most security-relevant parts."""
        if len(source) <= max_chars:
            return source

        # Priority: functions with external/public + state changes
        # Simple approach: keep the beginning (imports/state vars) and
        # function bodies
        lines = source.split('\n')
        kept = []
        char_count = 0

        # Always keep first 50 lines (imports, state vars, events)
        for line in lines[:50]:
            kept.append(line)
            char_count += len(line) + 1

        # Then scan for function definitions
        in_function = False
        brace_depth = 0
        function_buffer = []

        for line in lines[50:]:
            if char_count > max_chars:
                break

            # Detect function start
            if re.match(r'\s*function\s+\w+', line):
                in_function = True
                brace_depth = 0
                function_buffer = [line]
                continue

            if in_function:
                function_buffer.append(line)
                brace_depth += line.count('{') - line.count('}')

                if brace_depth <= 0:
                    # Function complete
                    func_text = '\n'.join(function_buffer)
                    # Only keep external/public functions (skip pure/view)
                    if not re.search(r'\b(pure|view|internal|private)\b', func_text.split('{')[0]):
                        if char_count + len(func_text) <= max_chars:
                            kept.append(func_text)
                            char_count += len(func_text) + 1
                    in_function = False
                    function_buffer = []

        return '\n'.join(kept)

    def _call_llm(self, prompt: str, max_retries: int = 2) -> str:
        """Call the LLM API — routes to Gemini > Groq > OpenAI."""
        if self.provider == 'gemini':
            return self._call_gemini(prompt, max_retries)
        if self.provider == 'groq':
            return self._call_groq(prompt, max_retries)
        return self._call_openai(prompt, max_retries)

    def _call_gemini(self, prompt: str, max_retries: int = 2) -> str:
        """Call Google Gemini 2.0 Flash (FREE tier).
        
        Uses the generateContent REST endpoint — no SDK needed.
        Rate limits: 15 RPM, 1M tokens/day on free tier.
        """
        import requests
        import time

        for model in self.GEMINI_MODELS:
            url = (
                f'{self.GEMINI_API_BASE}/models/{model}:generateContent'
                f'?key={self.gemini_key}'
            )
            payload = {
                'contents': [{'parts': [{'text': prompt}]}],
                'generationConfig': {
                    'temperature': 0.1,
                    'maxOutputTokens': 2048,
                },
            }
            for attempt in range(max_retries):
                try:
                    resp = requests.post(url, json=payload, timeout=30)
                    if resp.status_code == 200:
                        data = resp.json()
                        return data['candidates'][0]['content']['parts'][0]['text']
                    elif resp.status_code == 429:
                        time.sleep(2 ** attempt)
                        continue
                    elif resp.status_code == 404:
                        # Model not found, try next
                        break
                    else:
                        raise Exception(f'Gemini API {resp.status_code}: {resp.text[:200]}')
                except requests.Timeout:
                    continue
        raise Exception('Gemini call failed after retries')

    def _call_groq(self, prompt: str, max_retries: int = 2) -> str:
        """Call Groq (FREE, global, OpenAI-compatible). Llama 3.3 70B."""
        import requests
        import time

        headers = {
            'Authorization': f'Bearer {self.groq_key}',
            'Content-Type': 'application/json',
        }
        for model in self.GROQ_MODELS:
            payload = {
                'model': model,
                'messages': [{'role': 'user', 'content': prompt}],
                'temperature': 0.1,
                'max_tokens': 2048,
            }
            for attempt in range(max_retries):
                try:
                    resp = requests.post(
                        f'{self.GROQ_API_BASE}/chat/completions',
                        headers=headers, json=payload, timeout=30,
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        return data['choices'][0]['message']['content']
                    elif resp.status_code == 429:
                        time.sleep(2 ** attempt)
                        continue
                    elif resp.status_code == 404:
                        break  # Try next model
                    else:
                        raise Exception(f'Groq API {resp.status_code}')
                except requests.Timeout:
                    continue
        raise Exception('Groq call failed after retries')

    def _call_openai(self, prompt: str, max_retries: int = 2) -> str:
        """Call OpenAI-compatible API."""
        import requests
        import time

        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
        }
        payload = {
            'model': 'gpt-4o-mini',
            'messages': [{'role': 'user', 'content': prompt}],
            'temperature': 0.1,
            'max_tokens': 2000,
        }
        for attempt in range(max_retries):
            try:
                resp = requests.post(
                    f'{self.base_url}/chat/completions',
                    headers=headers, json=payload, timeout=30,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data['choices'][0]['message']['content']
                elif resp.status_code == 429:
                    time.sleep(2 ** attempt)
                    continue
                else:
                    raise Exception(f'API {resp.status_code}')
            except requests.Timeout:
                continue
        raise Exception('LLM call failed after retries')

    def _parse_llm_response(self, response: str,
                             existing_findings: list) -> LLMAnalysisResult:
        """Parse the LLM JSON response."""
        result = LLMAnalysisResult()

        # Extract JSON from response (may have markdown wrapping)
        json_str = response.strip()
        if json_str.startswith('```'):
            json_str = re.sub(r'^```(?:json)?\s*', '', json_str)
            json_str = re.sub(r'\s*```$', '', json_str)

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            print(f'[LLM] JSON parse error: {e}')
            result.error = f'JSON parse: {e}'
            return result

        # Process validated findings (false positive elimination)
        validated = data.get('validated_findings', [])
        false_positives = []
        true_positives = []

        for vf in validated:
            vid = vf.get('vuln_id', '')
            is_tp = vf.get('is_true_positive', True)
            reason = vf.get('reason', '')
            adjusted_conf = vf.get('adjusted_confidence', 0)

            if not is_tp:
                false_positives.append(vid)
            else:
                true_positives.append(vid)
                result.confidence_adjustments[vid] = adjusted_conf

        result.false_positive_removals = false_positives

        # Filter existing findings based on LLM validation
        removal_ids = set(false_positives)
        result.findings = [
            f for f in existing_findings
            if f.vuln_id not in removal_ids
        ]

        # Adjust confidence scores based on LLM assessment
        for f in result.findings:
            if f.vuln_id in result.confidence_adjustments:
                f.confidence = result.confidence_adjustments[f.vuln_id]

        # Process new findings from LLM
        for nf in data.get('new_findings', []):
            if nf.get('category', '').lower() == 'safe':
                continue

            finding = Finding(
                vuln_id=f'LLM-{nf.get("category", "UNK")[:4].upper()}',
                category=nf.get('category', 'Business Logic'),
                severity=nf.get('severity', 'MEDIUM'),
                title=f'[LLM] {nf.get("title", "")}',
                description=nf.get('description', ''),
                location=nf.get('location', ''),
                confidence=nf.get('confidence', 0.6),
                zero_capital=nf.get('zero_capital', False),
                flash_loan_required=nf.get('flash_loan_required', False),
                attack_scenario=nf.get('attack_scenario', ''),
                source='llm',
            )
            result.findings.append(finding)
            result.new_business_logic_bugs.append(finding.title)

        result.overall_assessment = data.get('overall_risk', 'MEDIUM')

        self._request_count += 1
        print(f'[LLM] Analysis #{self._request_count}: '
              f'{len(false_positives)} false positives removed, '
              f'{len(result.new_business_logic_bugs)} new findings')

        return result

    def _rule_based_analysis(self, source: str, name: str,
                               findings: list) -> LLMAnalysisResult:
        """Rule-based fallback when LLM is not available.

        Uses heuristics to eliminate common false positive patterns.
        """
        result = LLMAnalysisResult()
        result.findings = list(findings)

        removals = []
        for f in findings:
            # Check if the finding references a test file
            if 'test' in f.location.lower() or 'mock' in f.location.lower():
                removals.append(f.vuln_id)
                continue

            # Check if the function is in an interface (no body)
            if ';\n' in f.location[:50] and '{' not in f.location[:100]:
                removals.append(f.vuln_id)
                continue

            # Reduce confidence for common false positive patterns
            if f.source == 'regex' and f.confidence < 0.7:
                # Regex-only findings with low confidence are often FPs
                if 'transfer' in f.title.lower() and 'erc20' in f.category.lower():
                    removals.append(f.vuln_id)
                    continue

        result.false_positive_removals = list(set(removals))
        result.findings = [f for f in result.findings if f.vuln_id not in set(removals)]

        return result
