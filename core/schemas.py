"""
core/schemas.py
Pydantic data models for structured pipeline validation.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class Verdict(str, Enum):
    LIKELY_SCAM = "likely_scam"
    SUSPICIOUS = "suspicious"
    LIKELY_SAFE = "likely_safe"


class RedFlag(BaseModel):
    phrase: str = Field(..., description="The suspicious phrase or red flag indicator.")
    explanation: str = Field(..., description="Why this phrase is dangerous or suspicious.")
    evidence_quote: str = Field(..., description="Exact substring from the original message.")
    category: str = Field("general", description="Category: urgency, credential_theft, prize_scam, fake_link, impersonation, etc.")
    severity: str = Field("medium", description="Severity level: low, medium, or high.")


class LLMScamResponse(BaseModel):
    """Structured response expected from the LLM layer."""
    verdict: Verdict
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0.")
    summary: str = Field(..., description="Short summary of the analysis.")
    red_flags: List[RedFlag] = Field(default_factory=list, description="List of detected red flags.")
    next_steps: List[str] = Field(default_factory=list, description="Clear next steps for the user.")
    simple_explanation_en: str = Field(..., description="Max 3 short sentences in simple English without jargon.")
    simple_explanation_ur: str = Field(..., description="Max 3 short sentences in simple Urdu without jargon.")


class AnalysisResult(BaseModel):
    """Final unified result after fusion and post-processing."""
    verdict: Verdict
    confidence: float = Field(..., ge=0.0, le=1.0)
    summary: str
    red_flags: List[RedFlag] = Field(default_factory=list)
    highlighted_text: str
    next_steps: List[str] = Field(default_factory=list)
    simple_explanation_en: str
    simple_explanation_ur: str
    mode: str = Field("hybrid", description="'hybrid' or 'rules_only'")
    script_type: str = Field("english", description="'english', 'urdu_script', 'roman_urdu', or 'mixed'")
    rule_score: float = 0.0
    llm_verdict: Optional[str] = None
    disagreement: bool = False
    warnings: List[str] = Field(default_factory=list)
