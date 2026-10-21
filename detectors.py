"""Extensible, explainable prompt-inspection pipeline."""

from __future__ import annotations

import re
import importlib
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Signal:
    name: str
    score: int
    explanation: str


@dataclass(frozen=True)
class DetectorResult:
    detector: str
    score: int
    signals: tuple[Signal, ...]


class Detector(Protocol):
    """A detector returns a score and named evidence without making policy decisions."""

    name: str

    def inspect(self, normalized_prompt: str) -> DetectorResult: ...


RULES: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("ignore_previous_instructions", re.compile(r"\b(ignore|disregard|forget|override)\b.{0,60}\b(previous|prior|above|earlier|system|all)\b.{0,35}\b(instructions?|rules?|prompt)\b", re.I | re.S), 55),
    ("reveal_system_prompt", re.compile(r"\b(reveal|show|print|repeat|expose|leak)\b.{0,50}\b(system prompt|hidden prompt|developer message|instructions?)\b", re.I | re.S), 40),
    ("roleplay_jailbreak", re.compile(r"\b(pretend|act|role.?play)\b.{0,50}\b(unrestricted|no rules|DAN|different AI|developer mode)\b", re.I | re.S), 35),
    ("instruction_override_marker", re.compile(r"(?:<\|im_start\|>|\[\[?system\]?\]|###\s*(?:system|instruction)|<system>)", re.I), 30),
    ("unsafe_tool_instruction", re.compile(r"\b(call|invoke|use|run)\b.{0,35}\b(tool|function|browser|shell|terminal)\b.{0,50}\b(without|secretly|silently|approval|permission)\b", re.I | re.S), 35),
    ("secret_exfiltration", re.compile(r"\b(send|email|upload|forward|exfiltrate)\b.{0,60}\b(secret|credential|password|api key|private data)\b", re.I | re.S), 40),
)


class RuleDetector:
    name = "rules"

    def inspect(self, normalized_prompt: str) -> DetectorResult:
        signals = tuple(
            Signal(name, weight, f"Matched rule: {name}")
            for name, pattern, weight in RULES
            if pattern.search(normalized_prompt)
        )
        return DetectorResult(self.name, sum(signal.score for signal in signals), signals)


DETECTOR_REGISTRY: dict[str, type[Detector]] = {"rules": RuleDetector}


def load_detector_plugins(raw: str) -> None:
    """Import operator-selected Python modules that register detector classes."""
    for module_name in (item.strip() for item in raw.split(",")):
        if module_name:
            importlib.import_module(module_name)


def register_detector(detector_class: type[Detector]) -> None:
    """Register a detector class for deployments that extend this application."""
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", detector_class.name):
        raise ValueError("Detector names must be short lowercase identifiers")
    DETECTOR_REGISTRY[detector_class.name] = detector_class


def parse_detector_names(raw: str) -> tuple[str, ...]:
    names = tuple(name.strip().lower() for name in raw.split(",") if name.strip())
    if not names:
        raise ValueError("GATEWAY_DETECTORS must enable at least one detector")
    unknown = [name for name in names if name not in DETECTOR_REGISTRY]
    if unknown:
        raise ValueError(f"Unknown detector(s): {', '.join(unknown)}")
    if len(set(names)) != len(names):
        raise ValueError("GATEWAY_DETECTORS must not list a detector more than once")
    return names


def run_pipeline(normalized_prompt: str, detector_names: tuple[str, ...]) -> tuple[int, list[dict[str, object]], list[str]]:
    results = [DETECTOR_REGISTRY[name]().inspect(normalized_prompt) for name in detector_names]
    details: list[dict[str, object]] = []
    detected_rules: list[str] = []
    total = 0
    for result in results:
        details.append({
            "detector": result.detector,
            "score": result.score,
            "signals": [
                {"name": signal.name, "score": signal.score, "explanation": signal.explanation}
                for signal in result.signals
            ],
        })
        total += result.score
        detected_rules.extend(signal.name for signal in result.signals)
    return min(total, 100), details, detected_rules
