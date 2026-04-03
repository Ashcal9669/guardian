"""
Shared helpers for rendering structured remediation guidance in findings.
"""

from __future__ import annotations


def build_remediation(explanation: str, steps: list[object]) -> str:
    """
    Build a remediation string that the HTML report can parse into:
    - an explanation paragraph
    - numbered steps
    - command blocks for each step
    """
    lines = [f"Explanation: {explanation.strip()}"]
    for index, step in enumerate(steps, start=1):
        if isinstance(step, dict):
            text = str(step.get("text", "")).strip()
            raw_commands = step.get("commands", [])
        elif isinstance(step, tuple) and len(step) == 2:
            text = str(step[0]).strip()
            raw_commands = step[1]
        else:
            text = str(step).strip()
            raw_commands = []
        if isinstance(raw_commands, str):
            raw_commands = [raw_commands]
        commands = [str(cmd).strip() for cmd in raw_commands if str(cmd).strip()]
        if not text:
            continue
        lines.append(f"{index}. {text}")
        for command in commands:
            lines.append(f"$ {command}")
    return "\n".join(lines)
