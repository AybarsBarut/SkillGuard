"""
Harmless helper script for clean skill fixture.
"""

def clean_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]
