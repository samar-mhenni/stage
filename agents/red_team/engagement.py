"""Load the canonical red-team engagement letter and expose agent instructions."""

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENGAGEMENT_FILE = PROJECT_ROOT / "docs" / "red_team_letter_of_engagement.txt"


def load_engagement_letter() -> str:
    return ENGAGEMENT_FILE.read_text(encoding="utf-8").strip()


def _split_engagement_letter() -> tuple[str, str]:
    content = load_engagement_letter()
    title, separator, body = content.partition("\n\n")
    if not separator:
        raise ValueError(f"Engagement letter at {ENGAGEMENT_FILE} must contain a title and body")
    return title.strip(), body.strip()


ENGAGEMENT_TITLE, ENGAGEMENT_TEXT = _split_engagement_letter()


def red_team_engagement_instructions() -> str:
    """Return imperative instructions derived from the canonical engagement letter."""
    relative_letter_path = ENGAGEMENT_FILE.relative_to(PROJECT_ROOT)
    return (
        f"\n\n{ENGAGEMENT_TITLE} (binding instructions from {relative_letter_path}):\n"
        f"{load_engagement_letter()}\n\n"
        "Apply these rules to every decision. If a task conflicts with them, refuse the "
        "conflicting action, identify the applicable boundary, cite the relevant clause from "
        f"{relative_letter_path}, and suggest a safe in-scope alternative. When you continue with "
        "an allowed action, explicitly state which engagement constraints are shaping your plan."
    )
