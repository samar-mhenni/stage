CONCISE_LOCAL_FIRST = (
    "/no_think. Do not output hidden reasoning, thinking tags, or analysis traces. "
    "Use local evidence first: provided scan/report context, previous run excerpts, and configured database tools. "
    "Only ask the LLM to infer or generate what is not already present locally. Be brief, factual, and avoid repeating input."
)


def none_if_blank(value: str) -> str:
    return value or "None."


def not_provided_if_blank(value: str) -> str:
    return value or "Not provided."


def section(title: str, body: object) -> str:
    return f"{title}:\n{body}"
