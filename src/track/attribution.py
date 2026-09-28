"""Who made a commit: commit -> PR -> AIDev, never the git author alone.

Three values, never "human" by default:
  agent       the commit belongs to an AIDev PR (by SHA, or by the PR number in its
              subject), or carries an explicit agent signature
  not_agent   a PR (or commit) was found, it is not in AIDev and carries no signature
  unknown     no PR could be found for the commit and no signature
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..repo.history import Commit

SQUASH_NUMBER = re.compile(r"\(#(\d+)\)\s*$")
MERGE_NUMBER = re.compile(r"^Merge pull request #(\d+)\b")

# (agent, pattern on "name <email>")
SIGNATURE_AUTHORS = (
    ("Copilot", re.compile(r"copilot-swe-agent|\+Copilot@users\.noreply\.github\.com", re.I)),
    ("Cursor", re.compile(r"cursoragent@cursor\.com|^Cursor Agent ", re.I)),
    ("Devin", re.compile(r"devin-ai-integration\[bot\]", re.I)),
    ("Google_Jules", re.compile(r"google-labs-jules\[bot\]", re.I)),
    ("Claude_Code", re.compile(r"claude\[bot\]|noreply@anthropic\.com", re.I)),
)
SIGNATURE_TRAILERS = (
    ("Claude_Code", re.compile(r"Generated with \[?Claude Code|Co-authored-by:\s*Claude\b", re.I)),
    ("Copilot", re.compile(r"Co-authored-by:\s*Copilot\b", re.I)),
    ("Cursor", re.compile(r"Co-authored-by:\s*Cursor\b", re.I)),
    ("Devin", re.compile(r"Co-authored-by:\s*devin-ai-integration", re.I)),
    ("OpenAI_Codex", re.compile(r"Co-authored-by:\s*(?:chatgpt-)?codex\b", re.I)),
)


def pr_number_in(message: str) -> int | None:
    subject = message.split("\n", 1)[0]
    m = SQUASH_NUMBER.search(subject) or MERGE_NUMBER.match(subject)
    return int(m.group(1)) if m else None


@dataclass
class PrIndex:
    by_number: dict[int, dict]
    by_commit: dict[str, dict]

    @classmethod
    def build(cls, rows: list[dict]) -> "PrIndex":
        by_number, by_commit = {}, {}
        for r in rows:
            by_number[r["number"]] = r
            for sha in r.get("commit_shas", ()):
                by_commit[sha] = r
        return cls(by_number, by_commit)


def signature(commit: Commit) -> str | None:
    who = f"{commit.author_name} <{commit.author_email}>"
    for agent, rx in SIGNATURE_AUTHORS:
        if rx.search(who):
            return agent
    for agent, rx in SIGNATURE_TRAILERS:
        if rx.search(commit.message):
            return agent
    return None


def attribute(commit: Commit, index: PrIndex) -> dict:
    pr = index.by_commit.get(commit.sha)
    if pr is not None:
        return {"author_kind": "agent", "agent": pr["agent"], "pr_number": pr["number"], "evidence": "aidev_pr_commit"}
    number = pr_number_in(commit.message)
    if number is not None and number in index.by_number:
        pr = index.by_number[number]
        return {"author_kind": "agent", "agent": pr["agent"], "pr_number": number, "evidence": "aidev_pr_number"}
    sig = signature(commit)
    if sig is not None:
        return {"author_kind": "agent", "agent": sig, "pr_number": number, "evidence": "signature"}
    if number is not None:
        return {"author_kind": "not_agent", "agent": None, "pr_number": number, "evidence": "pr_not_in_aidev"}
    return {"author_kind": "unknown", "agent": None, "pr_number": None, "evidence": "no_pr_found"}
