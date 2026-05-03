from __future__ import annotations

from dataclasses import dataclass
from typing import List
import re


class PatchValidationError(ValueError):
    """Raised when a diff fails validation."""


@dataclass
class DiffHunk:
    header: str
    lines: List[str]


@dataclass
class DiffSummary:
    target_file: str
    hunks: List[DiffHunk]
    added_lines: int
    removed_lines: int


def normalize_diff_text(diff_text: str) -> str:
    """Strip markdown fences, DeepSeek <think> blocks, or surrounding noise and return raw diff."""
    if not diff_text:
        return ""
    text = diff_text.strip()
    # Strip DeepSeek-R1 <think>...</think> reasoning blocks
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    if "```" in text:
        lines = text.splitlines()
        cleaned = []
        inside = False
        for line in lines:
            if line.strip().startswith("```"):
                inside = not inside
                continue
            if inside:
                cleaned.append(line)
        if cleaned:
            text = "\n".join(cleaned).strip()
    # If still contains extra text before diff headers, trim
    diff_start = None
    for idx, line in enumerate(text.splitlines()):
        if line.startswith("--- "):
            diff_start = idx
            break
    if diff_start is not None:
        text = "\n".join(text.splitlines()[diff_start:]).strip()
    return text


def parse_unified_diff(diff_text: str) -> DiffSummary:
    """Parse and validate unified diff. Raises PatchValidationError on failure."""
    text = normalize_diff_text(diff_text)
    if not text:
        raise PatchValidationError("Empty diff")
    if "Binary files" in text:
        raise PatchValidationError("Binary diff is not allowed")

    lines = text.splitlines()
    if not lines or not lines[0].startswith("--- "):
        raise PatchValidationError("Diff must start with '---'")

    file_headers = []
    hunk_indices = []
    for idx, line in enumerate(lines):
        if line.startswith("--- "):
            file_headers.append(idx)
        if line.startswith("@@ "):
            hunk_indices.append(idx)
    if len(file_headers) != 1:
        raise PatchValidationError("Only one file diff is allowed")
    if not hunk_indices:
        raise PatchValidationError("Diff must contain at least one hunk")

    if len(lines) < 2 or not lines[1].startswith("+++ "):
        raise PatchValidationError("Diff missing '+++' header")

    from_file = lines[0][4:].strip()
    to_file = lines[1][4:].strip()
    if from_file == "/dev/null" or to_file == "/dev/null":
        raise PatchValidationError("File creation/deletion not allowed")

    target_file = to_file
    if target_file.startswith("b/"):
        target_file = target_file[2:]
    if target_file.startswith("a/"):
        target_file = target_file[2:]

    # Ensure no additional file headers
    if len([l for l in lines if l.startswith("--- ") or l.startswith("+++ ")]) > 2:
        raise PatchValidationError("Multiple file headers detected")

    hunks: List[DiffHunk] = []
    added = 0
    removed = 0
    current_hunk = None
    for line in lines[2:]:
        if line.startswith("@@ "):
            if current_hunk:
                hunks.append(current_hunk)
            current_hunk = DiffHunk(header=line, lines=[])
            continue
        if current_hunk is None:
            continue
        current_hunk.lines.append(line)
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    if current_hunk:
        hunks.append(current_hunk)

    if not hunks:
        raise PatchValidationError("No hunks found in diff")

    return DiffSummary(
        target_file=target_file,
        hunks=hunks,
        added_lines=added,
        removed_lines=removed,
    )


def apply_unified_diff(original_text: str, diff_text: str) -> str:
    """Apply a unified diff to original_text and return patched text."""
    summary = parse_unified_diff(diff_text)
    lines = original_text.splitlines()
    out_lines = []
    idx = 0

    # Parse a unified diff @@ hunk header and return old/new start and length values.
    def parse_hunk_header(header: str):
        match = re.match(r"@@\s*-(\d+)(?:,(\d+))?\s*\+(\d+)(?:,(\d+))?\s*@@", header)
        if not match:
            raise PatchValidationError(f"Invalid hunk header: {header}")
        old_start = int(match.group(1))
        old_len = int(match.group(2) or 1)
        new_start = int(match.group(3))
        new_len = int(match.group(4) or 1)
        return old_start, old_len, new_start, new_len

    for hunk in summary.hunks:
        old_start, old_len, new_start, new_len = parse_hunk_header(hunk.header)
        # Copy unchanged lines before hunk
        while idx < old_start - 1:
            if idx >= len(lines):
                raise PatchValidationError("Diff hunk exceeds original text length")
            out_lines.append(lines[idx])
            idx += 1
        # Apply hunk
        for hline in hunk.lines:
            if hline.startswith(" "):
                if idx >= len(lines):
                    raise PatchValidationError("Diff context line exceeds original text length")
                out_lines.append(lines[idx])
                idx += 1
            elif hline.startswith("-"):
                if idx >= len(lines):
                    raise PatchValidationError("Diff removal exceeds original text length")
                idx += 1
            elif hline.startswith("+"):
                out_lines.append(hline[1:])
            else:
                # Unexpected line, treat as context
                if idx >= len(lines):
                    raise PatchValidationError("Diff line exceeds original text length")
                out_lines.append(lines[idx])
                idx += 1
    # Append remaining lines
    out_lines.extend(lines[idx:])
    return "\n".join(out_lines)
