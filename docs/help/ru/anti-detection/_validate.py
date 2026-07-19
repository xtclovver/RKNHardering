#!/usr/bin/env python3
"""Validate anti-detection documentation coverage and internal links.

Run from repository root:
    python3 docs/help/ru/anti-detection/_validate.py

The script verifies the documentation itself. It does not compare the source tree
with an external baseline and does not make network requests to external links.
"""
from collections import Counter
from pathlib import Path
from urllib.parse import urljoin, urlsplit
import re
import sys

ROOT = Path(__file__).resolve().parents[4]
DOCS = ROOT / "docs"
DOC_DIR = Path(__file__).resolve().parent
MATRIX = (DOC_DIR / "matrix.md").read_text(encoding="utf-8")


def enum_values(path: Path, enum_name: str) -> list[str]:
    text = path.read_text(encoding="utf-8")
    match = re.search(rf"enum class {re.escape(enum_name)}\s*\{{(.*?)\n\}}", text, re.S)
    if not match:
        raise RuntimeError(f"Cannot parse {enum_name} from {path}")
    return [
        line.strip().rstrip(",")
        for line in match.group(1).splitlines()
        if line.strip() and not line.strip().startswith("//")
    ]


def permalink(path: Path) -> str | None:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return None
    match = re.search(r"(?m)^permalink:\s*(\S+)\s*$", text)
    if not match:
        return None
    value = match.group(1)
    if not value.startswith("/"):
        value = "/" + value
    if value != "/" and not value.endswith("/"):
        value += "/"
    return value


def matrix_rows(start_heading: str, end_heading: str, expected_columns: int) -> list[list[str]]:
    try:
        start = MATRIX.index(start_heading)
        end = MATRIX.index(end_heading, start)
    except ValueError as exc:
        raise RuntimeError(f"Cannot locate matrix section {start_heading!r}") from exc

    rows: list[list[str]] = []
    for line in MATRIX[start:end].splitlines():
        if not re.match(r"^\| (?:`[^`]+`|\[`[^`]+`\]\([^)]+\)) \|", line):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != expected_columns:
            raise RuntimeError(
                f"Matrix row has {len(cells)} columns, expected {expected_columns}: {line}"
            )
        rows.append(cells)
    return rows


native = enum_values(
    ROOT / "app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt",
    "NativeSignalId",
)
evidence = enum_values(
    ROOT / "app/src/main/java/com/notcvnt/rknhardering/model/CheckResult.kt",
    "EvidenceSource",
)
beta_text = (
    ROOT / "app/src/main/java/com/notcvnt/rknhardering/checker/BetaCheckRegistry.kt"
).read_text(encoding="utf-8")
beta = re.findall(r'definition\("(beta\.[^"]+)"', beta_text)

errors: list[str] = []
section_specs = (
    ("EvidenceSource", evidence, "## 1.", "## 2.", 6, 3, 4),
    ("NativeSignalId", native, "## 2.", "## 3.", 5, 2, 3),
    ("beta", beta, "## 3.", "## 4.", 7, 4, 5),
)
for label, expected, start, end, columns, non_root_index, root_index in section_specs:
    try:
        rows = matrix_rows(start, end, columns)
    except RuntimeError as exc:
        errors.append(str(exc))
        continue

    actual = []
    for row in rows:
        match = re.search(r"`([^`]+)`", row[0])
        if not match:
            errors.append(f"{label}: cannot parse ID cell {row[0]!r}")
            continue
        actual.append(match.group(1))
    expected_set = set(expected)
    actual_set = set(actual)
    missing = sorted(expected_set - actual_set)
    extra = sorted(actual_set - expected_set)
    duplicates = sorted(key for key, count in Counter(actual).items() if count != 1)
    if missing:
        errors.append(f"{label}: missing rows {missing}")
    if extra:
        errors.append(f"{label}: unexpected rows {extra}")
    if duplicates:
        errors.append(f"{label}: duplicate rows {duplicates}")
    if len(actual) != len(expected):
        errors.append(f"{label}: expected {len(expected)} rows, found {len(actual)}")

    for row in rows:
        row_id = row[0]
        if not row[non_root_index]:
            errors.append(f"{label}: empty non-root guidance for {row_id}")
        if not row[root_index]:
            errors.append(f"{label}: empty root guidance for {row_id}")

# Map Jekyll permalink URLs to source Markdown files.
permalink_map: dict[str, Path] = {}
for md in DOCS.rglob("*.md"):
    link = permalink(md)
    if link:
        if link in permalink_map:
            errors.append(
                f"duplicate permalink: {link} in {permalink_map[link].relative_to(ROOT)} "
                f"and {md.relative_to(ROOT)}"
            )
        permalink_map[link] = md

link_re = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
for md in sorted(DOC_DIR.glob("*.md")):
    text = md.read_text(encoding="utf-8")
    base = permalink(md)
    if not base:
        errors.append(f"missing permalink: {md.relative_to(ROOT)}")
        continue
    for raw in link_re.findall(text):
        if raw.startswith(("http://", "https://", "mailto:")):
            continue
        path_only = urlsplit(raw).path
        if not path_only:
            continue
        # First accept a real source-file relative link.
        source_candidate = (md.parent / path_only).resolve()
        if source_candidate.exists():
            continue
        # Then resolve as the rendered Jekyll URL, which is how links such as
        # ../network-path/ and ../../native/foo/ work in the published site.
        rendered = urljoin(base, path_only)
        if rendered != "/" and not rendered.endswith("/"):
            rendered += "/"
        if rendered not in permalink_map:
            errors.append(
                f"broken link: {md.relative_to(ROOT)} -> {raw} (renders as {rendered})"
            )

if errors:
    print("VALIDATION FAILED")
    for error in errors:
        print(" -", error)
    sys.exit(1)

print(
    f"OK: exact matrix coverage — {len(evidence)}/{len(evidence)} EvidenceSource, "
    f"{len(native)}/{len(native)} NativeSignalId, {len(beta)}/{len(beta)} beta IDs"
)
print("OK: every matrix row has non-root and root guidance")
print(f"OK: {len(permalink_map)} Jekyll permalinks indexed; anti-detection links resolve")
