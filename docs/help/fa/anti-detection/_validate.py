#!/usr/bin/env python3
"""کامل‌بودن مستندات ضدتشخیص و پیوندهای داخلی را اعتبارسنجی می‌کند.

اجرا از ریشهٔ مخزن:
    python3 docs/help/fa/anti-detection/_validate.py

اسکریپت فقط خود مستندات را بررسی می‌کند؛ هیچ درخواست شبکه‌ای نمی‌فرستد و
درخت منبع را با مبنای خارجی مقایسه نمی‌کند.
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
RU_MATRIX_PATH = DOCS / "help/ru/anti-detection/matrix.md"


def enum_values(path: Path, enum_name: str) -> list[str]:
    text = path.read_text(encoding="utf-8")
    match = re.search(rf"enum class {re.escape(enum_name)}\s*\{{(.*?)\n\}}", text, re.S)
    if not match:
        raise RuntimeError(f"امکان تجزیهٔ {enum_name} از {path} وجود ندارد")
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


def matrix_rows_from(
    matrix: str, start_heading: str, end_heading: str, expected_columns: int
) -> list[list[str]]:
    try:
        start = matrix.index(start_heading)
        end = matrix.index(end_heading, start)
    except ValueError as exc:
        raise RuntimeError(f"بخش ماتریس پیدا نشد: {start_heading!r}") from exc

    rows: list[list[str]] = []
    for line in matrix[start:end].splitlines():
        if not re.match(r"^\| (?:`[^`]+`|\[`[^`]+`\]\([^)]+\)) \|", line):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != expected_columns:
            raise RuntimeError(
                f"ردیف ماتریس {len(cells)} ستون دارد؛ انتظار {expected_columns} ستون بود: {line}"
            )
        rows.append(cells)
    return rows


def matrix_rows(start_heading: str, end_heading: str, expected_columns: int) -> list[list[str]]:
    return matrix_rows_from(MATRIX, start_heading, end_heading, expected_columns)


def matrix_ids(
    matrix: str, start_heading: str, end_heading: str, expected_columns: int
) -> list[str]:
    ids: list[str] = []
    for row in matrix_rows_from(matrix, start_heading, end_heading, expected_columns):
        match = re.search(r"`([^`]+)`", row[0])
        if not match:
            raise RuntimeError(f"شناسه از سلول قابل تجزیه نیست: {row[0]!r}")
        ids.append(match.group(1))
    return ids


native_source = ROOT / "app/src/main/java/com/notcvnt/rknhardering/model/NativeSignalId.kt"
evidence_source = ROOT / "app/src/main/java/com/notcvnt/rknhardering/model/CheckResult.kt"
beta_source = ROOT / "app/src/main/java/com/notcvnt/rknhardering/checker/BetaCheckRegistry.kt"

if native_source.exists() and evidence_source.exists() and beta_source.exists():
    native = enum_values(native_source, "NativeSignalId")
    evidence = enum_values(evidence_source, "EvidenceSource")
    beta_text = beta_source.read_text(encoding="utf-8")
    beta = re.findall(r'definition\("(beta\.[^"]+)"', beta_text)
    coverage_source = "درخت منبع Kotlin"
elif RU_MATRIX_PATH.exists():
    # توزیع‌های فقط‌مستندات، درخت منبع Android را ندارند. در آن حالت،
    # ماتریس روسیِ حفظ‌شده مبنای تغییرناپذیر برای بررسی ترجمه است.
    baseline = RU_MATRIX_PATH.read_text(encoding="utf-8")
    evidence = matrix_ids(baseline, "## 1.", "## 2.", 6)
    native = matrix_ids(baseline, "## 2.", "## 3.", 5)
    beta = matrix_ids(baseline, "## 3.", "## 4.", 7)
    coverage_source = "ماتریس حفظ‌شدهٔ مستندات روسی"
else:
    raise RuntimeError(
        "نه درخت منبع Kotlin و نه docs/help/ru/anti-detection/matrix.md در دسترس نیست"
    )

errors: list[str] = []
section_specs = (
    ("EvidenceSource", evidence, "## ۱.", "## ۲.", 6, 3, 4),
    ("NativeSignalId", native, "## ۲.", "## ۳.", 5, 2, 3),
    ("beta", beta, "## ۳.", "## ۴.", 7, 4, 5),
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
            errors.append(f"{label}: شناسه از سلول قابل تجزیه نیست {row[0]!r}")
            continue
        actual.append(match.group(1))
    expected_set = set(expected)
    actual_set = set(actual)
    missing = sorted(expected_set - actual_set)
    extra = sorted(actual_set - expected_set)
    duplicates = sorted(key for key, count in Counter(actual).items() if count != 1)
    if missing:
        errors.append(f"{label}: ردیف‌های غایب {missing}")
    if extra:
        errors.append(f"{label}: ردیف‌های غیرمنتظره {extra}")
    if duplicates:
        errors.append(f"{label}: ردیف‌های تکراری {duplicates}")
    if len(actual) != len(expected):
        errors.append(f"{label}: انتظار {len(expected)} ردیف بود، {len(actual)} ردیف پیدا شد")

    for row in rows:
        row_id = row[0]
        if not row[non_root_index]:
            errors.append(f"{label}: راهنمای بدون روت برای {row_id} خالی است")
        if not row[root_index]:
            errors.append(f"{label}: راهنمای روت برای {row_id} خالی است")

# نشانی‌های `permalink` در Jekyll را به فایل‌های Markdown نگاشت می‌کند.
permalink_map: dict[str, Path] = {}
for md in DOCS.rglob("*.md"):
    link = permalink(md)
    if link:
        if link in permalink_map:
            errors.append(
                f"`permalink` تکراری: {link} در {permalink_map[link].relative_to(ROOT)} "
                f"و {md.relative_to(ROOT)}"
            )
        permalink_map[link] = md

link_re = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
for md in sorted(DOC_DIR.glob("*.md")):
    text = md.read_text(encoding="utf-8")
    base = permalink(md)
    if not base:
        errors.append(f"`permalink` وجود ندارد: {md.relative_to(ROOT)}")
        continue
    for raw in link_re.findall(text):
        if raw.startswith(("http://", "https://", "mailto:")):
            continue
        path_only = urlsplit(raw).path
        if not path_only:
            continue
        source_candidate = (md.parent / path_only).resolve()
        if source_candidate.exists():
            continue
        rendered = urljoin(base, path_only)
        if rendered != "/" and not rendered.endswith("/"):
            rendered += "/"
        if rendered not in permalink_map:
            errors.append(
                f"پیوند خراب: {md.relative_to(ROOT)} -> {raw} (خروجی Jekyll: {rendered})"
            )

if errors:
    print("اعتبارسنجی ناموفق بود")
    for error in errors:
        print(" -", error)
    sys.exit(1)

print(f"تأیید شد: مبنای پوشش — {coverage_source}")
print(
    f"تأیید شد: پوشش دقیق ماتریس — {len(evidence)}/{len(evidence)} EvidenceSource، "
    f"{len(native)}/{len(native)} NativeSignalId، {len(beta)}/{len(beta)} شناسهٔ beta"
)
print("تأیید شد: همهٔ ردیف‌های ماتریس راهنمای بدون روت و با روت دارند")
print(f"تأیید شد: تعداد {len(permalink_map)} پیوند دائمی در Jekyll نمایه شد؛ پیوندهای بخش ضدتشخیص معتبرند")
