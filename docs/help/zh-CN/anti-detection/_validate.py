#!/usr/bin/env python3
"""验证反检测文档的覆盖范围与内部链接。

请在仓库根目录运行：
    python3 docs/help/zh-CN/anti-detection/_validate.py

该脚本只验证文档本身，不会把源码树与外部基线比较，也不会向外部链接发起网络请求。
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
        raise RuntimeError(f"无法从 {path} 解析 {enum_name}")
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
        raise RuntimeError(f"找不到矩阵章节 {start_heading!r}") from exc

    rows: list[list[str]] = []
    for line in matrix[start:end].splitlines():
        if not re.match(r"^\| (?:`[^`]+`|\[`[^`]+`\]\([^)]+\)) \|", line):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != expected_columns:
            raise RuntimeError(
                f"矩阵行有 {len(cells)} 列，应为 {expected_columns} 列：{line}"
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
            raise RuntimeError(f"无法解析 ID 单元格 {row[0]!r}")
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
    coverage_source = "Kotlin 源码树"
elif RU_MATRIX_PATH.exists():
    # 纯文档分发包不包含 Android 源码树。此时使用保留的俄文矩阵作为
    # 不可变来源基线，检查翻译后的矩阵是否完整一致。
    baseline = RU_MATRIX_PATH.read_text(encoding="utf-8")
    evidence = matrix_ids(baseline, "## 1.", "## 2.", 6)
    native = matrix_ids(baseline, "## 2.", "## 3.", 5)
    beta = matrix_ids(baseline, "## 3.", "## 4.", 7)
    coverage_source = "保留的俄文文档矩阵"
else:
    raise RuntimeError(
        "Kotlin 源码树和 docs/help/ru/anti-detection/matrix.md 均不可用"
    )

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
            errors.append(f"{label}：无法解析 ID 单元格 {row[0]!r}")
            continue
        actual.append(match.group(1))
    expected_set = set(expected)
    actual_set = set(actual)
    missing = sorted(expected_set - actual_set)
    extra = sorted(actual_set - expected_set)
    duplicates = sorted(key for key, count in Counter(actual).items() if count != 1)
    if missing:
        errors.append(f"{label}：缺少行 {missing}")
    if extra:
        errors.append(f"{label}：存在意外行 {extra}")
    if duplicates:
        errors.append(f"{label}：存在重复行 {duplicates}")
    if len(actual) != len(expected):
        errors.append(f"{label}：应有 {len(expected)} 行，实际为 {len(actual)} 行")

    for row in rows:
        row_id = row[0]
        if not row[non_root_index]:
            errors.append(f"{label}：{row_id} 的无 root 指南为空")
        if not row[root_index]:
            errors.append(f"{label}：{row_id} 的有 root 指南为空")

# 建立 Jekyll permalink URL 到 Markdown 源文件的映射。
permalink_map: dict[str, Path] = {}
for md in DOCS.rglob("*.md"):
    link = permalink(md)
    if link:
        if link in permalink_map:
            errors.append(
                f"重复 permalink：{link}，位于 {permalink_map[link].relative_to(ROOT)} "
                f"和 {md.relative_to(ROOT)}"
            )
        permalink_map[link] = md

link_re = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
for md in sorted(DOC_DIR.glob("*.md")):
    text = md.read_text(encoding="utf-8")
    base = permalink(md)
    if not base:
        errors.append(f"缺少 permalink：{md.relative_to(ROOT)}")
        continue
    for raw in link_re.findall(text):
        if raw.startswith(("http://", "https://", "mailto:")):
            continue
        path_only = urlsplit(raw).path
        if not path_only:
            continue
        # 先接受真实存在的相对源文件链接。
        source_candidate = (md.parent / path_only).resolve()
        if source_candidate.exists():
            continue
        # 再按渲染后的 Jekyll URL 解析，例如 ../network-path/ 和
        # ../../native/foo/。
        rendered = urljoin(base, path_only)
        if rendered != "/" and not rendered.endswith("/"):
            rendered += "/"
        if rendered not in permalink_map:
            errors.append(
                f"损坏链接：{md.relative_to(ROOT)} -> {raw}（渲染为 {rendered}）"
            )

if errors:
    print("验证失败")
    for error in errors:
        print(" -", error)
    sys.exit(1)

print(f"通过：覆盖基线——{coverage_source}")
print(
    f"通过：矩阵精确覆盖——{len(evidence)}/{len(evidence)} EvidenceSource，"
    f"{len(native)}/{len(native)} NativeSignalId，{len(beta)}/{len(beta)} beta ID"
)
print("通过：每个矩阵条目均包含无 root 与有 root 指南")
print(f"通过：已索引 {len(permalink_map)} 个 Jekyll permalink；反检测内部链接均可解析")
