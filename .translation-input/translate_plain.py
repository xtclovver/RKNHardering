#!/usr/bin/env python3
"""Translate Markdown documentation in a disposable CI workspace.

Inputs are ordinary UTF-8 Markdown files. The program preserves Markdown
structure, code fences, inline code, URLs, HTML, paths, commands, identifiers,
and link destinations while translating natural-language fragments.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

import argostranslate.package
import ctranslate2

CYRILLIC_RE = re.compile(r"[А-Яа-яЁё]")
LATIN_RE = re.compile(r"[A-Za-z]")
PERSIAN_RE = re.compile(r"[\u0600-\u06ff]")
CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]")
TOKEN_RE = re.compile(
    r"("
    r"`+[^`\n]*`+"
    r"|<https?://[^>\n]+>"
    r"|https?://[^\s<>\]\)]+"
    r"|mailto:[^\s<>\]\)]+"
    r"|<[^>\n]+>"
    r"|&[A-Za-z0-9#]+;"
    r")"
)
LINK_RE = re.compile(r"(!?)\[([^\]\n]*)\]\(([^)\n]+)\)")
FENCE_RE = re.compile(r"^\s*(```+|~~~+)")
FRONTMATTER_FIELD_RE = re.compile(r"^([A-Za-z0-9_-]+):(\s*)(.*)$")
TECH_ONLY_RE = re.compile(
    r"^(?:"
    r"[A-Z][A-Z0-9_]{1,}"
    r"|[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+"
    r"|[A-Za-z_][A-Za-z0-9_]*(?:/[A-Za-z0-9_.-]+)+"
    r"|[A-Za-z_][A-Za-z0-9_]*\([^)]*\)"
    r"|--?[A-Za-z0-9_-]+"
    r"|\d+(?:\.\d+){1,}"
    r")$"
)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def split_long_text(text: str, max_chars: int = 420) -> list[str]:
    if len(text) <= max_chars:
        return [text]
    pieces = re.split(r"(?<=[.!?…])(?=\s)|(?<=[;:])(?=\s)", text)
    out: list[str] = []
    buf = ""
    for piece in pieces:
        if not piece:
            continue
        if len(buf) + len(piece) <= max_chars:
            buf += piece
            continue
        if buf:
            out.append(buf)
            buf = ""
        while len(piece) > max_chars:
            cut = piece.rfind(" ", 0, max_chars + 1)
            if cut < max_chars // 2:
                cut = max_chars
            out.append(piece[:cut])
            piece = piece[cut:]
        buf = piece
    if buf:
        out.append(buf)
    return out or [text]


@dataclass
class ArgosBatchTranslator:
    model_path: Path
    source_code: str
    target_code: str
    batch_size: int = 64

    def __post_init__(self) -> None:
        if not self.model_path.is_file() or not zipfile.is_zipfile(self.model_path):
            raise RuntimeError(f"Invalid model package: {self.model_path}")
        argostranslate.package.install_from_path(str(self.model_path))
        packages = [
            p for p in argostranslate.package.get_installed_packages()
            if p.from_code == self.source_code and p.to_code == self.target_code
        ]
        if not packages:
            raise RuntimeError(f"Installed package {self.source_code}->{self.target_code} not found")
        self.pkg = packages[-1]
        self.engine = ctranslate2.Translator(
            str(self.pkg.package_path / "model"),
            device="cpu",
            inter_threads=max(1, min(4, os.cpu_count() or 2)),
            intra_threads=0,
            compute_type="auto",
        )
        self.cache: dict[str, str] = {}

    def translate_many(self, texts: Sequence[str]) -> list[str]:
        results: list[str | None] = [None] * len(texts)
        pending: dict[str, list[int]] = {}
        for idx, text in enumerate(texts):
            if text in self.cache:
                results[idx] = self.cache[text]
            else:
                pending.setdefault(text, []).append(idx)
        unique = list(pending)
        for start in range(0, len(unique), self.batch_size):
            batch = unique[start:start + self.batch_size]
            encoded = [self.pkg.tokenizer.encode(t) for t in batch]
            prefix = None
            if getattr(self.pkg, "target_prefix", ""):
                prefix = [[self.pkg.target_prefix]] * len(encoded)
            translated = self.engine.translate_batch(
                encoded,
                target_prefix=prefix,
                replace_unknowns=True,
                max_batch_size=self.batch_size,
                batch_type="examples",
                beam_size=1,
                num_hypotheses=1,
                length_penalty=0.2,
                return_scores=False,
            )
            for src, item in zip(batch, translated):
                value = self.pkg.tokenizer.decode(item.hypotheses[0]).strip()
                if not value and src.strip():
                    value = src
                self.cache[src] = value
                for idx in pending[src]:
                    results[idx] = value
            print(
                f"{self.source_code}->{self.target_code}: "
                f"{min(start + len(batch), len(unique))}/{len(unique)} unique fragments",
                flush=True,
            )
        return [x if x is not None else "" for x in results]


@dataclass
class Slot:
    original: str
    set_value: Callable[[str], None]


class MarkdownPlan:
    def __init__(self, text: str, target_lang: str):
        self.target_lang = target_lang
        self.parts: list[str] = []
        self.slots: list[Slot] = []
        self._parse(text)

    def _literal(self, value: str) -> None:
        self.parts.append(value)

    def _slot(self, value: str) -> None:
        index = len(self.parts)
        self.parts.append(value)
        self.slots.append(Slot(value, lambda translated, i=index: self._set(i, translated)))

    def _set(self, index: int, value: str) -> None:
        self.parts[index] = value

    @staticmethod
    def _should_translate(chunk: str) -> bool:
        stripped = chunk.strip()
        if not stripped or TECH_ONLY_RE.fullmatch(stripped):
            return False
        return bool(CYRILLIC_RE.search(stripped) or LATIN_RE.search(stripped))

    def _inline(self, text: str) -> None:
        pos = 0
        for link in LINK_RE.finditer(text):
            self._nonlink(text[pos:link.start()])
            bang, label, destination = link.groups()
            self._literal(f"{bang}[")
            self._nonlink(label)
            self._literal(f"]({destination})")
            pos = link.end()
        self._nonlink(text[pos:])

    def _nonlink(self, text: str) -> None:
        pos = 0
        for token in TOKEN_RE.finditer(text):
            self._maybe_slot(text[pos:token.start()])
            self._literal(token.group(0))
            pos = token.end()
        self._maybe_slot(text[pos:])

    def _maybe_slot(self, text: str) -> None:
        if not text:
            return
        m = re.match(r"^(\s*(?:#{1,6}\s+|[-*+]\s+|\d+[.)]\s+|>\s*)?)(.*?)(\s*)$", text, re.S)
        if not m:
            self._literal(text)
            return
        prefix, core, suffix = m.groups()
        self._literal(prefix)
        if self._should_translate(core):
            for piece in split_long_text(core):
                self._slot(piece) if self._should_translate(piece) else self._literal(piece)
        else:
            self._literal(core)
        self._literal(suffix)

    def _parse(self, text: str) -> None:
        lines = text.splitlines(keepends=True)
        in_fence = False
        fence_marker = ""
        in_frontmatter = bool(lines and lines[0].rstrip("\r\n") == "---")
        frontmatter_line = 0
        for line in lines:
            raw = line.rstrip("\r\n")
            newline = line[len(raw):]
            fence = FENCE_RE.match(raw)
            if fence:
                marker = fence.group(1)
                if not in_fence:
                    in_fence = True
                    fence_marker = marker[0]
                elif marker[0] == fence_marker:
                    in_fence = False
                self._literal(line)
                continue
            if in_fence:
                self._literal(line)
                continue
            if in_frontmatter:
                frontmatter_line += 1
                if frontmatter_line > 1 and raw == "---":
                    in_frontmatter = False
                    self._literal(line)
                    continue
                fm = FRONTMATTER_FIELD_RE.match(raw)
                if fm:
                    key, spacing, value = fm.groups()
                    if key == "permalink":
                        value = re.sub(r"/help/(?:ru|en|fa|zh-CN)/", f"/help/{self.target_lang}/", value)
                        self._literal(f"{key}:{spacing}{value}{newline}")
                    elif key in {"title", "description"}:
                        self._literal(f"{key}:{spacing}")
                        self._inline(value)
                        self._literal(newline)
                    else:
                        self._literal(line)
                else:
                    self._literal(line)
                continue
            if not raw.strip() or re.fullmatch(r"\s*\|?(?:\s*:?-{3,}:?\s*\|)+\s*", raw):
                self._literal(line)
                continue
            if raw.lstrip().startswith("|") and raw.rstrip().endswith("|"):
                leading = raw[: len(raw) - len(raw.lstrip())]
                body = raw[len(leading):]
                self._literal(leading)
                cells = body.split("|")
                for i, cell in enumerate(cells):
                    if i:
                        self._literal("|")
                    self._inline(cell)
                self._literal(newline)
            else:
                self._inline(raw)
                self._literal(newline)

    def source_chunks(self) -> list[str]:
        return [slot.original for slot in self.slots]

    def apply(self, translations: Sequence[str]) -> str:
        if len(translations) != len(self.slots):
            raise ValueError("Translation count mismatch")
        for slot, translated in zip(self.slots, translations):
            slot.set_value(translated)
        result = "".join(self.parts)
        return re.sub(
            r"/help/(?:ru|en|fa|zh-CN)/",
            f"/help/{self.target_lang}/",
            result,
        )


def translate_documents(
    source_dir: Path,
    target_dir: Path,
    target_lang: str,
    translator: ArgosBatchTranslator,
    only_missing: bool,
) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    plans: list[tuple[Path, Path, MarkdownPlan]] = []
    chunks: list[str] = []
    offsets: list[tuple[int, int]] = []
    for src in sorted(source_dir.glob("*.md")):
        dst = target_dir / src.name
        if only_missing and dst.exists():
            print(f"Keeping seeded English file: {dst.name}", flush=True)
            continue
        plan = MarkdownPlan(src.read_text(encoding="utf-8"), target_lang)
        start = len(chunks)
        chunks.extend(plan.source_chunks())
        offsets.append((start, len(chunks)))
        plans.append((src, dst, plan))
        print(f"Planned {src.name}: {len(plan.source_chunks())} fragments", flush=True)
    translated = translator.translate_many(chunks)
    for (src, dst, plan), (start, end) in zip(plans, offsets):
        rendered = plan.apply(translated[start:end])
        dst.write_text(rendered, encoding="utf-8", newline="\n")
        print(f"Wrote {target_lang}/{dst.name}", flush=True)


def validate(source: Path, output_root: Path) -> dict[str, object]:
    source_names = sorted(p.name for p in source.glob("*.md"))
    errors: list[str] = []
    manifest: dict[str, object] = {"source_files": source_names, "languages": {}}
    for lang in ("en", "fa", "zh-CN"):
        base = output_root / lang
        names = sorted(p.name for p in base.glob("*.md"))
        if names != source_names:
            errors.append(f"{lang}: file set differs from source")
        entries: dict[str, object] = {}
        for p in sorted(base.glob("*.md")):
            text = p.read_text(encoding="utf-8")
            expected = f"/help/{lang}/anti-detection/"
            if not text.startswith("---\n") or expected not in text:
                errors.append(f"{lang}/{p.name}: invalid front matter or permalink")
            if CYRILLIC_RE.search(text):
                errors.append(f"{lang}/{p.name}: untranslated Cyrillic remains")
            if lang == "fa" and not PERSIAN_RE.search(text):
                errors.append(f"{lang}/{p.name}: Persian script not detected")
            if lang == "zh-CN" and not CJK_RE.search(text):
                errors.append(f"{lang}/{p.name}: CJK script not detected")
            for marker in ("```", "~~~"):
                if sum(line.lstrip().startswith(marker) for line in text.splitlines()) % 2:
                    errors.append(f"{lang}/{p.name}: unbalanced {marker} fence")
            entries[p.name] = {"bytes": p.stat().st_size, "sha256": sha256(p)}
        manifest["languages"][lang] = entries
    if errors:
        raise RuntimeError("Validation failed:\n" + "\n".join(errors))
    return manifest


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", type=Path, required=True)
    ap.add_argument("--seed", type=Path, required=True)
    ap.add_argument("--models", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    output_root = args.output.parent / "localized-anti-detection"
    if output_root.exists():
        shutil.rmtree(output_root)
    (output_root / "en").mkdir(parents=True)
    for p in args.seed.glob("*.md"):
        shutil.copy2(p, output_root / "en" / p.name)

    models = {
        "ru_en": args.models / "translate-ru_en-1_9.argosmodel",
        "en_fa": args.models / "translate-en_fa-1_5.argosmodel",
        "en_zh": args.models / "translate-en_zh-1_9.argosmodel",
    }
    for name, path in models.items():
        if not path.is_file() or path.stat().st_size < 20 * 1024 * 1024:
            raise RuntimeError(f"Model {name} is absent or too small: {path}")

    ru_en = ArgosBatchTranslator(models["ru_en"], "ru", "en")
    translate_documents(args.source, output_root / "en", "en", ru_en, only_missing=True)
    del ru_en

    en_fa = ArgosBatchTranslator(models["en_fa"], "en", "fa")
    translate_documents(output_root / "en", output_root / "fa", "fa", en_fa, only_missing=False)
    del en_fa

    en_zh = ArgosBatchTranslator(models["en_zh"], "en", "zh")
    translate_documents(output_root / "en", output_root / "zh-CN", "zh-CN", en_zh, only_missing=False)
    del en_zh

    manifest = validate(args.source, output_root)
    manifest_path = output_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if args.output.exists():
        args.output.unlink()
    with zipfile.ZipFile(args.output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for p in sorted(output_root.rglob("*")):
            if p.is_file():
                zf.write(p, p.relative_to(output_root))
    with zipfile.ZipFile(args.output) as zf:
        bad = zf.testzip()
        if bad:
            raise RuntimeError(f"Corrupt output member: {bad}")
    print(f"OUTPUT={args.output}", flush=True)
    print(f"OUTPUT_SHA256={sha256(args.output)}", flush=True)


if __name__ == "__main__":
    main()
