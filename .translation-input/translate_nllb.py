#!/usr/bin/env python3
"""Translate Markdown documentation with NLLB while preserving technical syntax.

The script is intentionally strict: it rejects untranslated Cyrillic, missing target
script, malformed Markdown fences, altered protected tokens, and degenerate output.
"""
from __future__ import annotations

import argparse
import gc
import hashlib
import json
import os
import re
import shutil
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

import torch
from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

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
    r"|\*\*|__"
    r"|\b\d+(?:\.\d+){1,}\b"
    r"|\b(?:RKNHardering|VPNHide|Android|Magisk|KernelSU|APatch|Zygisk|LSPosed|Vector|Shizuku|SUSFS|Mihomo|Clash|Xray|sing-box)\b"
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
REPEATED_CHAR_RE = re.compile(r"([^\s\-_=*`|])\1{7,}")
REPEATED_TOKEN_RE = re.compile(r"(?:^|\s)(\S{1,24})(?:\s+\1){7,}(?:\s|$)", re.IGNORECASE)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def split_long_text(text: str, max_chars: int = 320) -> list[str]:
    if len(text) <= max_chars:
        return [text]
    pieces = re.split(r"(?<=[.!?…])(?=\s)|(?<=[;:])(?=\s)|(?<=。)|(?<=！)|(?<=？)", text)
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


def normalize_for_guard(text: str) -> str:
    return unicodedata.normalize("NFKC", text).strip()


def is_degenerate(source: str, translated: str, target_code: str) -> str | None:
    src = normalize_for_guard(source)
    out = normalize_for_guard(translated)
    if src and not out:
        return "empty output"
    if REPEATED_CHAR_RE.search(out):
        return "repeated-character loop"
    if REPEATED_TOKEN_RE.search(out):
        return "repeated-token loop"
    max_ratio = 4.0 if target_code != "zho_Hans" else 3.0
    if len(out) > max(180, int(len(src) * max_ratio) + 40):
        return f"output too long ({len(out)} vs {len(src)})"
    if len(src) > 35 and len(out) < max(3, int(len(src) * 0.08)):
        return f"output too short ({len(out)} vs {len(src)})"
    if target_code == "pes_Arab" and src and not PERSIAN_RE.search(out):
        return "Persian script absent"
    if target_code == "zho_Hans" and src and not CJK_RE.search(out):
        return "CJK script absent"
    if target_code == "eng_Latn" and src and not LATIN_RE.search(out):
        return "Latin script absent"
    return None


@dataclass
class NllbBatchTranslator:
    model_name: str
    revision: str
    source_code: str
    target_code: str
    batch_size: int = 12

    def __post_init__(self) -> None:
        os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
        torch.set_num_threads(max(1, min(4, os.cpu_count() or 2)))
        self.tokenizer = AutoTokenizer.from_pretrained(
            self.model_name,
            revision=self.revision,
            src_lang=self.source_code,
            use_fast=True,
        )
        self.model = AutoModelForSeq2SeqLM.from_pretrained(
            self.model_name,
            revision=self.revision,
            low_cpu_mem_usage=True,
        )
        self.model.eval()
        self.target_id = self.tokenizer.convert_tokens_to_ids(self.target_code)
        if not isinstance(self.target_id, int) or self.target_id < 0:
            raise RuntimeError(f"Unknown NLLB target code: {self.target_code}")
        self.cache: dict[str, str] = {}
        print(
            f"Loaded {self.model_name}@{self.revision[:12]} for "
            f"{self.source_code}->{self.target_code}, batch={self.batch_size}",
            flush=True,
        )

    def close(self) -> None:
        del self.model
        del self.tokenizer
        gc.collect()

    def _generate(self, batch: Sequence[str], *, retry: bool = False) -> list[str]:
        self.tokenizer.src_lang = self.source_code
        encoded = self.tokenizer(
            list(batch),
            return_tensors="pt",
            padding=True,
            truncation=True,
            max_length=480,
        )
        token_lengths = encoded["attention_mask"].sum(dim=1).tolist()
        too_long = [n for n in token_lengths if n >= 480]
        if too_long:
            raise RuntimeError(f"Source fragment reached tokenizer limit: {too_long[:5]}")
        kwargs = {
            "forced_bos_token_id": self.target_id,
            "max_new_tokens": 480,
            "num_beams": 1 if retry else 4,
            "do_sample": False,
            "no_repeat_ngram_size": 4 if retry else 3,
            "repetition_penalty": 1.25 if retry else 1.10,
            "length_penalty": 1.0,
            "early_stopping": False if retry else True,
            "use_cache": True,
        }
        with torch.inference_mode():
            generated = self.model.generate(**encoded, **kwargs)
        return [x.strip() for x in self.tokenizer.batch_decode(generated, skip_special_tokens=True)]

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
            translated = self._generate(batch)
            if len(translated) != len(batch):
                raise RuntimeError("Model returned an unexpected batch size")
            for src, first in zip(batch, translated):
                reason = is_degenerate(src, first, self.target_code)
                value = first
                if reason:
                    print(f"Retrying fragment after {reason}: {src[:100]!r}", flush=True)
                    value = self._generate([src], retry=True)[0]
                    second_reason = is_degenerate(src, value, self.target_code)
                    if second_reason:
                        raise RuntimeError(
                            f"Degenerate translation after retry ({second_reason})\n"
                            f"SOURCE: {src!r}\nOUTPUT: {value!r}"
                        )
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
        self.protected_tokens: list[str] = []
        self._parse(text)

    def _literal(self, value: str, *, protected: bool = False) -> None:
        self.parts.append(value)
        if protected and value:
            self.protected_tokens.append(value)

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
            self._literal(f"]({destination})", protected=True)
            pos = link.end()
        self._nonlink(text[pos:])

    def _nonlink(self, text: str) -> None:
        pos = 0
        for token in TOKEN_RE.finditer(text):
            self._maybe_slot(text[pos:token.start()])
            self._literal(token.group(0), protected=True)
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
                self._literal(line, protected=True)
                continue
            if in_fence:
                self._literal(line, protected=True)
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
                        self._literal(f"{key}:{spacing}{value}{newline}", protected=True)
                    elif key in {"title", "description"}:
                        self._literal(f"{key}:{spacing}")
                        self._inline(value)
                        self._literal(newline)
                    else:
                        self._literal(line, protected=True)
                else:
                    self._literal(line)
                continue
            if not raw.strip() or re.fullmatch(r"\s*\|?(?:\s*:?-{3,}:?\s*\|)+\s*", raw):
                self._literal(line, protected=True)
                continue
            if raw.lstrip().startswith("|") and raw.rstrip().endswith("|"):
                leading = raw[: len(raw) - len(raw.lstrip())]
                body = raw[len(leading):]
                self._literal(leading)
                cells = body.split("|")
                for i, cell in enumerate(cells):
                    if i:
                        self._literal("|", protected=True)
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
        result = re.sub(
            r"/help/(?:ru|en|fa|zh-CN)/",
            f"/help/{self.target_lang}/",
            result,
        )
        for token in set(self.protected_tokens):
            expected_count = self.protected_tokens.count(token)
            if result.count(token) < expected_count:
                raise RuntimeError(f"Protected token changed or lost: {token!r}")
        return result


def translate_documents(
    source_dir: Path,
    target_dir: Path,
    target_lang: str,
    translator: NllbBatchTranslator,
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


def validate(output_root: Path) -> dict[str, object]:
    source_names = sorted(p.name for p in (output_root / "en").glob("*.md"))
    errors: list[str] = []
    manifest: dict[str, object] = {"source_files": source_names, "languages": {}}
    if len(source_names) != 11:
        errors.append(f"expected 11 English source files, got {len(source_names)}")
    for lang in ("en", "fa", "zh-CN"):
        base = output_root / lang
        names = sorted(p.name for p in base.glob("*.md"))
        if names != source_names:
            errors.append(f"{lang}: file set differs from English")
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
            if REPEATED_CHAR_RE.search(text):
                errors.append(f"{lang}/{p.name}: repeated-character loop detected")
            if REPEATED_TOKEN_RE.search(text):
                errors.append(f"{lang}/{p.name}: repeated-token loop detected")
            for marker in ("```", "~~~"):
                if sum(line.lstrip().startswith(marker) for line in text.splitlines()) % 2:
                    errors.append(f"{lang}/{p.name}: unbalanced {marker} fence")
            if text.count("**") % 2:
                errors.append(f"{lang}/{p.name}: unbalanced bold marker")
            entries[p.name] = {"bytes": p.stat().st_size, "sha256": sha256(p)}
        manifest["languages"][lang] = entries
    if errors:
        raise RuntimeError("Validation failed:\n" + "\n".join(errors))
    return manifest


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", type=Path, required=True)
    ap.add_argument("--seed", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--model", default="facebook/nllb-200-distilled-600M")
    ap.add_argument("--revision", default="cb65f9d79affdfe51b915cf26acf7e4cfd0fe471")
    ap.add_argument("--batch-size", type=int, default=12)
    args = ap.parse_args()

    output_root = args.output.parent / "localized-anti-detection"
    if output_root.exists():
        shutil.rmtree(output_root)
    (output_root / "en").mkdir(parents=True)
    for p in args.seed.glob("*.md"):
        shutil.copy2(p, output_root / "en" / p.name)

    translator = NllbBatchTranslator(
        args.model, args.revision, "rus_Cyrl", "eng_Latn", args.batch_size
    )
    translate_documents(args.source, output_root / "en", "en", translator, only_missing=True)
    translator.close()

    translator = NllbBatchTranslator(
        args.model, args.revision, "eng_Latn", "pes_Arab", args.batch_size
    )
    translate_documents(output_root / "en", output_root / "fa", "fa", translator, only_missing=False)
    translator.close()

    translator = NllbBatchTranslator(
        args.model, args.revision, "eng_Latn", "zho_Hans", args.batch_size
    )
    translate_documents(output_root / "en", output_root / "zh-CN", "zh-CN", translator, only_missing=False)
    translator.close()

    manifest = validate(output_root)
    manifest.update(
        {
            "model": args.model,
            "revision": args.revision,
            "batch_size": args.batch_size,
        }
    )
    manifest_path = output_root / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

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
