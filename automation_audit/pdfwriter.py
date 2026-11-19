"""A minimal, dependency-free PDF writer for the evidence report.

ClaimCheck has to emit a PDF from a clean clone with no network and no PDF
library, so this module writes the file directly: base-14 Helvetica fonts,
uncompressed content streams, one cross-reference table. It implements only what
the report needs - wrapped paragraphs, bullets, key/value lines, tables with
wrapping cells and repeated headers, rules, page breaks and a footer.

The output is deliberately plain: a reviewer can open it, select the text, and
diff it against the Markdown.
"""
from __future__ import annotations

from dataclasses import dataclass

# Helvetica and Helvetica-Bold advance widths (1/1000 em) for ASCII 32..126.
_HELV = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
    1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
    333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
    556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
]
_HELVB = [
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
    975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
    333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
    611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
]

_INK = (0.055, 0.102, 0.169)
_TEAL = (0.043, 0.361, 0.420)
_RUST = (0.541, 0.200, 0.141)
_GREY = (0.357, 0.400, 0.451)
_RULE = (0.835, 0.863, 0.894)

# characters the WinAnsi encoding cannot carry are folded to ASCII
_FOLD = {
    "\u2212": "-", "\u2013": "-", "\u2014": "-", "\u2018": "'", "\u2019": "'",
    "\u201c": '"', "\u201d": '"', "\u00b7": "-", "\u2264": "<=", "\u2265": ">=",
    "\u00d7": "x", "\u2026": "...", "\u00b0": "o", "\u2192": "->", "\u00e2": "a",
}


def _encode(text: str) -> bytes:
    out = []
    for ch in text:
        ch = _FOLD.get(ch, ch)
        try:
            out.append(ch.encode("cp1252"))
        except UnicodeEncodeError:
            out.append(b"?")
    return b"".join(out)


def _escape(raw: bytes) -> bytes:
    return raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


def _width(text: str, bold: bool, size: float) -> float:
    table = _HELVB if bold else _HELV
    total = 0
    for ch in text:
        code = ord(ch)
        total += table[code - 32] if 32 <= code <= 126 else 556
    return total * size / 1000.0


def _wrap(text: str, bold: bool, size: float, max_width: float) -> list[str]:
    """Greedy wrap; hard-splits a word that cannot fit on a line by itself."""
    words = str(text).replace("\r", " ").replace("\n", " ").split(" ")
    lines: list[str] = []
    cur = ""
    for word in words:
        if word == "":
            if cur:
                cur += " "
            continue
        trial = (cur + " " + word) if cur else word
        if _width(trial, bold, size) <= max_width:
            cur = trial
            continue
        if cur:
            lines.append(cur)
        if _width(word, bold, size) <= max_width:
            cur = word
            continue
        # hard split
        piece = ""
        for ch in word:
            if _width(piece + ch, bold, size) > max_width and piece:
                lines.append(piece)
                piece = ch
            else:
                piece += ch
        cur = piece
    if cur:
        lines.append(cur)
    return lines or [""]


@dataclass
class Page:
    ops: list[str]

    def add(self, op: str) -> None:
        self.ops.append(op)


class PdfBuilder:
    def __init__(self, *, width: float = 612, height: float = 792) -> None:
        self.width = width
        self.height = height
        self.margin_l = 36.0
        self.margin_r = 36.0
        self.margin_t = 34.0
        self.margin_b = 32.0
        self.pages: list[Page] = []
        self._new_page()
        self.y = self.height - self.margin_t

    # ---------------------------------------------------------------- geometry
    @property
    def content_width(self) -> float:
        return self.width - self.margin_l - self.margin_r

    def _new_page(self) -> None:
        self.pages.append(Page([]))
        self.y = self.height - self.margin_t

    def _space(self, amount: float) -> None:
        self.y -= amount
        if self.y < self.margin_b:
            self._new_page()

    def _put(self, x: float, y: float, text: str, *, bold: bool = False, size: float = 8.5, color=_INK) -> None:
        font = "F2" if bold else "F1"
        r, g, b = color
        self.pages[-1].add(
            f"BT {r:.3f} {g:.3f} {b:.3f} rg /{font} {size:.2f} Tf "
            f"1 0 0 1 {x:.2f} {y:.2f} Tm ({_escape(_encode(text)).decode('latin-1')}) Tj ET"
        )

    def _line(self, x1: float, y1: float, x2: float, y2: float, *, width: float = 0.6, color=_RULE) -> None:
        r, g, b = color
        self.pages[-1].add(
            f"{width:.2f} w {r:.3f} {g:.3f} {b:.3f} RG {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S"
        )

    # ------------------------------------------------------------------ blocks
    def title(self, text: str, *, size: float = 17.0) -> None:
        self._put(self.margin_l, self.y, text.upper(), bold=True, size=size, color=_INK)
        self._space(size + 4)

    def role(self, text: str) -> None:
        self._put(self.margin_l, self.y, text, bold=True, size=9.0, color=_TEAL)
        self._space(13)

    def heading(self, text: str) -> None:
        self._space(4)
        self._put(self.margin_l, self.y, text.upper(), bold=True, size=8.6, color=_INK)
        self._space(3)
        self._line(self.margin_l, self.y, self.width - self.margin_r, self.y, width=1.0, color=_INK)
        self._space(8)

    def paragraph(self, text: str, *, size: float = 8.6, leading: float = 10.6, color=_INK, bold: bool = False) -> None:
        for line in _wrap(text, bold, size, self.content_width):
            self._put(self.margin_l, self.y, line, bold=bold, size=size, color=color)
            self._space(leading)
        self._space(1.5)

    def note(self, text: str, *, size: float = 8.2, leading: float = 10.2) -> None:
        for line in _wrap(text, False, size, self.content_width - 8):
            self._put(self.margin_l + 8, self.y, line, size=size, color=_GREY)
            self._space(leading)
        self._space(1.0)

    def bullets(self, items: list[str], *, size: float = 8.6, leading: float = 10.6) -> None:
        for item in items:
            lines = _wrap(item, False, size, self.content_width - 11)
            for i, line in enumerate(lines):
                if i == 0:
                    self._put(self.margin_l, self.y, "-", bold=True, size=size)
                self._put(self.margin_l + 11, self.y, line, size=size)
                self._space(leading)
        self._space(1.0)

    def kv(self, pairs: list[tuple[str, str]], *, size: float = 7.6, leading: float = 9.4) -> None:
        for key, value in pairs:
            label = f"{key}: "
            bold_w = _width(label, True, size)
            self._put(self.margin_l, self.y, label, bold=True, size=size, color=_INK)
            avail = self.content_width - bold_w
            lines = _wrap(str(value), False, size, avail)
            for i, line in enumerate(lines):
                self._put(self.margin_l + (bold_w if i == 0 else bold_w), self.y, line, size=size, color=_INK)
                self._space(leading)
        self._space(1.0)

    def table(
        self,
        headers: list[str],
        rows: list[list[str]],
        widths: list[float],
        *,
        status_col: int | None = None,
        size: float = 7.5,
        leading: float = 9.2,
        header_size: float = 7.0,
    ) -> None:
        cols = [w * self.content_width for w in widths]
        pad = 3.0

        def row_lines(cells: list[str], bold: bool, fsize: float) -> list[list[str]]:
            return [_wrap(str(c), bold, fsize, cols[i] - pad) for i, c in enumerate(cells)]

        def header() -> None:
            wrapped = row_lines(headers, True, header_size)
            height = max(len(w) for w in wrapped) * leading + 2
            if self.y - height < self.margin_b:
                self._new_page()
            top = self.y
            for i, lines in enumerate(wrapped):
                x = self.margin_l + sum(cols[:i])
                for j, line in enumerate(lines):
                    self._put(x + pad / 2, top - leading * (j + 1) + 2, line.upper(), bold=True, size=header_size)
            self.y = top - height
            self._line(self.margin_l, self.y, self.width - self.margin_r, self.y, width=1.0, color=_INK)
            self._space(1.0)

        header()
        for row in rows:
            wrapped = row_lines(row, False, size)
            height = max(len(w) for w in wrapped) * leading + 2.5
            if self.y - height < self.margin_b:
                self._new_page()
                header()
            top = self.y
            for i, lines in enumerate(wrapped):
                x = self.margin_l + sum(cols[:i])
                colour = _INK
                if status_col is not None and i == status_col:
                    status = str(row[i])
                    colour = _TEAL if status.startswith("VERIFIED") else (_RUST if "NOT SUPPORTED" in status else _GREY)
                for j, line in enumerate(lines):
                    self._put(x + pad / 2, top - leading * (j + 1) + 2, line, size=size, color=colour,
                              bold=(status_col is not None and i == status_col))
            self.y = top - height
            self._line(self.margin_l, self.y, self.width - self.margin_r, self.y, width=0.5, color=_RULE)
            self._space(1.0)
        self._space(2.0)

    def footer(self, text: str) -> None:
        self._space(3)
        self._line(self.margin_l, self.y, self.width - self.margin_r, self.y, width=1.0, color=_INK)
        self._space(3)
        for line in _wrap(text, False, 7.6, self.content_width):
            self._put(self.margin_l, self.y, line, size=7.6, color=_GREY)
            self._space(9.0)

    # ------------------------------------------------------------------- output
    def save(self, path: str) -> None:
        objects: list[bytes] = []

        def obj(body: bytes) -> int:
            objects.append(body)
            return len(objects)  # 1-based object number

        # Reserve: 1 catalog, 2 pages, 3 F1, 4 F2, 5 F3
        objects = [b"", b"", b"", b"", b""]
        page_ids = []
        for page in self.pages:
            content = "\n".join(page.ops).encode("latin-1")
            content_id = len(objects) + 2
            page_id = len(objects) + 1
            objects.append(
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.width:.0f} {self.height:.0f}] "
                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> "
                f"/Contents {content_id} 0 R >>".encode("latin-1")
            )
            objects.append(b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream")
            page_ids.append(page_id)
        kids = " ".join(f"{pid} 0 R" for pid in page_ids)
        objects[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
        objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("latin-1")
        objects[2] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
        objects[3] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
        objects[4] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Oblique /Encoding /WinAnsiEncoding >>"

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for i, body in enumerate(objects, 1):
            offsets.append(len(out))
            out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
        xref_at = len(out)
        out += f"xref\n0 {len(objects) + 1}\n".encode()
        out += b"0000000000 65535 f \n"
        for off in offsets:
            out += f"{off:010d} 00000 n \n".encode()
        out += (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n".encode()
        )
        with open(path, "wb") as fh:
            fh.write(bytes(out))

    @property
    def page_count(self) -> int:
        return len(self.pages)


def render(document, path: str, *, pdf_items: int = 12) -> int:
    """Render a report Document to ``path``; returns the page count."""
    b = PdfBuilder()
    b.title(document.title)
    b.role(document.role)
    for section in document.sections:
        b.heading(section.heading)
        for kind, payload in section.blocks:
            if kind == "p":
                b.paragraph(str(payload))
            elif kind == "note":
                b.note(str(payload))
            elif kind == "bullets":
                b.bullets(list(payload))
            elif kind == "kv":
                b.kv(list(payload))
            elif kind == "table":
                rows = payload["rows"]
                if payload.get("limit"):
                    rows = rows[: payload["limit"]]
                b.table(payload["headers"], rows, payload["widths"], status_col=payload.get("status_col"))
    b.footer(document.footer)
    b.save(path)
    return b.page_count
