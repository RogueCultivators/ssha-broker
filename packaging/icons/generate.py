#!/usr/bin/env python3
"""Draw the ssha app icon.

Run with:  python3 packaging/icons/generate.py

Writes the icon set next to this file:
  ssha-{16,24,32,48,64,128,256,512,1024}.png   for Linux hicolor themes
  ssha.ico                                     for Windows
  ssha.icns                                    for macOS

Everything is drawn once at 1024px and scaled down with Lanczos, which is how
the rounded corners and the stroke ends stay clean at 16px.
"""

import struct
from pathlib import Path

from PIL import Image, ImageDraw

HERE = Path(__file__).resolve().parent

# A dark tile so the icon holds up on a light desktop, and an accent bright
# enough to separate from a dark one.
BG_TOP = (31, 38, 51, 255)
BG_BOTTOM = (18, 22, 29, 255)
RING = (58, 70, 90, 255)
GLYPH = (106, 169, 255, 255)

S = 1024  # master size


def rounded_mask(size: int, radius: int) -> Image.Image:
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, size - 1, size - 1), radius=radius, fill=255)
    return mask


def vertical_gradient(size: int, top, bottom) -> Image.Image:
    grad = Image.new("RGBA", (1, size))
    for y in range(size):
        t = y / max(size - 1, 1)
        grad.putpixel(
            (0, y),
            tuple(round(top[i] + (bottom[i] - top[i]) * t) for i in range(4)),
        )
    return grad.resize((size, size))


def draw_tile(size: int) -> Image.Image:
    """The rounded tile every variant sits on."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    radius = round(size * 0.22)
    img.paste(vertical_gradient(size, BG_TOP, BG_BOTTOM), (0, 0), rounded_mask(size, radius))
    ring = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    ImageDraw.Draw(ring).rounded_rectangle(
        (0, 0, size - 1, size - 1), radius=radius, outline=RING, width=max(1, round(size * 0.012))
    )
    img.alpha_composite(ring)
    return img


def chevron(d: ImageDraw.ImageDraw, size: int, stroke: float, x0: float, x1: float, y0: float, ym: float, y1: float) -> None:
    pts = [(size * x0, size * y0), (size * x1, size * ym), (size * x0, size * y1)]
    d.line(pts, fill=GLYPH, width=round(stroke), joint="curve")
    # Rounded caps: ImageDraw.line has square ends, which look cut off.
    for x, y in pts:
        d.ellipse((x - stroke / 2, y - stroke / 2, x + stroke / 2, y + stroke / 2), fill=GLYPH)


def draw_small(size: int) -> Image.Image:
    """16 and 24 pixels get a simplified, bolder glyph: at that size the cursor
    bar and the normal stroke width just smear into mush."""
    img = draw_tile(size)
    glyph = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(glyph)
    stroke = size * 0.155
    chevron(d, size, stroke, 0.30, 0.66, 0.26, 0.50, 0.74)
    img.alpha_composite(glyph)
    return img


def draw_master() -> Image.Image:
    img = draw_tile(S)
    radius = round(S * 0.22)

    tile = vertical_gradient(S, BG_TOP, BG_BOTTOM)
    img.paste(tile, (0, 0), rounded_mask(S, radius))

    glyph = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(glyph)
    stroke = S * 0.098
    # A terminal prompt: ">" then a cursor bar sitting on the baseline, where an
    # underscore belongs. It says "this runs commands" without resorting to a
    # pictogram of a server.
    chevron(d, S, stroke, 0.26, 0.50, 0.28, 0.50, 0.72)
    d.rounded_rectangle(
        (S * 0.60, S * 0.645, S * 0.80, S * 0.645 + stroke),
        radius=stroke / 2,
        fill=GLYPH,
    )
    img.alpha_composite(glyph)
    return img


def render(master: Image.Image, size: int) -> Image.Image:
    """Small sizes are drawn at their own scale rather than downscaled from the
    master, because the cursor bar does not survive a 64x reduction."""
    if size <= 24:
        return draw_small(size)
    return master.resize((size, size), Image.LANCZOS)


def write_pngs(master: Image.Image, sizes: list[int]) -> None:
    for size in sizes:
        render(master, size).save(HERE / f"ssha-{size}.png")
    print("png:", ", ".join(str(s) for s in sizes))


def write_ico(master: Image.Image) -> None:
    sizes = [16, 24, 32, 48, 64, 128, 256]
    frames = [render(master, s).convert("RGBA") for s in sizes]
    frames[-1].save(HERE / "ssha.ico", format="ICO", append_images=frames[:-1],
                    sizes=[(s, s) for s in sizes])
    print("ico:", ", ".join(str(s) for s in sizes))


def write_icns(master: Image.Image) -> None:
    """ICNS is a header plus typed chunks. PNG data is accepted since 10.7, so
    no macOS tooling is needed to produce it."""
    chunks = {
        b"ic11": 32,    # 16@2x
        b"ic12": 64,    # 32@2x
        b"ic07": 128,
        b"ic13": 256,   # 128@2x
        b"ic08": 256,
        b"ic14": 512,   # 256@2x
        b"ic09": 512,
        b"ic10": 1024,  # 512@2x
    }
    body = b""
    for kind, size in chunks.items():
        tmp = HERE / f".icns-{size}.png"
        render(master, size).save(tmp, format="PNG")
        data = tmp.read_bytes()
        tmp.unlink()
        body += kind + struct.pack(">I", len(data) + 8) + data
    out = b"icns" + struct.pack(">I", len(body) + 8) + body
    (HERE / "ssha.icns").write_bytes(out)
    print("icns:", ", ".join(str(s) for s in chunks.values()))


def main() -> None:
    master = draw_master()
    write_pngs(master, [16, 24, 32, 48, 64, 128, 256, 512, 1024])
    write_ico(master)
    write_icns(master)
    master.save(HERE / "ssha-master.png")
    print("wrote the icon set to", HERE)


if __name__ == "__main__":
    main()
