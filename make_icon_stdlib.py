#!/usr/bin/env python3
"""Launcher icon generator (stdlib only, no Pillow).

Reproduces make_icon.py: white padlock on a blue vertical gradient.
Renders a 1024x1024 master with shape masks, then box-filters down to
each density. Written so CI can regenerate icons without pip/Pillow.
"""
import os
import struct
import zlib

S = 1024  # master canvas

TOP = (37, 99, 235)      # #2563EB
BOTTOM = (30, 58, 138)   # #1E3A8A
WHITE = (255, 255, 255)
PUNCH = (34, 84, 196)    # mid tone used for the shackle hole
KH = (30, 64, 175)       # keyhole colour

CX = S // 2


def in_ellipse(x, y, cx, cy, rx, ry):
    dx = (x + 0.5 - cx) / rx
    dy = (y + 0.5 - cy) / ry
    return dx * dx + dy * dy <= 1.0


def in_rounded_rect(x, y, l, t, r, b, rad):
    px, py = x + 0.5, y + 0.5
    if px < l or px > r or py < t or py > b:
        return False
    if (l + rad <= px <= r - rad) or (t + rad <= py <= b - rad):
        return True
    qx = min(max(px, l + rad), r - rad)
    qy = min(max(py, t + rad), b - rad)
    dx, dy = px - qx, py - qy
    return dx * dx + dy * dy <= rad * rad


def in_keyhole_stem(x, y):
    px, py = x + 0.5, y + 0.5
    # polygon [(CX-34, 660), (CX+34, 660), (CX+52, 782), (CX-52, 782)]
    x0, y0, x1, y1 = CX - 52.0, 660.0, CX + 52.0, 782.0
    if py < y0 or py > y1:
        return False
    # left edge from (CX-34,y0) to (CX-52,y1); right edge mirrors it
    t = (py - y0) / (y1 - y0)
    lx = (CX - 34.0) + t * ((CX - 52.0) - (CX - 34.0))
    rx = (CX + 34.0) + t * ((CX + 52.0) - (CX + 34.0))
    return lx <= px <= rx


def render_master():
    px = bytearray(S * S * 3)
    for y in range(S):
        t = y / (S - 1)
        base = tuple(round(TOP[i] + (BOTTOM[i] - TOP[i]) * t) for i in range(3))
        row = y * S * 3
        for x in range(S):
            if in_ellipse(x, y, CX, 355.0, 185.0, 185.0):
                c = WHITE
                if in_ellipse(x, y, CX, 355.0, 97.0, 97.0):
                    c = PUNCH
            elif in_rounded_rect(x, y, CX - 265, 460, CX + 265, 850, 72):
                c = WHITE
            else:
                c = base
            if c is WHITE and in_keyhole_stem(x, y):
                c = KH
            if in_ellipse(x, y, CX, 650.0, 58.0, 58.0):
                c = KH
            i = row + x * 3
            px[i] = c[0]
            px[i + 1] = c[1]
            px[i + 2] = c[2]
    return px


def downscale(master, size):
    out = bytearray(size * size * 3)
    win = S / size
    area = win * win
    for oy in range(size):
        ys, ye = oy * win, (oy + 1) * win
        for ox in range(size):
            xs, xe = ox * win, (ox + 1) * win
            r = g = b = 0.0
            for sy in range(int(ys), max(int(ys), int(round(ye)))):
                wy = min(sy + 1, ye) - max(sy, ys)
                if wy <= 0:
                    continue
                row = sy * S * 3
                for sx in range(int(xs), max(int(xs), int(round(xe)))):
                    wx = min(sx + 1, xe) - max(sx, xs)
                    if wx <= 0:
                        continue
                    w = wx * wy
                    i = row + sx * 3
                    r += master[i] * w
                    g += master[i + 1] * w
                    b += master[i + 2] * w
            o = (oy * size + ox) * 3
            out[o] = min(255, int(round(r / area)))
            out[o + 1] = min(255, int(round(g / area)))
            out[o + 2] = min(255, int(round(b / area)))
    return out


def write_png(path, data, size):
    raw = bytearray()
    for y in range(size):
        raw.append(0)  # filter type 0
        raw += data[y * size * 3:(y + 1) * size * 3]

    def chunk(tag, payload):
        c = struct.pack(">I", len(payload)) + tag + payload
        return c + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)  # 8-bit RGB
    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
           + chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b""))
    with open(path, "wb") as f:
        f.write(png)


def main():
    sizes = {
        "mipmap-mdpi": 48,
        "mipmap-hdpi": 72,
        "mipmap-xhdpi": 96,
        "mipmap-xxhdpi": 144,
        "mipmap-xxxhdpi": 192,
    }
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app/src/main/res")
    master = render_master()
    for folder, px in sizes.items():
        d = os.path.join(base, folder)
        os.makedirs(d, exist_ok=True)
        write_png(os.path.join(d, "ic_launcher.png"), downscale(master, px), px)
        print(folder, px)


if __name__ == "__main__":
    main()
