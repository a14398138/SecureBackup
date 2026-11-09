#!/usr/bin/env python3
"""Launcher icon for the encrypted-backup app: white padlock on a blue gradient."""
from PIL import Image, ImageDraw

S = 1024  # master canvas

# --- background: vertical gradient, rounded corners are left to the OS mask;
# Android legacy icons are square, so fill the whole canvas. ---
top = (37, 99, 235)     # #2563EB
bottom = (30, 58, 138)  # #1E3A8A
img = Image.new("RGB", (S, S))
for y in range(S):
    t = y / (S - 1)
    img.paste(tuple(round(top[i] + (bottom[i] - top[i]) * t) for i in range(3)), (0, y, S, y + 1))
d = ImageDraw.Draw(img)

cx = S // 2

# --- shackle: white ring punched with the background colour ---
outer = (cx - 185, 170, cx + 185, 540)
d.ellipse(outer, fill=(255, 255, 255))
inner = (outer[0] + 88, outer[1] + 88, outer[2] - 88, outer[3] - 88)
# punch the hole with the local gradient colour (approx. mid tone)
d.ellipse(inner, fill=(34, 84, 196))

# --- body: white rounded rectangle covering the ring's lower half ---
body = (cx - 265, 460, cx + 265, 850)
d.rounded_rectangle(body, radius=72, fill=(255, 255, 255))

# --- keyhole: circle + stem in the background tone ---
kh = (30, 64, 175)
d.ellipse((cx - 58, 592, cx + 58, 708), fill=kh)
d.polygon([(cx - 34, 660), (cx + 34, 660), (cx + 52, 782), (cx - 52, 782)], fill=kh)

# --- export all densities ---
sizes = {
    "mipmap-mdpi": 48,
    "mipmap-hdpi": 72,
    "mipmap-xhdpi": 96,
    "mipmap-xxhdpi": 144,
    "mipmap-xxxhdpi": 192,
}
import os
base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app/src/main/res")
for folder, px in sizes.items():
    out = img.resize((px, px), Image.LANCZOS)
    out.save(os.path.join(base, folder, "ic_launcher.png"))
    print(folder, px)
img.save(os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon-preview.png"))
print("preview saved")
