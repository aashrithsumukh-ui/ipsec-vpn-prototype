import re
import os

print("Reading frontend/index.html...")
with open("frontend/index.html", "r", encoding="utf-8") as f:
    content = f.read()

print(f"Original file length: {len(content)} characters, {len(content.splitlines())} lines")
