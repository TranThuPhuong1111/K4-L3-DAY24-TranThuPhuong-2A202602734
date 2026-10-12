import sys


def use_utf8_stdio() -> None:
    """Ép stdout/stderr sang UTF-8 cho các CLI in tiếng Việt.

    Trên Windows, khi output bị pipe/redirect, Python dùng code page ANSI
    (vd cp1252) nên print("Đã ...") ném UnicodeEncodeError.
    """
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
