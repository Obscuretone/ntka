import os
from dataclasses import dataclass
from pathlib import Path


LOGO_TYPES = {".svg": "image/svg+xml", ".png": "image/png", ".webp": "image/webp", ".ico": "image/x-icon"}


@dataclass(frozen=True)
class Brand:
    name: str
    wordmark: str
    logo_type: str = "image/svg+xml"
    logo: bytes | None = None

    @property
    def logo_url(self):
        return "/brand/logo" if self.logo is not None else "/assets/obscuretone.svg"

    @classmethod
    def from_environment(cls):
        name = os.environ.get("IDENTITY_NAME", "Obscuretone Identity").strip()
        wordmark = os.environ.get("IDENTITY_WORDMARK", "obscuretone.").strip()
        if not (1 <= len(name) <= 60 and 1 <= len(wordmark) <= 40):
            raise ValueError("Set a display name and wordmark of 1–60 and 1–40 characters.")
        path = os.environ.get("IDENTITY_LOGO_FILE")
        if not path:
            return cls(name, wordmark)
        file = Path(path)
        mime = LOGO_TYPES.get(file.suffix.lower())
        if not file.is_absolute() or not file.is_file() or not mime:
            raise ValueError("IDENTITY_LOGO_FILE must be an absolute SVG, PNG, WebP, or ICO file path.")
        with file.open("rb") as logo:
            data = logo.read(512 * 1024 + 1)
        if not 0 < len(data) <= 512 * 1024:
            raise ValueError("IDENTITY_LOGO_FILE must be nonempty and no larger than 512 KiB.")
        return cls(name, wordmark, mime, data)
