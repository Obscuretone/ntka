import os
from dataclasses import dataclass
from pathlib import Path


IMAGE_TYPES = {".svg": "image/svg+xml", ".png": "image/png", ".webp": "image/webp", ".ico": "image/x-icon"}


@dataclass(frozen=True)
class Brand:
    name: str
    wordmark: str
    logo_type: str = "image/svg+xml"
    logo: bytes | None = None
    hero: bytes | None = None
    hero_type: str = ""
    css: bytes | None = None
    site_styles: Path | None = None

    @property
    def logo_url(self):
        return "/brand/logo" if self.logo is not None else None

    @classmethod
    def from_environment(cls):
        name = os.environ.get("IDENTITY_NAME", "NTKA").strip()
        wordmark = os.environ.get("IDENTITY_WORDMARK", "NTKA").strip()
        if not (1 <= len(name) <= 60 and 1 <= len(wordmark) <= 40):
            raise ValueError("Set a display name and wordmark of 1–60 and 1–40 characters.")
        logo, logo_type = asset("IDENTITY_LOGO_FILE", IMAGE_TYPES, 512 * 1024)
        hero, hero_type = asset("IDENTITY_HERO_FILE", IMAGE_TYPES, 2 * 1024 * 1024)
        css, _ = asset("IDENTITY_CSS_FILE", {".css": "text/css"}, 128 * 1024)
        path = os.environ.get("IDENTITY_SITE_CSS_DIR")
        site_styles = Path(path) if path else None
        if site_styles and (not site_styles.is_absolute() or not site_styles.is_dir()):
            raise ValueError("IDENTITY_SITE_CSS_DIR must be an absolute directory.")
        return cls(name, wordmark, logo_type, logo, hero, hero_type, css, site_styles)


def asset(setting, types, limit):
    path = os.environ.get(setting)
    if not path:
        return None, ""
    file = Path(path)
    mime = types.get(file.suffix.lower())
    if not file.is_absolute() or not file.is_file() or not mime:
        raise ValueError(f"{setting} must be an absolute file path with a supported extension.")
    with file.open("rb") as stream:
        data = stream.read(limit + 1)
    if not 0 < len(data) <= limit:
        raise ValueError(f"{setting} is empty or larger than {limit} bytes.")
    return data, mime
