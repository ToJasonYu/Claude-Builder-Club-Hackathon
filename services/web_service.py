"""Fetches NGO mission text from their website using httpx."""

import html
import logging
import re
from html.parser import HTMLParser

import httpx
from pydantic import HttpUrl

from core.config import Settings

log = logging.getLogger(__name__)


class _TextExtractor(HTMLParser):
    """Minimal HTML parser that extracts meta description and first <p> tags."""

    def __init__(self) -> None:
        super().__init__()
        self.meta_description: str = ""
        self.paragraphs: list[str] = []
        self._in_p = False
        self._current_p: list[str] = []
        self._skip_tags = {"script", "style", "nav", "footer", "header"}
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._skip_tags:
            self._skip_depth += 1
        if tag == "meta":
            attr_dict = dict(attrs)
            if attr_dict.get("name", "").lower() == "description":
                self.meta_description = attr_dict.get("content", "")
        if tag == "p" and self._skip_depth == 0 and len(self.paragraphs) < 5:
            self._in_p = True
            self._current_p = []

    def handle_endtag(self, tag: str) -> None:
        if tag in self._skip_tags and self._skip_depth > 0:
            self._skip_depth -= 1
        if tag == "p" and self._in_p:
            text = " ".join(self._current_p).strip()
            if len(text) > 30:
                self.paragraphs.append(text)
            self._in_p = False
            self._current_p = []

    def handle_data(self, data: str) -> None:
        if self._in_p and self._skip_depth == 0:
            cleaned = data.strip()
            if cleaned:
                self._current_p.append(cleaned)


def _clean_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


class WebService:
    def __init__(self, settings: Settings) -> None:
        self._timeout = settings.web_fetch_timeout
        self._max_chars = settings.max_mission_chars

    def fetch_mission(self, url: HttpUrl) -> tuple[str, str]:
        """Fetch mission text from a URL.

        Returns (mission_text, source_label) where source_label is one of:
        "website_fetch" | "unavailable"
        Never raises.
        """
        try:
            resp = httpx.get(
                str(url),
                timeout=self._timeout,
                follow_redirects=True,
                headers={"User-Agent": "SecurityResearcher/1.0 (responsible-disclosure)"},
            )
            resp.raise_for_status()
            extractor = _TextExtractor()
            extractor.feed(resp.text)

            parts: list[str] = []
            if extractor.meta_description:
                parts.append(_clean_whitespace(extractor.meta_description))
            for p in extractor.paragraphs[:3]:
                cleaned = _clean_whitespace(p)
                if cleaned not in parts:
                    parts.append(cleaned)

            mission_text = " ".join(parts)
            if not mission_text:
                mission_text = "Mission statement unavailable (no readable text found on website)"
                return mission_text, "unavailable"

            return mission_text[: self._max_chars], "website_fetch"

        except httpx.TimeoutException:
            log.warning("Website fetch timed out for %s", url)
            return "Mission statement unavailable (website timed out)", "unavailable"
        except httpx.HTTPStatusError as e:
            log.warning("HTTP %s fetching %s", e.response.status_code, url)
            return (
                f"Mission statement unavailable (HTTP {e.response.status_code})",
                "unavailable",
            )
        except Exception as exc:
            log.warning("Unexpected error fetching %s: %s", url, exc)
            return "Mission statement unavailable", "unavailable"
