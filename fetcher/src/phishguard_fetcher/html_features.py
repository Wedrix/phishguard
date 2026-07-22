from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit


class StaticHtmlFeatureParser(HTMLParser):
    """Extracts bounded structural facts without retaining markup or text."""

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.forms = 0
        self.password_inputs = 0
        self.hidden_inputs = 0
        self.external_form_actions = 0
        self.external_links = 0
        self.script_tags = 0
        self.meta_refresh = 0
        self._base_host = (urlsplit(base_url).hostname or "").lower()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag == "form":
            self.forms += 1
            action = values.get("action")
            if action and self._is_external(action):
                self.external_form_actions += 1
        elif tag == "input":
            input_type = values.get("type", "text").lower()
            self.password_inputs += input_type == "password"
            self.hidden_inputs += input_type == "hidden"
        elif tag == "a":
            href = values.get("href")
            if href and self._is_external(href):
                self.external_links += 1
        elif tag == "script":
            self.script_tags += 1
        elif tag == "meta" and values.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh += 1

    def _is_external(self, candidate: str) -> bool:
        host = (urlsplit(urljoin(self.base_url, candidate)).hostname or "").lower()
        return bool(host and host != self._base_host)

    def features(self) -> dict[str, int | bool]:
        return {
            "forms": self.forms,
            "password_inputs": self.password_inputs,
            "hidden_inputs": self.hidden_inputs,
            "external_form_actions": self.external_form_actions,
            "external_links": self.external_links,
            "script_tags_present": self.script_tags > 0,
            "meta_refresh_present": self.meta_refresh > 0,
        }

