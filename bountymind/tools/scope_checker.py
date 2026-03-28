import re
from urllib.parse import urlparse


class ScopeViolationError(Exception):
    pass


def validate_scope(url: str, scope_rules: dict) -> None:
    if not url or not scope_rules:
        return

    in_scope     = scope_rules.get("in_scope",     [])
    out_of_scope = scope_rules.get("out_of_scope", [])

    if out_of_scope:
        for pattern in out_of_scope:
            if _matches(url, pattern):
                raise ScopeViolationError(f"URL {url!r} matches out-of-scope pattern {pattern!r}")

    if in_scope:
        if not any(_matches(url, p) for p in in_scope):
            raise ScopeViolationError(f"URL {url!r} not in scope")


def _matches(url: str, pattern: str) -> bool:
    try:
        if "*" in pattern:
            regex = re.escape(pattern).replace(r"\*", ".*")
            return bool(re.match(regex, url, re.IGNORECASE))
        parsed_url     = urlparse(url)
        parsed_pattern = urlparse(pattern if "://" in pattern else "https://" + pattern)
        url_host     = parsed_url.netloc.lower().lstrip("www.")
        pattern_host = parsed_pattern.netloc.lower().lstrip("www.")
        if not pattern_host:
            return pattern.lower() in url.lower()
        return url_host == pattern_host or url_host.endswith("." + pattern_host)
    except Exception:
        return pattern.lower() in url.lower()
