#!/usr/bin/env python3
"""Build the static Morocco cyber feed used by the GitHub Pages dashboard."""

from __future__ import annotations

import email.utils
import html
import json
import re
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.error import URLError
from urllib.request import Request, urlopen
from xml.etree import ElementTree


OUTPUT = Path("data/morocco-cyber-feed.json")
DGSSI_BULLETINS_URL = "https://www.dgssi.gov.ma/fr/bulletins/"
DGSSI_HOME_URL = "https://www.dgssi.gov.ma/en/"
DGSSI_RSS_SOURCES = [
    ("DGSSI / maCERT", "dgssi", "https://www.dgssi.gov.ma/rss.xml"),
    ("DGSSI / maCERT", "dgssi", "https://www.dgssi.gov.ma/en/rss.xml"),
]

RSS_SOURCES = [
    ("Hespress English", "hespress-en", "https://en.hespress.com/feed"),
    ("Hespress Français", "hespress-fr", "https://fr.hespress.com/feed"),
    ("Hespress Arabic", "hespress-ar", "https://www.hespress.com/feed"),
    ("Aujourd'hui le Maroc", "aujourdhui", "https://aujourdhui.ma/feed"),
    ("La Vie Eco", "lavieeco", "https://www.lavieeco.com/feed/"),
]

MOROCCO_TERMS = (
    "morocco", "moroccan", "maroc", "marocain", "marocaine", "المغرب",
    "مغربي", "مغربية", "rabat", "casablanca", "marrakech", "tanger",
)

CYBER_TERMS = (
    "cyber", "cybersecurity", "cybersécurité", "cybersecurite", "cyberattaque",
    "cyberattack", "security", "sécurité", "securite", "vulnerability",
    "vulnérabilité", "vulnerabilite", "ransomware", "malware", "phishing",
    "spyware", "breach", "leak", "fuite", "piratage", "hacker", "dgssi",
    "macert", "cert", "cve", "zero-day", "ddos", "سيبر", "الأمن السيبراني",
    "اختراق", "قرصنة", "تسريب", "برمجية", "خبيثة", "هجوم", "هجمات",
)

DGSSI_BULLETIN_TERMS = (
    "bulletin", "vulnerabilite", "vulnérabilité", "vulnerabilites",
    "vulnérabilités", "faille", "failles", "malware", "ransomware",
    "attaque", "attaques", "exploite", "exploitée", "critique", "cve-",
    "zero-day", "zero day",
)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fetch_text(url: str, timeout: int = 20) -> str:
    request = Request(url, headers={"User-Agent": "CyberVulnDB Morocco feed builder"})
    context = ssl.create_default_context()
    with urlopen(request, timeout=timeout, context=context) as response:
        return response.read().decode(response.headers.get_content_charset() or "utf-8", errors="replace")


def clean_text(value: str) -> str:
    value = re.sub(r"<[^>]+>", " ", value or "")
    value = html.unescape(value)
    return re.sub(r"\s+", " ", value).strip()


def slug(value: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", value.lower())
    return value.strip("-")[:96] or "item"


def parse_date(value: str) -> str:
    if not value:
        return now_iso()
    try:
      parsed = email.utils.parsedate_to_datetime(value)
      if parsed.tzinfo is None:
          parsed = parsed.replace(tzinfo=timezone.utc)
      return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError):
      return now_iso()


def is_cyber_related(title: str, description: str) -> bool:
    text = f"{title} {description}".lower()
    return any(term.lower() in text for term in CYBER_TERMS)


def is_dgssi_security_bulletin(title: str, description: str, link: str) -> bool:
    text = f"{title} {description}".lower()
    return "/bulletins/" in link.lower() or any(term.lower() in text for term in DGSSI_BULLETIN_TERMS)


def item(
    *,
    title: str,
    link: str,
    description: str,
    source: str,
    source_key: str,
    category: str,
    published: str,
    official: bool = False,
) -> dict:
    return {
        "id": f"{source_key}-{slug(title or link)}",
        "title": clean_text(title),
        "link": link,
        "description": clean_text(description)[:500],
        "source": source,
        "sourceKey": source_key,
        "category": category,
        "published": published,
        "countryCode": "MA",
        "official": official,
        "type": "news",
    }


def dgssi_seed_items() -> list[dict]:
    generated = now_iso()
    return [
        item(
            title="DGSSI security bulletins",
            link=DGSSI_BULLETINS_URL,
            description="Official DGSSI / maCERT security bulletins and advisories for Morocco.",
            source="DGSSI / maCERT",
            source_key="dgssi",
            category="official",
            published=generated,
            official=True,
        ),
        item(
            title="DGSSI official cybersecurity updates",
            link=DGSSI_HOME_URL,
            description="Official Moroccan authority updates, notices, and cybersecurity information from DGSSI.",
            source="DGSSI / maCERT",
            source_key="dgssi",
            category="official",
            published=generated,
            official=True,
        ),
    ]


def read_existing_dgssi_items() -> list[dict]:
    if not OUTPUT.exists():
        return []
    try:
        payload = json.loads(OUTPUT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [
        entry for entry in payload.get("items", [])
        if entry.get("sourceKey") == "dgssi" and entry.get("official") is True
    ]


def parse_dgssi_bulletins() -> list[dict]:
    try:
        page = fetch_text(DGSSI_BULLETINS_URL)
    except (OSError, URLError) as exc:
        print(f"[warn] DGSSI fetch failed: {exc}", file=sys.stderr)
        return dgssi_seed_items()

    matches = re.findall(r'href="([^"]*bulletins[^"]*)"\s*[^>]*>([^<]{12,180})<', page, flags=re.I)
    items: list[dict] = []
    for href, title in matches[:20]:
        link = href if href.startswith("http") else f"https://www.dgssi.gov.ma{href}"
        title = clean_text(title)
        if not title or title.lower() == "security bulletins":
            continue
        items.append(item(
            title=title,
            link=link,
            description="Official DGSSI / maCERT security bulletin.",
            source="DGSSI / maCERT",
            source_key="dgssi",
            category="official",
            published=now_iso(),
            official=True,
        ))

    return items or dgssi_seed_items()


def parse_dgssi_rss() -> list[dict]:
    results: list[dict] = []
    for source in DGSSI_RSS_SOURCES:
        name, key, url = source
        try:
            xml = fetch_text(url)
            root = ElementTree.fromstring(xml)
        except (ElementTree.ParseError, OSError, URLError) as exc:
            print(f"[warn] DGSSI RSS fetch failed for {url}: {exc}", file=sys.stderr)
            continue

        for node in root.findall(".//item")[:50]:
            title = clean_text(node.findtext("title") or "")
            link = clean_text(node.findtext("link") or "")
            description = clean_text(node.findtext("description") or "")
            published = parse_date(node.findtext("pubDate") or "")
            if title and link and is_dgssi_security_bulletin(title, description, link):
                results.append(item(
                    title=title,
                    link=link,
                    description=description or "Official DGSSI / maCERT security bulletin.",
                    source=name,
                    source_key=key,
                    category="official",
                    published=published,
                    official=True,
                ))
    return results


def parse_rss(source: tuple[str, str, str]) -> list[dict]:
    name, key, url = source
    try:
        xml = fetch_text(url)
        root = ElementTree.fromstring(xml)
    except (ElementTree.ParseError, OSError, URLError) as exc:
        print(f"[warn] RSS fetch failed for {name}: {exc}", file=sys.stderr)
        return []

    results: list[dict] = []
    for node in root.findall(".//item")[:30]:
        title = clean_text(node.findtext("title") or "")
        link = clean_text(node.findtext("link") or "")
        description = clean_text(node.findtext("description") or "")
        published = parse_date(node.findtext("pubDate") or "")
        if title and link and is_cyber_related(title, description):
            results.append(item(
                title=title,
                link=link,
                description=description or title,
                source=name,
                source_key=key,
                category="morocco",
                published=published,
            ))
    return results


def dedupe(items: Iterable[dict]) -> list[dict]:
    seen: set[str] = set()
    unique: list[dict] = []
    for entry in items:
        key = (entry.get("link") or entry.get("title") or "").rstrip("/").lower()
        if not key or key in seen:
            continue
        seen.add(key)
        unique.append(entry)
    return sorted(unique, key=lambda row: row.get("published", ""), reverse=True)


def main() -> int:
    items = parse_dgssi_rss() or parse_dgssi_bulletins()
    if len([entry for entry in items if entry.get("sourceKey") == "dgssi"]) < 3:
        existing_dgssi = read_existing_dgssi_items()
        if len(existing_dgssi) >= 3:
            items = existing_dgssi
    for source in RSS_SOURCES:
        items.extend(parse_rss(source))

    payload = {
        "countryFocus": "MA",
        "generatedAt": now_iso(),
        "sources": [DGSSI_BULLETINS_URL, DGSSI_HOME_URL, *(source[2] for source in DGSSI_RSS_SOURCES), *(source[2] for source in RSS_SOURCES)],
        "items": dedupe(items)[:100],
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(payload['items'])} Morocco cyber items to {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
