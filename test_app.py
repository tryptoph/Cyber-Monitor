import re
import sys
import threading
import json
from pathlib import Path
from contextlib import contextmanager
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

try:
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright
except ImportError:
    PlaywrightError = RuntimeError
    sync_playwright = None


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)
    print(f"✓ {message}")


def get_status_count_value(text):
    match = re.search(r"(\d+)", text)
    if not match:
        return None
    return int(match.group(1))


@contextmanager
def local_server(port=8082):
    try:
        server = ThreadingHTTPServer(("127.0.0.1", port), SimpleHTTPRequestHandler)
    except OSError:
        yield
        return

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield
    finally:
        server.shutdown()
        server.server_close()


def main():
    if sync_playwright is None:
        raise RuntimeError("Playwright is not installed. Install it with `python3 -m pip install playwright && python3 -m playwright install chromium`.")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        try:
            print("Loading CyberVulnDB...")
            with local_server():
                page.goto("http://127.0.0.1:8082", wait_until="domcontentloaded", timeout=30000)
                page.wait_for_selector("#cve-list .threat-card", timeout=30000)

            data_stats = page.evaluate(
                """() => {
                const d = window.cyberData || {};
                return {
                  cves: (d.cves || []).length,
                  ransomware: (d.ransomware || []).length,
                  apt: (d.apt || []).length,
                  news: (d.news || []).length,
                  critical: (d.cves || []).filter(c => c.cvss && c.cvss.severity === 'CRITICAL').length
                };
            }"""
            )

            cve_count = page.locator("#cve-list .threat-card").count()
            assert_true(cve_count == data_stats["cves"], f"CVE list renders expected count ({cve_count})")

            status_text = page.locator("#status-source").inner_text()
            assert_true("[OK]" in status_text, f"Status source is connected: {status_text}")

            expected_total = data_stats["cves"] + data_stats["ransomware"] + data_stats["apt"] + data_stats["news"]
            status_count_text = page.locator("#status-count").inner_text()
            status_count_value = get_status_count_value(status_count_text)
            assert_true(
                status_count_value == expected_total,
                f"Threat counter matches loaded data ({status_count_value} == {expected_total})",
            )

            first_card = page.locator("#cve-list .threat-card").first
            first_card.click()
            page.wait_for_selector("#modal-overlay:not(.hidden)", timeout=5000)
            assert_true(page.locator("#modal-overlay:not(.hidden)").count() == 1, "Modal opens on CVE click")

            page.locator(".modal-close").click()
            page.wait_for_selector("#modal-overlay", state="hidden", timeout=5000)
            assert_true(page.locator("#modal-overlay.hidden").count() == 1, "Modal closes correctly")

            page.locator("#cve-severity-filter").select_option("CRITICAL")
            page.wait_for_timeout(300)
            critical_cards = page.locator("#cve-list .threat-card").count()
            assert_true(
                critical_cards == data_stats["critical"],
                f"Severity filter returns only CRITICAL CVEs ({critical_cards})",
            )

            print("\n✅ All checks passed")
        finally:
            browser.close()


def test_smoke():
    if sync_playwright is None:
        import pytest
        pytest.skip("Playwright is not installed")
    main()


def test_morocco_feed_seed_contains_official_dgssi_items():
    feed_path = Path("data/morocco-cyber-feed.json")
    assert feed_path.exists(), "Morocco cyber feed seed should exist"

    payload = json.loads(feed_path.read_text(encoding="utf-8"))
    items = payload.get("items", [])
    assert payload.get("countryFocus") == "MA"
    assert any(item.get("sourceKey") == "dgssi" for item in items), "DGSSI should be present as an official Morocco source"
    assert all(item.get("countryCode") == "MA" for item in items), "Morocco feed items should be tagged MA"
    assert any(item.get("official") is True for item in items), "Official-source badge metadata should be available"


def test_morocco_focus_hooks_are_wired():
    index_html = Path("index.html").read_text(encoding="utf-8")
    api_js = Path("js/api.js").read_text(encoding="utf-8")
    app_js = Path("js/app.js").read_text(encoding="utf-8")

    assert 'id="country-focus-filter"' in index_html
    assert 'value="MA"' in index_html
    assert "matchesCountryFocus" in api_js
    assert "fetchMoroccoNews" in api_js
    assert "fetchDGSSIRSSNews" in api_js
    assert "CYBERVULNDB_DGSSI_API" in api_js
    assert "currentCountryFocus" in app_js
    assert "applyActiveFilters" in app_js


def test_morocco_feed_collector_and_worker_exist():
    collector = Path("scripts/build_morocco_feed.py")
    worker = Path("workers/dgssi-feed-worker.js")

    assert collector.exists(), "Morocco feed collector script should exist"
    assert worker.exists(), "DGSSI worker script should exist"

    script = collector.read_text(encoding="utf-8")
    worker_js = worker.read_text(encoding="utf-8")
    assert "https://www.dgssi.gov.ma/fr/bulletins/" in script
    assert "https://www.dgssi.gov.ma/rss.xml" in script
    assert "https://en.hespress.com/feed" in script
    assert "data/morocco-cyber-feed.json" in script
    assert "Access-Control-Allow-Origin" in worker_js
    assert "https://www.dgssi.gov.ma/rss.xml" in worker_js


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, PlaywrightError) as err:
        print(f"\n❌ Test failed: {err}")
        sys.exit(1)
