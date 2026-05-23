import re
import sys
import threading
import json
import importlib.util
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


def load_morocco_feed_builder():
    script_path = Path("scripts/build_morocco_feed.py")
    spec = importlib.util.spec_from_file_location("build_morocco_feed", script_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
    workflow = Path(".github/workflows/update-morocco-cyber-feed.yml")

    assert collector.exists(), "Morocco feed collector script should exist"
    assert worker.exists(), "DGSSI worker script should exist"
    assert workflow.exists(), "Scheduled Morocco feed workflow should exist"

    script = collector.read_text(encoding="utf-8")
    worker_js = worker.read_text(encoding="utf-8")
    workflow_yml = workflow.read_text(encoding="utf-8")
    assert "https://www.dgssi.gov.ma/fr/bulletins/" in script
    assert "https://www.dgssi.gov.ma/rss.xml" in script
    assert "https://en.hespress.com/feed" in script
    assert "data/morocco-cyber-feed.json" in script
    assert "Access-Control-Allow-Origin" in worker_js
    assert "https://www.dgssi.gov.ma/rss.xml" in worker_js
    assert "workflow_dispatch" in workflow_yml
    assert "schedule:" in workflow_yml
    assert "python3 scripts/build_morocco_feed.py" in workflow_yml
    assert "data/morocco-cyber-feed.json" in workflow_yml


def test_morocco_feed_payload_signature_ignores_generated_at():
    builder = load_morocco_feed_builder()
    payload = {
        "countryFocus": "MA",
        "generatedAt": "2026-05-23T10:00:00Z",
        "sources": ["https://www.dgssi.gov.ma/rss.xml"],
        "items": [{"id": "dgssi-1", "title": "Alert", "published": "2026-05-23T09:00:00Z"}],
    }
    same_payload_new_time = {
        **payload,
        "generatedAt": "2026-05-23T16:00:00Z",
    }

    assert builder.payload_signature(payload) == builder.payload_signature(same_payload_new_time)
    assert builder.has_feed_changes(payload, same_payload_new_time) is False


def test_morocco_feed_payload_signature_detects_item_changes():
    builder = load_morocco_feed_builder()
    existing_payload = {
        "countryFocus": "MA",
        "generatedAt": "2026-05-23T10:00:00Z",
        "sources": ["https://www.dgssi.gov.ma/rss.xml"],
        "items": [{"id": "dgssi-1", "title": "Alert", "published": "2026-05-23T09:00:00Z"}],
    }
    changed_payload = {
        **existing_payload,
        "items": [{"id": "dgssi-2", "title": "New Alert", "published": "2026-05-23T11:00:00Z"}],
    }

    assert builder.has_feed_changes(existing_payload, changed_payload) is True


def test_load_all_data_uses_country_focus_for_news_cache_and_fetch():
    api_js = Path("js/api.js").read_text(encoding="utf-8")

    assert "const countryFocus = timeRanges.countryFocus || 'global';" in api_js
    assert "${countryFocus}" in api_js
    assert "fetchNewsBySource('all', newsRange, countryFocus)" in api_js


def test_external_link_sanitizer_rejects_relative_urls():
    app_js = Path("js/app.js").read_text(encoding="utf-8")

    assert "if (!/^https?:\\/\\//i.test(raw)) return '';" in app_js
    assert "new URL(raw)" in app_js


def test_filtered_renders_own_visible_count_badges():
    app_js = Path("js/app.js").read_text(encoding="utf-8")

    assert "if (badge) badge.textContent = items.length || '';" not in app_js
    assert "if (badge) badge.textContent = cves.length || '';" not in app_js


def test_cve_live_refresh_passes_new_ids_and_does_not_override_badge():
    app_js = Path("js/app.js").read_text(encoding="utf-8")

    assert "renderActiveData(undefined, { newCveIds: new Set(newIds) })" in app_js
    assert "renderCVEs(visible.cves, options.newCveIds || new Set())" in app_js
    assert "badge.textContent = merged.length" not in app_js


def test_known_cve_ids_are_not_silently_capped():
    app_js = Path("js/app.js").read_text(encoding="utf-8")

    assert "knownCveIds.size < 500" not in app_js
    assert "knownCveIds.add(cve.id)" in app_js


def test_time_ago_handles_unix_second_numbers():
    utils_js = Path("js/utils.js").read_text(encoding="utf-8")

    assert "timestamp < 1e12 ? timestamp * 1000 : timestamp" in utils_js
    assert "Number.isNaN(date.getTime())" in utils_js


def test_unsupported_country_focus_does_not_pass_everything():
    api_js = Path("js/api.js").read_text(encoding="utf-8")

    assert "if (countryFocus !== 'MA') return true;" not in api_js
    assert "if (countryFocus !== 'MA') return false;" in api_js


def test_fallback_data_is_marked_and_status_uses_metadata():
    api_js = Path("js/api.js").read_text(encoding="utf-8")
    app_js = Path("js/app.js").read_text(encoding="utf-8")
    ui_js = Path("js/ui.js").read_text(encoding="utf-8")

    assert "isFallback: true" in api_js
    assert re.search(r"_meta:\s*\{\s*usingFallback", api_js)
    assert "!data._meta?.usingFallback" in app_js
    assert "statusLabel" in ui_js


def test_search_handler_has_single_render_path():
    app_js = Path("js/app.js").read_text(encoding="utf-8")
    handler_match = re.search(
        r"searchInput\.addEventListener\('input', Utils\.debounce\(\(e\) => \{([\s\S]*?)\}, 250\)\);",
        app_js,
    )

    assert handler_match
    assert "if (!currentSearchQuery)" not in handler_match.group(1)
    assert handler_match.group(1).count("renderActiveData(data);") == 1


def test_dgssi_scrape_preserves_existing_published_dates():
    builder = load_morocco_feed_builder()
    existing = [
        {
            "title": "DGSSI Alert",
            "link": "https://www.dgssi.gov.ma/fr/bulletins/alert",
            "published": "2026-05-17T21:36:41Z",
        }
    ]

    assert builder.preserved_published(
        "https://www.dgssi.gov.ma/fr/bulletins/alert",
        "DGSSI Alert",
        existing,
    ) == "2026-05-17T21:36:41Z"


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, PlaywrightError) as err:
        print(f"\n❌ Test failed: {err}")
        sys.exit(1)
