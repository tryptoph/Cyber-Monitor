import re
import sys

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright


def assert_true(condition, message):
    if not condition:
        raise AssertionError(message)
    print(f"✓ {message}")


def get_status_count_value(text):
    match = re.search(r"(\d+)", text)
    if not match:
        return None
    return int(match.group(1))


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        try:
            print("Loading CyberVulnDB...")
            page.goto("http://localhost:8082", wait_until="domcontentloaded", timeout=30000)
            page.wait_for_selector("#cve-list .threat-card", timeout=15000)

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


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, PlaywrightError) as err:
        print(f"\n❌ Test failed: {err}")
        sys.exit(1)
