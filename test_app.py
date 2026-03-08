from playwright.sync_api import sync_playwright


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        console_messages = []
        page.on(
            "console", lambda msg: console_messages.append(f"[{msg.type}] {msg.text}")
        )
        page.on("pageerror", lambda err: console_messages.append(f"[PAGE_ERROR] {err}"))

        print("Loading app...")
        page.goto("http://localhost:8082", wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(3000)  # Wait for JS to execute

        # Try to manually call loadAndRender
        print("\nManually calling loadAndRender...")
        result = page.evaluate("typeof loadAndRender")
        print(f"loadAndRender type: {result}")

        page.wait_for_timeout(3000)

        # Check window.cyberData
        cyber_data = page.evaluate("window.cyberData")
        print(f"window.cyberData after manual call: {cyber_data}")

        # Check all console messages
        print("\nAll console messages:")
        for m in console_messages:
            print(f"  {m}")

        browser.close()


if __name__ == "__main__":
    main()
