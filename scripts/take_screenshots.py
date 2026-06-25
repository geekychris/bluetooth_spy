"""Drive a running bt-spy UI with Playwright and screenshot each major tab/flow.

Usage:
    BTSPY_DATA_DIR=/tmp/bt-spy-screenshots .venv/bin/python scripts/seed_demo_data.py
    BTSPY_DATA_DIR=/tmp/bt-spy-screenshots .venv/bin/bt-spy serve &
    .venv/bin/python scripts/take_screenshots.py
    # then kill the server

PNGs land in docs/screenshots/.
"""

from __future__ import annotations

import time
from pathlib import Path

from playwright.sync_api import sync_playwright

OUT = Path(__file__).resolve().parent.parent / "docs" / "screenshots"
URL = "http://127.0.0.1:8765"
VIEWPORT = {"width": 1440, "height": 900}


SHOTS = [
    # (tab name, output filename, optional post-actions)
    ("dashboard", "01-dashboard.png", None),
    ("capture", "02-capture.png", None),
    ("sessions", "03-sessions.png", None),
    ("diff", "04-diff.png", None),
    ("replay", "05-replay.png", None),
    ("protocol", "06-protocol-dict.png", None),
    ("integrations", "07-integrations.png", None),
    ("dongle", "08-dongle.png", None),
]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(viewport=VIEWPORT, device_scale_factor=2)  # 2x for crisp PNGs
        page = ctx.new_page()
        page.goto(URL)
        page.wait_for_selector("nav.tabs", timeout=15_000)

        for tab, filename, post in SHOTS:
            target = OUT / filename
            print(f"  capturing {tab} → {target.name}")
            page.click(f'.tab[data-tab="{tab}"]')
            page.wait_for_timeout(800)
            if post:
                post(page)
                page.wait_for_timeout(500)
            page.screenshot(path=str(target), full_page=True)

        # Bonus: session-detail view with markers + diff dropdowns
        page.click('.tab[data-tab="sessions"]')
        page.wait_for_timeout(500)
        page.click("#btn-refresh-sessions")
        page.wait_for_timeout(800)
        # Click View on the most-recent session (tap_power_on)
        buttons = page.locator(".view-session")
        if buttons.count() > 0:
            buttons.first.click()
            page.wait_for_timeout(1200)
            page.screenshot(path=str(OUT / "09-session-detail.png"), full_page=True)

        # Bonus: packet detail modal
        rows = page.locator("#hist-packets tbody tr")
        if rows.count() > 0:
            rows.first.click()
            page.wait_for_timeout(800)
            page.screenshot(path=str(OUT / "10-packet-detail.png"), full_page=False)
            page.click("#modal-close")

        # Bonus: protocol entry view
        page.click('.tab[data-tab="protocol"]')
        page.wait_for_timeout(300)
        page.click("#btn-refresh-proto")
        page.wait_for_timeout(800)
        # Expand the add-entry form
        details = page.locator("#tab-protocol details").first
        if details.count() > 0:
            details.click()
            page.wait_for_timeout(300)
            page.screenshot(path=str(OUT / "11-protocol-add-entry.png"), full_page=True)

        ctx.close()
        browser.close()


if __name__ == "__main__":
    main()
    print("✓ Done — see docs/screenshots/")
