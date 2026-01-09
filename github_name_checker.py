
"""Check GitHub username availability or scan short name combinations."""
import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import itertools
import string

API_URL = "https://api.github.com/users/{username}"
WEB_URL = "https://github.com/{username}"
SIGNUP_CHECK_URLS = (
    "https://github.com/signup_check/username?username={username}",
    "https://github.com/signup_check/username?value={username}",
)
REQUEST_TIMEOUT = 10
DEFAULT_ALPHABET = string.ascii_lowercase
AVAILABLE_OUTPUT_NAME = "available names.txt"
BLOCKLIST_NAME = "blocked_terms.txt"
DEFAULT_BLOCKLIST = {"sex", "porn", "xxx", "nude", "nsfw"}
RATE_LIMIT_FALLBACK_SECONDS = 60

ANSI_COLORS = {
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "reset": "\x1b[0m",
}


def load_env(path=".env"):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                key, sep, value = line.partition("=")
                if not sep:
                    continue
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except FileNotFoundError:
        pass


def get_env_float(name, default):
    value = os.getenv(name)
    if value is None or value == "":
        return default
    try:
        return float(value)
    except ValueError:
        return default


def enable_ansi():
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
            return False
        new_mode = mode.value | 0x0004
        if kernel32.SetConsoleMode(handle, new_mode) == 0:
            return False
        return True
    except Exception:
        return False


def script_dir():
    return os.path.dirname(os.path.abspath(__file__))


def color_text(text, color, enabled):
    if not enabled:
        return text
    return f"{ANSI_COLORS[color]}{text}{ANSI_COLORS['reset']}"


def available_output_path():
    return os.path.join(script_dir(), AVAILABLE_OUTPUT_NAME)


def blocklist_path():
    return os.path.join(script_dir(), BLOCKLIST_NAME)


def load_blocklist(path=None):
    if path is None:
        path = blocklist_path()
    try:
        terms = set()
        with open(path, "r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                terms.add(line.lower())
        return terms, path
    except FileNotFoundError:
        return set(DEFAULT_BLOCKLIST), None


def is_blocked(username, blocklist):
    if not blocklist:
        return False
    name = username.lower()
    return any(term in name for term in blocklist)


def retry_after_from_headers(headers):
    if not headers:
        return None
    retry_after = headers.get("Retry-After")
    if retry_after:
        try:
            return max(0, int(float(retry_after)))
        except ValueError:
            pass
    reset = headers.get("X-RateLimit-Reset")
    if reset:
        try:
            wait = int(reset) - int(time.time())
            if wait > 0:
                return wait
        except ValueError:
            pass
    return None


def sleep_for_rate_limit(retry_after, source):
    wait_seconds = retry_after if retry_after is not None else RATE_LIMIT_FALLBACK_SECONDS
    if wait_seconds < 1:
        wait_seconds = 1
    print(f"Rate limited by {source}. Sleeping {wait_seconds} seconds...")
    time.sleep(wait_seconds)


def format_status_line(username, status, color_enabled, detail=None):
    if status == "available":
        label = "Available"
        color = "green"
    elif status == "taken":
        label = "TAKEN"
        color = "red"
    elif status == "blocked":
        label = "BLOCKED"
        color = "yellow"
    elif status == "unverified":
        label = "TAKEN"
        color = "red"
    elif status == "rate_limited":
        label = "RATE LIMITED"
        color = "yellow"
    else:
        label = "ERROR"
        if detail:
            label = f"{label} ({detail})"
        color = "yellow"
    label_text = color_text(label, color, color_enabled)
    return f"{username} | {label_text}"


def check_username_api(username, token):
    headers = {
        "User-Agent": "github-name-checker/1.0",
        "Accept": "application/vnd.github+json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(
        API_URL.format(username=username),
        headers=headers,
        method="GET",
    )
    response_headers = None
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            status = response.status
            response_headers = response.headers
    except urllib.error.HTTPError as exc:
        status = exc.code
        response_headers = exc.headers
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", "unknown error")
        return {"username": username, "status": "error", "detail": str(reason)}

    if status == 200:
        return {"username": username, "status": "taken"}
    if status == 404:
        return {"username": username, "status": "available"}
    if status in {403, 429}:
        retry_after = retry_after_from_headers(response_headers)
        return {
            "username": username,
            "status": "rate_limited",
            "retry_after": retry_after,
            "source": "api",
        }
    return {"username": username, "status": "unknown", "detail": f"http_{status}"}


def check_username_web(username):
    headers = {
        "User-Agent": "github-name-checker/1.0",
    }
    request = urllib.request.Request(
        WEB_URL.format(username=username),
        headers=headers,
        method="HEAD",
    )
    response_headers = None
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            status = response.status
            response_headers = response.headers
    except urllib.error.HTTPError as exc:
        status = exc.code
        response_headers = exc.headers
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", "unknown error")
        return {"username": username, "status": "error", "detail": str(reason)}

    if status == 200:
        return {"username": username, "status": "taken"}
    if status == 404:
        return {"username": username, "status": "available"}
    if status in {403, 429}:
        retry_after = retry_after_from_headers(response_headers)
        return {
            "username": username,
            "status": "rate_limited",
            "retry_after": retry_after,
            "source": "web",
        }
    return {"username": username, "status": "unknown", "detail": f"http_{status}"}


def parse_signup_payload(payload):
    if not isinstance(payload, dict):
        return None
    available = payload.get("available")
    if isinstance(available, bool):
        return available
    is_available = payload.get("is_available")
    if isinstance(is_available, bool):
        return is_available
    is_valid = payload.get("is_valid")
    if isinstance(is_valid, bool) and not is_valid:
        return False
    status = payload.get("status")
    if isinstance(status, str):
        status_value = status.lower()
        if status_value == "available":
            return True
        if "unavailable" in status_value or "invalid" in status_value or "taken" in status_value:
            return False
    for key in ("message", "error"):
        message = payload.get(key)
        if isinstance(message, str):
            lowered = message.lower()
            if "not available" in lowered or "unavailable" in lowered or "taken" in lowered or "invalid" in lowered:
                return False
            if "available" in lowered:
                return True
    errors = payload.get("errors")
    if errors:
        if isinstance(errors, list):
            text = " ".join(str(item) for item in errors)
        else:
            text = str(errors)
        lowered = text.lower()
        if "not available" in lowered or "unavailable" in lowered or "taken" in lowered or "invalid" in lowered:
            return False
        if "available" in lowered:
            return True
    return None


def check_username_signup(username):
    headers = {
        "User-Agent": "github-name-checker/1.0",
        "Accept": "application/json",
        "X-Requested-With": "XMLHttpRequest",
    }
    encoded = urllib.parse.quote(username, safe="")
    last_detail = None
    for template in SIGNUP_CHECK_URLS:
        url = template.format(username=encoded)
        request = urllib.request.Request(
            url,
            headers=headers,
            method="GET",
        )
        response_headers = None
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
                status = response.status
                response_headers = response.headers
                payload_bytes = response.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            response_headers = exc.headers
            payload_bytes = exc.read()
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", "unknown error")
            return {"username": username, "status": "error", "detail": str(reason)}

        if status in {403, 429}:
            retry_after = retry_after_from_headers(response_headers)
            return {
                "username": username,
                "status": "rate_limited",
                "retry_after": retry_after,
                "source": "signup",
            }
        if status != 200:
            last_detail = f"http_{status}"
            continue
        try:
            payload = json.loads(payload_bytes.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            last_detail = "signup_invalid_json"
            continue

        available = parse_signup_payload(payload)
        if available is True:
            return {"username": username, "status": "available"}
        if available is False:
            return {"username": username, "status": "taken"}
        last_detail = "signup_unknown"

    detail = last_detail or "signup_unknown"
    return {"username": username, "status": "unverified", "detail": detail}


def check_username(username, token):
    api_result = check_username_api(username, token)
    if api_result["status"] != "available":
        return api_result

    signup_result = check_username_signup(username)
    if signup_result["status"] in {"available", "taken", "rate_limited"}:
        return signup_result

    web_result = check_username_web(username)
    if web_result["status"] in {"taken", "rate_limited"}:
        return web_result

    detail = web_result.get("detail") or signup_result.get("detail") or "unverified"
    return {"username": username, "status": "taken", "detail": detail}


def prompt_length():
    while True:
        choice = input("Choose length 3L or 4L: ").strip().lower()
        if choice in {"3", "3l"}:
            return 3
        if choice in {"4", "4l"}:
            return 4
        print("Please enter 3L or 4L.")


def iter_combinations(length, alphabet=DEFAULT_ALPHABET):
    for combo in itertools.product(alphabet, repeat=length):
        yield "".join(combo)


def scan_combinations(length, token, alphabet=DEFAULT_ALPHABET):
    color_enabled = enable_ansi()
    if not token:
        print("Warning: GITHUB_TOKEN not set; unauthenticated requests are heavily rate limited.")
    delay_seconds = get_env_float("REQUEST_DELAY_SECONDS", 0.0)
    if delay_seconds > 0:
        print(f"Delaying {delay_seconds} seconds between checks.")
    blocklist, blocklist_source = load_blocklist()
    if blocklist:
        source_label = blocklist_source or "built-in list"
        print(f"Blocking {len(blocklist)} terms from {source_label}.")
    total = len(alphabet) ** length
    print(f"Scanning {total:,} combinations...")
    output_path = available_output_path()
    print(f"Saving available names to {output_path}")
    combinations = list(iter_combinations(length, alphabet))
    random.shuffle(combinations)
    with open(output_path, "a", encoding="utf-8") as handle:
        for username in combinations:
            if is_blocked(username, blocklist):
                line = format_status_line(username, "blocked", color_enabled)
                print(line)
                if delay_seconds > 0:
                    time.sleep(delay_seconds)
                continue
            while True:
                result = check_username(username, token)
                status = result["status"]
                if status == "rate_limited":
                    retry_after = result.get("retry_after")
                    source = result.get("source", "unknown")
                    sleep_for_rate_limit(retry_after, source)
                    continue
                break
            status = result["status"]
            line = format_status_line(username, status, color_enabled, result.get("detail"))
            print(line)
            if status == "available":
                handle.write(f"{username}\n")
                handle.flush()
            if delay_seconds > 0:
                time.sleep(delay_seconds)


def main():
    parser = argparse.ArgumentParser(description="Check GitHub username availability.")
    parser.add_argument(
        "usernames",
        nargs="*",
        help="One or more GitHub usernames to check",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON",
    )
    parser.add_argument(
        "--env",
        default=".env",
        help="Path to .env file (default: .env)",
    )
    args = parser.parse_args()

    load_env(args.env)
    token = os.getenv("GITHUB_TOKEN")

    if not args.usernames:
        length = prompt_length()
        scan_combinations(length, token)
        input("Press Enter to exit...")
        return 0

    blocklist, _ = load_blocklist()
    results = []
    for name in args.usernames:
        if is_blocked(name, blocklist):
            results.append({"username": name, "status": "blocked"})
            continue
        results.append(check_username(name, token))
    if args.json:
        print(json.dumps(results, indent=2))
        return 0

    output_path = available_output_path()
    for result in results:
        status = result["status"]
        if status == "available":
            print(f"{result['username']}: available")
            with open(output_path, "a", encoding="utf-8") as handle:
                handle.write(f"{result['username']}\n")
        elif status == "taken":
            print(f"{result['username']}: taken")
        elif status == "blocked":
            print(f"{result['username']}: blocked")
        elif status == "unverified":
            print(f"{result['username']}: taken")
        elif status == "rate_limited":
            print(f"{result['username']}: rate limited (token recommended)")
        else:
            detail = result.get("detail", "")
            suffix = f" ({detail})" if detail else ""
            print(f"{result['username']}: error{suffix}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
