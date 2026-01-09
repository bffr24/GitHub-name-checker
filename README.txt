GitHub Name Checker
===================

This tool checks GitHub username availability and can scan all 3-letter or
4-letter combinations. The scan runs in a random order and prints results
in color:
- Available in green
- Taken in red
- Blocked in yellow (terms from blocked_terms.txt)

Quick Start
-----------
1) Double-click `github_name_checker.bat`
2) Enter 3L or 4L when prompted
3) The scan starts and writes available names to `available names.txt`

You can also check specific names:
  python github_name_checker.py someuser otheruser

Files Created
-------------
- `available names.txt`: any available names found during scans
- `blocked_terms.txt`: terms that are skipped (one per line, case-insensitive)

Rate Limits (Important)
-----------------------
GitHub enforces multiple rate limits:
- The GitHub API (api.github.com) has its own rate limits.
- The signup availability check is stricter and can rate-limit even with a token.

When rate-limited, the checker will automatically pause and retry based on
GitHub headers. If limits are still too aggressive, add a delay between checks.

Add a delay (optional):
  - In `.env`, set:
      REQUEST_DELAY_SECONDS=0.5
  - Increase the value if you still hit limits.

How to Add a Token
------------------
1) Create a GitHub Personal Access Token.
2) Put it in `.env` in the same folder as the script:
      GITHUB_TOKEN=your_token_here
3) Run the checker again.

Notes
-----
- The checker uses multiple signals to verify availability.
- If a name cannot be verified reliably, it is treated as TAKEN.

Author:
Discord @bffr
Github  @bffr24
