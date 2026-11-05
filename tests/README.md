# Tests

Run the full suite with `.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v` after installing `requirements.txt`.

The suite covers the M1/M2 repository and policy engine plus M3 real HTTP integration over MCP Streamable HTTP. Gateway tests verify unauthenticated and revoked tokens stop before handlers, credential hashes (not raw credentials) are stored, identity arguments cannot expand CRM scope, an `ALLOW` executes and increments the real repository counter, `DENY` and `REQUIRE_APPROVAL` leave it unchanged, and audit-write failures block execution.
