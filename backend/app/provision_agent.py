"""Issue or revoke a local demo agent credential from a trusted administrator shell."""
from __future__ import annotations

import argparse

from backend.app.security.auth import issue_agent_token, revoke_agent_credentials


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    issue = commands.add_parser("issue", help="issue a new bearer credential (shown once)")
    issue.add_argument("agent_id")
    issue.add_argument("--admin", action="store_true", help="grant the server-side admin role")
    revoke = commands.add_parser("revoke", help="revoke all active credentials for an agent")
    revoke.add_argument("agent_id")
    args = parser.parse_args()
    if args.command == "issue":
        token = issue_agent_token(args.agent_id, is_admin=args.admin)
        print("Agent credential (copy now; it is stored only as a hash):")
        print(token)
        return
    count = revoke_agent_credentials(args.agent_id)
    print(f"Revoked {count} active credential(s).")


if __name__ == "__main__":
    main()
