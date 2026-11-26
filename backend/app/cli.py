"""Local CLI helpers for ANDHAK EDR backend provisioning."""

from __future__ import annotations

import argparse
import json

from app.auth import create_user
from app.config import get_settings
from app.db import init_database
from app.services.ingest import issue_enrollment_token


def main() -> None:
    parser = argparse.ArgumentParser(description="ANDHAK EDR backend administration CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="Initialize local SQLite WAL database")

    tok = sub.add_parser("issue-token", help="Generate a one-time agent enrollment token")
    tok.add_argument("--description", default="Local workstation enrollment")
    tok.add_argument("--ttl-hours", type=int, default=24)

    usr = sub.add_parser("create-user", help="Create an RBAC operator account")
    usr.add_argument("--username", required=True)
    usr.add_argument("--display-name", default="")
    usr.add_argument(
        "--role",
        required=True,
        choices=["admin", "responder", "analyst", "readonly_demo"],
    )
    usr.add_argument("--password", required=True)

    args = parser.parse_args()
    cfg = get_settings()
    init_database(cfg)

    if args.command == "init-db":
        print(json.dumps({"initialized": str(cfg.resolved_db_path)}))
    elif args.command == "issue-token":
        result = issue_enrollment_token(
            description=args.description,
            ttl_hours=args.ttl_hours,
            settings=cfg,
        )
        print(json.dumps(result, indent=2))
    elif args.command == "create-user":
        created = create_user(
            username=args.username,
            display_name=args.display_name or args.username,
            role=args.role,
            password=args.password,
            settings=cfg,
        )
        print(json.dumps(created, indent=2))


if __name__ == "__main__":
    main()
