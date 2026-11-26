"""Local CLI helpers for ANDHAK EDR backend provisioning."""

from __future__ import annotations

import argparse
import json

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


if __name__ == "__main__":
    main()
