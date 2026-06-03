from __future__ import annotations

import argparse
import logging
import sys

from insightvm_pull.client import InsightVMClient
from insightvm_pull.collector import InsightVMCollector
from insightvm_pull.config import load_settings
from insightvm_pull.logging_setup import setup_logging
from insightvm_pull.scheduler import run_service

INSIGHTVM_BANNER = r"""
  ___           _       _     _   __     ___  __
 |_ _|_ __  ___(_) __ _| |__ | |_/ /    / / |/ /
  | || '_ \/ __| |/ _` | '_ \| __| |   / /| ' /
  | || | | \__ \ | (_| | | | | |_| |  / / | . \
 |___|_| |_|___/_|\__, |_| |_|\__|_| /_/  |_|\_\
                  |___/
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="InsightVM pull integration")
    p.add_argument("--env-file", default=".env", help="Path to .env file")
    p.add_argument("--interval-seconds", type=int, default=None, help="Pull interval in seconds")
    p.add_argument("--page-size", type=int, default=None, help="InsightVM page size")
    p.add_argument("--severities", default=None, help="Comma-separated severities (e.g. critical,high)")
    p.add_argument("--max-retries", type=int, default=None, help="Retry attempts per cycle")
    p.add_argument("--retry-backoff-seconds", type=float, default=None, help="Initial exponential backoff")
    p.add_argument("--log-level", default=None, help="DEBUG/INFO/WARNING/ERROR")
    p.add_argument("--log-file", default=None, help="Path to log file")
    p.add_argument("--payload-dir", default=None, help="Directory to persist payloads")
    p.add_argument(
        "--persist-raw-api-debug",
        action="store_true",
        default=None,
        help="Persist raw InsightVM API payloads for diagnostics",
    )
    p.add_argument("--once", action="store_true", help="Run one cycle and exit")
    return p


def main() -> None:
    args = build_parser().parse_args()
    overrides = {
        "interval_seconds": args.interval_seconds,
        "page_size": args.page_size,
        "severities": args.severities,
        "max_retries": args.max_retries,
        "retry_backoff_seconds": args.retry_backoff_seconds,
        "log_level": args.log_level,
        "log_file": args.log_file,
        "payload_dir": args.payload_dir,
        "persist_raw_api_debug": args.persist_raw_api_debug,
    }
    overrides = {k: v for k, v in overrides.items() if v is not None}
    try:
        settings = load_settings(env_file=args.env_file, overrides=overrides)
    except Exception as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        sys.exit(2)

    setup_logging(settings.log_level, settings.log_file)
    log = logging.getLogger("insightvm_pull.cli")
    log.info("\n%s", INSIGHTVM_BANNER)
    log.info(
        "starting interval=%s page_size=%s severities=%s retries=%s",
        settings.interval_seconds,
        settings.page_size,
        ",".join(settings.severities),
        settings.max_retries,
    )
    log.info("log_file=%s payload_dir=%s", settings.log_file, settings.payload_dir)
    client = InsightVMClient(settings=settings)
    collector = InsightVMCollector(client=client)
    run_service(settings=settings, collector=collector, once=args.once)


if __name__ == "__main__":
    main()
