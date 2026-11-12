"""CLI Interface for Enterprise Backup Service.

Commands:
  run     : Execute backup workflow for one or all clients
  verify  : Test connectivity to storage and all client databases/hosts
  prune   : Enforce retention policies on Google Drive / Storage
  history : Display historical backup runs and metrics from catalog
  init    : Generate a starter config.yaml file
"""

import sys
import shutil
import argparse
import logging
from pathlib import Path
from backup_service.config.settings import AppConfig
from backup_service.core.orchestrator import BackupOrchestrator
from backup_service.core.catalog import StateCatalog


def setup_logging(verbose: bool = False):
    """Configure structured logging."""
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
    logging.basicConfig(level=level, format=fmt, datefmt="%Y-%m-%d %H:%M:%S")


def command_run(args):
    """Execute backup workflow."""
    setup_logging(args.verbose)
    config = AppConfig.from_yaml_file(args.config)
    orchestrator = BackupOrchestrator(config)

    print(f"\n[+] Loaded configuration from: {args.config}")
    print(f"[+] Storage Provider : {config.storage_provider.upper()}")
    print(f"[+] Configured Clients: {len(config.clients)}")
    if args.dry_run:
        print("[!] DRY RUN MODE ENABLED - No changes will be written to storage or catalog\n")

    reports = orchestrator.run_all(client_id_filter=args.client, dry_run=args.dry_run)

    print("\n" + "=" * 80)
    print("BACKUP EXECUTION SUMMARY")
    print("=" * 80)
    for report in reports:
        print(f"Client    : {report.client_id} ({report.client_display_name})")
        print(f"Status    : COMPLETED in {report.duration_seconds:.2f}s")
        print(f"Databases : {len(report.databases)} dumped")
        print(f"Files     : +{report.added_count} added, *{report.updated_count} updated, -{report.deleted_count} deleted (preserved)")
        print(f"Volume    : {report.total_incremental_bytes / (1024*1024):.2f} MB")
        print("-" * 80)


def command_verify(args):
    """Verify connections to Google Drive and clients."""
    setup_logging(args.verbose)
    config = AppConfig.from_yaml_file(args.config)
    orchestrator = BackupOrchestrator(config)

    print("\n" + "=" * 80)
    print("CONNECTIVITY VERIFICATION")
    print("=" * 80)
    report = orchestrator.verify_all_connections()

    storage_status = "CONNECTED [OK]" if report["storage_connected"] else "FAILED [ERROR]"
    print(f"Storage Provider ({report['storage_provider']}): {storage_status}")
    print("-" * 80)

    all_ok = report["storage_connected"]
    for cid, cinfo in report["clients"].items():
        status = "CONNECTED [OK]" if cinfo["connected"] else f"FAILED: {cinfo.get('error', 'Unknown')}"
        print(f"Client [{cid}] (Mode: {cinfo['mode']}): {status}")
        if not cinfo["connected"]:
            all_ok = False

    print("=" * 80)
    if not all_ok:
        sys.exit(1)


def command_prune(args):
    """Run retention enforcement only."""
    setup_logging(args.verbose)
    config = AppConfig.from_yaml_file(args.config)
    orchestrator = BackupOrchestrator(config)

    print(f"\n[+] Running Retention Prune across configured clients (Dry Run: {args.dry_run})...")
    for client in config.clients:
        if args.client and client.client_id != args.client:
            continue
        days = args.days if args.days is not None else client.retention_days
        purged = orchestrator.retention.enforce_client_retention(
            client_id=client.client_id,
            retention_days=days,
            dry_run=args.dry_run
        )
        print(f"Client [{client.client_id}]: {len(purged)} folder(s) processed for pruning.")


def command_history(args):
    """View historical runs from SQLite catalog."""
    config = AppConfig.from_yaml_file(args.config)
    catalog = StateCatalog(config.catalog_db_path)

    for client in config.clients:
        if args.client and client.client_id != args.client:
            continue
        history = catalog.get_run_history(client.client_id, limit=args.limit)
        print("\n" + "=" * 80)
        print(f"RUN HISTORY: {client.client_id} ({client.display_name})")
        print("=" * 80)
        if not history:
            print("  No previous backup runs recorded in catalog.")
            continue

        print(f"{'DATE':<12} {'TIME (UTC)':<20} {'STATUS':<10} {'+ADD':<6} {'*UPD':<6} {'-DEL':<6} {'DBS':<4} {'DURATION':<10}")
        print("-" * 80)
        for h in history:
            print(
                f"{h['run_date']:<12} {h['run_timestamp']:<20} {h['status']:<10} "
                f"{h['files_added']:<6} {h['files_updated']:<6} {h['files_deleted']:<6} "
                f"{h['dbs_dumped']:<4} {h['duration_seconds']:<8.2f}s"
            )


def command_init(args):
    """Generate a starter config.yaml file."""
    target = Path(args.output).resolve()
    example_path = Path(__file__).parent / "config" / "config.example.yaml"
    if not example_path.exists():
        print("Error: config.example.yaml template not found.")
        sys.exit(1)

    if target.exists() and not args.force:
        print(f"Error: Target file {target} already exists. Use --force to overwrite.")
        sys.exit(1)

    shutil.copyfile(str(example_path), str(target))
    print(f"[+] Created starter configuration file: {target}")


def main():
    parser = argparse.ArgumentParser(
        description="Enterprise Multi-Tenant Backup Service to Google Drive"
    )
    parser.add_argument(
        "--config", "-c", default="config.yaml",
        help="Path to YAML configuration file (default: config.yaml)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging output"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # run command
    p_run = subparsers.add_parser("run", help="Execute backup cycle")
    p_run.add_argument("--client", help="Run only for a specific client_id")
    p_run.add_argument("--dry-run", action="store_true", help="Simulate execution without modifying storage")
    p_run.set_defaults(func=command_run)

    # verify command
    p_verify = subparsers.add_parser("verify", help="Verify credentials and connectivity")
    p_verify.set_defaults(func=command_verify)

    # prune command
    p_prune = subparsers.add_parser("prune", help="Enforce retention policy")
    p_prune.add_argument("--client", help="Prune only for a specific client_id")
    p_prune.add_argument("--days", type=int, help="Override retention days window")
    p_prune.add_argument("--dry-run", action="store_true", help="Simulate pruning without deleting")
    p_prune.set_defaults(func=command_prune)

    # history command
    p_history = subparsers.add_parser("history", help="Show backup execution history")
    p_history.add_argument("--client", help="Filter history by client_id")
    p_history.add_argument("--limit", type=int, default=15, help="Number of records to show")
    p_history.set_defaults(func=command_history)

    # init command
    p_init = subparsers.add_parser("init", help="Generate a starter configuration file")
    p_init.add_argument("--output", "-o", default="config.yaml", help="Output path (default: config.yaml)")
    p_init.add_argument("--force", "-f", action="store_true", help="Overwrite existing file")
    p_init.set_defaults(func=command_init)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
