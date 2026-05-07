from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

import click
import duckdb
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from uberblick.audit_packs import all_packs, pack_name
from uberblick.connector import SnowflakeConnectionError, connect
from uberblick.slack import build_block_kit_payload, post_to_slack
from uberblick.diff import compute_diff
from uberblick.history import (
    account_dir,
    latest_two,
    list_history,
    save_to_history,
    trim_history,
)
from uberblick.hris import load_hris_into
from uberblick.findings import run_rules, to_json_serializable
from uberblick.paths import find_paths_to_object, find_paths_user_to_object
from uberblick.report import render_findings_markdown, render_paths_markdown
from uberblick.report_data import (
    compute_admin_reach,
    compute_all_role_impersonation_details,
    compute_direct_user_grants,
    compute_policy_protections,
    compute_role_census,
    compute_role_graph,
    compute_role_groupings,
    compute_role_impersonation_detail,
    compute_role_impersonation_surface,
    compute_role_origin_breakdown,
    compute_secondary_role_breakdown,
    compute_tag_classifications,
    compute_user_blast_radius,
    compute_user_census,
    compute_user_secondary_reach,
    compute_view_summary,
)
from uberblick.report_html import render_report
from uberblick.snapshot import run_snapshot

console = Console()


def _load_env() -> None:
    repo_env = Path(__file__).resolve().parents[3] / ".env"
    cwd_env = Path.cwd() / ".env"
    for candidate in (cwd_env, repo_env):
        if candidate.exists():
            load_dotenv(candidate)
            return
    load_dotenv()


@click.group()
def main() -> None:
    _load_env()


@main.command()
@click.option(
    "--output-dir",
    "-o",
    default=".",
    show_default=True,
    type=click.Path(),
    help="Directory for snapshot.duckdb + report.html outputs.",
)
@click.option("--days", default=30, show_default=True, type=int)
@click.option("--depth-cap", default=30, show_default=True, type=int)
@click.option("--live/--no-live", default=False, show_default=True)
@click.option("--audit", type=click.Choice(all_packs()), default=None)
@click.option(
    "--slack-webhook",
    default=None,
    envvar="UBERBLICK_SLACK_WEBHOOK_URL",
)
@click.option(
    "--slack-mode",
    type=click.Choice(["off", "digest", "alert"]),
    default="digest",
    show_default=True,
    help=(
        "off = never post; digest = post every run; "
        "alert = post only when CRITICAL or HIGH findings present."
    ),
)
@click.option("--slack-report-url", default=None)
@click.option("--hris-csv", type=click.Path(), default=None)
def audit(
    output_dir: str,
    days: int,
    depth_cap: int,
    live: bool,
    audit: str | None,
    slack_webhook: str | None,
    slack_mode: str,
    slack_report_url: str | None,
    hris_csv: str | None,
) -> None:
    out = Path(output_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    snapshot_path = out / "snapshot.duckdb"
    report_path = out / "report.html"
    findings_json_path = out / "findings.json"

    console.print("[bold]Uberblick audit[/bold] (snapshot -> findings -> report)")

    try:
        with connect() as conn:
            console.print(f"[dim]Snapshotting to {snapshot_path}...[/dim]")
            run_snapshot(
                conn, snapshot_path,
                days=days, depth_cap=depth_cap, live=live,
            )
    except SnowflakeConnectionError as e:
        console.print(f"[red]Configuration error:[/red] {e}")
        sys.exit(2)
    except Exception as e:
        console.print(f"[red]Snapshot failed:[/red] {type(e).__name__}: {e}")
        sys.exit(1)

    duck = duckdb.connect(str(snapshot_path), read_only=False)
    try:
        if hris_csv:
            try:
                count = load_hris_into(duck, Path(hris_csv))
                console.print(f"[dim]Loaded {count} HRIS rows.[/dim]")
            except Exception as e:
                console.print(
                    f"[yellow]HRIS load failed:[/yellow] {type(e).__name__}: {e}"
                )
        results = run_rules(duck, audit_pack=audit)
    finally:
        duck.close()

    findings_json_path.write_text(
        json.dumps(to_json_serializable(results), indent=2)
    )

    sidecar = snapshot_path.parent / f"{snapshot_path.name}.meta.json"
    snap_meta = {}
    if sidecar.exists():
        try:
            snap_meta = json.loads(sidecar.read_text())
        except Exception:
            snap_meta = {}

    duck = duckdb.connect(str(snapshot_path), read_only=True)
    try:
        if hris_csv:
            try:
                load_hris_into(duck, Path(hris_csv))
            except Exception:
                pass
        diff_data = None
        try:
            account = snap_meta.get("account")
            if account:
                snaps = list_history(account)
                older = [s for s in snaps if s.resolve() != snapshot_path.resolve()]
                if older:
                    from dataclasses import asdict
                    diff_data = asdict(compute_diff(older[-1], snapshot_path))
        except Exception:
            diff_data = None

        data = {
            "snapshot": {
                "account": snap_meta.get("account"),
                "user": snap_meta.get("user"),
                "role": snap_meta.get("role"),
                "snapshot_at": snap_meta.get("snapshot_at"),
                "lookback_days": snap_meta.get("lookback_days", days),
                "closure_edges": snap_meta.get("closure_edges"),
                "closure_max_depth": snap_meta.get("closure_max_depth"),
            },
            "views": compute_view_summary(duck),
            "role_origins": compute_role_origin_breakdown(duck),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "category": f.category,
                    "title": f.title,
                    "summary": f.summary,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "audit_packs": f.audit_packs,
                }
                for f in results
            ],
            "admin_reach": compute_admin_reach(duck),
            "direct_grants": compute_direct_user_grants(duck),
            "role_graph": compute_role_graph(duck),
            "role_census": compute_role_census(duck),
            "role_groupings": compute_role_groupings(duck),
            "user_census": compute_user_census(duck),
            "role_impersonation": compute_role_impersonation_surface(duck),
            "role_impersonation_details": compute_all_role_impersonation_details(duck),
            "user_secondary_reach": compute_user_secondary_reach(duck),
            "secondary_role_breakdown": compute_secondary_role_breakdown(duck),
            "user_blast_radius": compute_user_blast_radius(duck),
            "policy_protections": compute_policy_protections(duck),
            "tag_classifications": compute_tag_classifications(duck),
            "diff": diff_data,
        }
    finally:
        duck.close()

    report_path.write_text(render_report(data))

    sev_counts: dict[str, int] = {}
    for f in results:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    console.print()
    console.print(
        f"[green]Findings:[/green] {len(results)} "
        + " ".join(
            f"{s}={n}" for s, n in
            [("CRITICAL", sev_counts.get("CRITICAL", 0)),
             ("HIGH", sev_counts.get("HIGH", 0)),
             ("MEDIUM", sev_counts.get("MEDIUM", 0)),
             ("LOW", sev_counts.get("LOW", 0))]
            if n > 0
        )
    )
    console.print(f"[green]Report:[/green] {report_path}")
    console.print(f"[green]Findings JSON:[/green] {findings_json_path}")

    if slack_webhook and slack_mode != "off":
        worth_posting = True
        if slack_mode == "alert":
            worth_posting = (
                sev_counts.get("CRITICAL", 0) > 0
                or sev_counts.get("HIGH", 0) > 0
            )
        if worth_posting:
            payload = build_block_kit_payload(
                results,
                snapshot_meta=snap_meta,
                audit_pack=audit,
                report_url=slack_report_url,
            )
            status, body = post_to_slack(slack_webhook, payload)
            if 200 <= status < 300:
                console.print(f"[dim]Slack notified ({status}).[/dim]")
            else:
                console.print(
                    f"[yellow]Slack post {status}:[/yellow] {body[:200]}"
                )
        else:
            console.print(
                "[dim]Slack alert-mode: nothing CRITICAL/HIGH, skipping post.[/dim]"
            )


@main.command()
@click.option(
    "--env-file",
    default=".env",
    show_default=True,
    type=click.Path(),
    help="Path to .env file to write.",
)
@click.option("--force", is_flag=True, help="Overwrite existing .env without prompting.")
def init(env_file: str, force: bool) -> None:
    env_path = Path(env_file).resolve()
    console.print("[bold]Uberblick init[/bold]")
    console.print(
        "Walk through Snowflake credentials, write a .env file, run verify."
    )
    console.print()

    if env_path.exists() and not force:
        if not click.confirm(f"{env_path} already exists. Overwrite?", default=False):
            console.print("[yellow]Aborted.[/yellow]")
            return

    console.print("[dim]Account locator: e.g. AYWFACZ-KPC93707 or your_org.your_account[/dim]")
    account = click.prompt("SNOWFLAKE_ACCOUNT", type=str)
    console.print(
        "[dim]Reader role recommended: a dedicated role with "
        "IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE.[/dim]"
    )
    user = click.prompt("SNOWFLAKE_USER", type=str)
    role = click.prompt("SNOWFLAKE_ROLE", type=str, default="UBERBLICK_RO")
    warehouse = click.prompt("SNOWFLAKE_WAREHOUSE", type=str, default="UBERBLICK_WH")
    password = click.prompt("SNOWFLAKE_PASSWORD", type=str, hide_input=True)

    body = (
        f"SNOWFLAKE_ACCOUNT={account}\n"
        f"SNOWFLAKE_USER={user}\n"
        f"SNOWFLAKE_PASSWORD={password}\n"
        f"SNOWFLAKE_ROLE={role}\n"
        f"SNOWFLAKE_WAREHOUSE={warehouse}\n"
        f"\n"
        f"UBERBLICK_ANTHROPIC_API_KEY=\n"
        f"UBERBLICK_OPENAI_API_KEY=\n"
        f"UBERBLICK_SLACK_WEBHOOK_URL=\n"
    )
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text(body)
    try:
        env_path.chmod(0o600)
    except OSError:
        pass
    console.print(f"[green]Wrote {env_path}[/green]")

    if click.confirm("Run uberblick verify now?", default=True):
        load_dotenv(env_path)
        try:
            with connect() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT CURRENT_VERSION(), CURRENT_ACCOUNT(), "
                    "CURRENT_USER(), CURRENT_ROLE(), CURRENT_WAREHOUSE()"
                )
                row = cur.fetchone()
                console.print()
                console.print("[green]Connected.[/green]")
                console.print(f"  Snowflake version: {row[0]}")
                console.print(f"  Account:           {row[1]}")
                console.print(f"  User:              {row[2]}")
                console.print(f"  Role:              {row[3]}")
                console.print(f"  Warehouse:         {row[4]}")
                cur.execute(
                    "SELECT COUNT(*) FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY "
                    "WHERE START_TIME >= DATEADD('hour', -1, CURRENT_TIMESTAMP())"
                )
                count = cur.fetchone()[0]
                console.print(
                    f"  ACCOUNT_USAGE accessible: {count} queries in last hour"
                )
        except Exception as e:
            console.print(f"[red]Verify failed:[/red] {type(e).__name__}: {e}")
            console.print(
                "[yellow]Check the credentials in[/yellow] " + str(env_path)
            )
            return

    console.print()
    console.print("[bold]Next steps:[/bold]")
    console.print("  uberblick snapshot")
    console.print("  uberblick findings")
    console.print("  uberblick report --output report.html")


@main.command()
def verify() -> None:
    try:
        with connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT CURRENT_VERSION(), CURRENT_ACCOUNT(), CURRENT_USER(), "
                "CURRENT_ROLE(), CURRENT_WAREHOUSE()"
            )
            row = cur.fetchone()
            console.print("[green]Connected.[/green]")
            console.print(f"  Snowflake version: {row[0]}")
            console.print(f"  Account:           {row[1]}")
            console.print(f"  User:              {row[2]}")
            console.print(f"  Role:              {row[3]}")
            console.print(f"  Warehouse:         {row[4]}")

            cur.execute(
                "SELECT COUNT(*) FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY "
                "WHERE START_TIME >= DATEADD('hour', -1, CURRENT_TIMESTAMP())"
            )
            count = cur.fetchone()[0]
            console.print(
                f"  ACCOUNT_USAGE accessible: {count} queries in last hour"
            )
    except SnowflakeConnectionError as e:
        console.print(f"[red]Configuration error:[/red] {e}")
        sys.exit(2)
    except Exception as e:
        console.print(f"[red]Connection failed:[/red] {type(e).__name__}: {e}")
        sys.exit(1)


@main.command()
@click.option(
    "--output",
    "-o",
    default="snapshot.duckdb",
    show_default=True,
    type=click.Path(),
    help="Output DuckDB file path.",
)
@click.option(
    "--days",
    default=30,
    show_default=True,
    type=int,
    help="Lookback window in days for time-filtered views.",
)
@click.option(
    "--depth-cap",
    default=30,
    show_default=True,
    type=int,
    help="Recursion depth cap for the role hierarchy closure.",
)
@click.option(
    "--live/--no-live",
    default=False,
    show_default=True,
    help=(
        "Use real-time SHOW commands for the role/grant spine instead of "
        "ACCOUNT_USAGE views. Useful for verifying changes immediately "
        "(ACCOUNT_USAGE has up to 120-min lag). Skips login/query/access history."
    ),
)
@click.option(
    "--save-history/--no-save-history",
    default=True,
    show_default=True,
    help="Copy snapshot into ~/.uberblick/history/<account>/ for diff support.",
)
@click.option("--keep-history", default=30, show_default=True, type=int)
def snapshot(
    output: str,
    days: int,
    depth_cap: int,
    live: bool,
    save_history: bool,
    keep_history: int,
) -> None:
    output_path = Path(output)
    try:
        with connect() as conn:
            console.print(
                f"[dim]Snapshotting ACCOUNT_USAGE views to {output_path}...[/dim]"
            )

            def on_view_start(name: str) -> None:
                console.print(f"  [dim]extracting[/dim] {name}...")

            def on_view_done(extraction) -> None:
                if extraction.error:
                    console.print(
                        f"    [yellow]warning:[/yellow] {extraction.name} -- "
                        f"{extraction.error}"
                    )
                else:
                    age = (
                        f"latest record {extraction.minutes_since_latest_record}m old"
                        if extraction.minutes_since_latest_record is not None
                        else "no time index"
                    )
                    console.print(
                        f"    [green]ok[/green] {extraction.name}: "
                        f"{extraction.rows:,} rows, {age}"
                    )

            def on_phase(phase: str) -> None:
                if phase == "classify":
                    console.print("[dim]classifying role origins...[/dim]")
                elif phase == "closure":
                    console.print(
                        "[dim]building cycle-safe role hierarchy closure...[/dim]"
                    )
                else:
                    console.print(f"[dim]{phase}[/dim]")

            result = run_snapshot(
                conn,
                output_path,
                days=days,
                depth_cap=depth_cap,
                on_view_start=on_view_start,
                on_view_done=on_view_done,
                on_phase=on_phase,
                live=live,
            )

        console.print()
        console.print(f"[green]Snapshot complete.[/green]")
        console.print(f"  Path:       {result.output_path}")
        console.print(f"  Sidecar:    {result.output_path}.meta.json")
        console.print(f"  Account:    {result.account}")
        console.print(f"  User/role:  {result.user} / {result.role}")
        console.print(f"  Captured:   {result.snapshot_at}")
        console.print(
            f"  Closure:    {result.closure_edges} edges, "
            f"max depth observed = {result.closure_max_depth} (cap {result.closure_depth_cap})"
        )

        if result.role_origin_breakdown:
            origin_tbl = Table(
                title="Role origin breakdown", show_lines=False, box=None
            )
            origin_tbl.add_column("Origin", style="cyan")
            origin_tbl.add_column("Roles", justify="right")
            for origin, count in result.role_origin_breakdown:
                origin_tbl.add_row(origin, f"{count:,}")
            console.print(origin_tbl)

        summary = Table(title="View summary", show_lines=False, box=None)
        summary.add_column("View", style="cyan")
        summary.add_column("Rows", justify="right")
        summary.add_column("Latest record (min ago)", justify="right")
        summary.add_column("Doc max lag (min)", justify="right")
        summary.add_column("Status")
        for name, info in result.views.items():
            status = "[red]error[/red]" if info["error"] else "[green]ok[/green]"
            summary.add_row(
                name,
                f"{info['rows']:,}",
                str(info["minutes_since_latest_record"])
                if info["minutes_since_latest_record"] is not None
                else "-",
                str(info["documented_max_lag_minutes"])
                if info["documented_max_lag_minutes"] is not None
                else "-",
                status,
            )
        console.print(summary)

        if save_history:
            try:
                hist_path = save_to_history(
                    output_path,
                    account=result.account,
                    sidecar_path=Path(str(result.output_path) + ".meta.json"),
                )
                trimmed = trim_history(result.account, keep=keep_history)
                console.print(
                    f"[dim]Saved to history: {hist_path}"
                    + (f" (trimmed {trimmed} older snapshots)" if trimmed else "")
                    + "[/dim]"
                )
            except Exception as e:
                console.print(
                    f"[yellow]History save warning:[/yellow] {type(e).__name__}: {e}"
                )
    except SnowflakeConnectionError as e:
        console.print(f"[red]Configuration error:[/red] {e}")
        sys.exit(2)
    except Exception as e:
        console.print(f"[red]Snapshot failed:[/red] {type(e).__name__}: {e}")
        sys.exit(1)


def _open_snapshot(snapshot_path: Path):
    if not snapshot_path.exists():
        console.print(
            f"[red]Snapshot not found:[/red] {snapshot_path}. "
            f"Run 'uberblick snapshot --output {snapshot_path}' first."
        )
        sys.exit(2)
    return duckdb.connect(str(snapshot_path), read_only=True)


_SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "magenta",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim",
}


@main.command()
@click.option(
    "--snapshot",
    "snapshot_path",
    default="snapshot.duckdb",
    show_default=True,
    type=click.Path(),
    help="Path to a snapshot DuckDB file.",
)
@click.option(
    "--json-out",
    type=click.Path(),
    default=None,
    help="Optional path to write findings as JSON.",
)
@click.option(
    "--markdown-out",
    type=click.Path(),
    default=None,
    help="Optional path to write findings as a markdown report.",
)
@click.option(
    "--audit",
    type=click.Choice(all_packs()),
    default=None,
    help=(
        "Filter to rules in a specific audit pack: cis (CIS Snowflake "
        "Foundations), soc2 (CC6 logical access), sox (ITGC), hipaa "
        "(164.312), or unc5537 (2024 Snowflake breach lessons)."
    ),
)
@click.option(
    "--slack-webhook",
    default=None,
    envvar="UBERBLICK_SLACK_WEBHOOK_URL",
    help="Slack incoming webhook URL. Posts a Block-Kit summary after the run.",
)
@click.option(
    "--slack-report-url",
    default=None,
    help="Optional URL to link from the Slack message (e.g. GitHub Pages report URL).",
)
@click.option(
    "--slack-mode",
    type=click.Choice(["off", "digest", "alert"]),
    default="digest",
    show_default=True,
    help="alert mode posts only when CRITICAL or HIGH findings present.",
)
@click.option(
    "--hris-csv",
    type=click.Path(),
    default=None,
    help=(
        "Optional HRIS CSV file with columns including login_name (or email) "
        "and status. Enables joiner-mover-leaver finding rules."
    ),
)
def findings(
    snapshot_path: str,
    json_out: str | None,
    markdown_out: str | None,
    audit: str | None,
    slack_webhook: str | None,
    slack_report_url: str | None,
    slack_mode: str,
    hris_csv: str | None,
) -> None:
    snap = Path(snapshot_path).resolve()
    if not snap.exists():
        console.print(f"[red]Snapshot not found:[/red] {snap}")
        sys.exit(2)
    duck = duckdb.connect(str(snap), read_only=False)
    try:
        if hris_csv:
            try:
                count = load_hris_into(duck, Path(hris_csv))
                console.print(f"[dim]Loaded {count} HRIS rows from {hris_csv}[/dim]")
            except Exception as e:
                console.print(
                    f"[yellow]HRIS load failed:[/yellow] {type(e).__name__}: {e}"
                )
        results = run_rules(duck, audit_pack=audit)
        sidecar_path = Path(snapshot_path).parent / f"{Path(snapshot_path).name}.meta.json"
        snapshot_meta = None
        if sidecar_path.exists():
            try:
                snapshot_meta = json.loads(sidecar_path.read_text())
            except Exception:
                snapshot_meta = None
    finally:
        duck.close()

    if not results:
        title = "No findings"
        if audit:
            title = f"No findings in {pack_name(audit)}"
        console.print(
            f"[green]{title}.[/green] (Either you're squeaky clean or "
            "the snapshot is unusually quiet.)"
        )
    else:
        title = f"Findings ({len(results)})"
        if audit:
            title = f"{pack_name(audit)} ({len(results)})"
        tbl = Table(title=title, show_lines=True)
        tbl.add_column("Severity")
        if audit:
            tbl.add_column("Control", style="bold")
        tbl.add_column("Rule", style="cyan")
        tbl.add_column("Title")
        tbl.add_column("Category", style="dim")
        for f in results:
            color = _SEVERITY_COLORS.get(f.severity, "white")
            row = [f"[{color}]{f.severity}[/{color}]"]
            if audit:
                ctrl = next(
                    (p["control"] for p in f.audit_packs if p["pack"] == audit),
                    "—",
                )
                row.append(ctrl)
            row.extend([f.rule_id, f.title, f.category])
            tbl.add_row(*row)
        console.print(tbl)

    if json_out:
        out_path = Path(json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(to_json_serializable(results), indent=2))
        console.print(f"[dim]Wrote {out_path}[/dim]")

    if markdown_out:
        md_path = Path(markdown_out)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(
            render_findings_markdown(results, snapshot_metadata=snapshot_meta)
        )
        console.print(f"[dim]Wrote {md_path}[/dim]")

    if slack_webhook and slack_mode != "off":
        worth_posting = True
        if slack_mode == "alert":
            worth_posting = any(
                f.severity in ("CRITICAL", "HIGH") for f in results
            )
        if worth_posting:
            payload = build_block_kit_payload(
                results,
                snapshot_meta=snapshot_meta,
                audit_pack=audit,
                report_url=slack_report_url,
            )
            status, body = post_to_slack(slack_webhook, payload)
            if 200 <= status < 300:
                console.print(f"[dim]Slack notified ({status}).[/dim]")
            else:
                console.print(
                    f"[yellow]Slack post returned {status}:[/yellow] {body[:200]}"
                )
        else:
            console.print(
                "[dim]Slack alert-mode: nothing CRITICAL/HIGH, skipping post.[/dim]"
            )


@main.command()
@click.option(
    "--snapshot",
    "snapshot_path",
    default="snapshot.duckdb",
    show_default=True,
    type=click.Path(),
)
@click.option(
    "--output",
    "-o",
    default="report.html",
    show_default=True,
    type=click.Path(),
)
def report(snapshot_path: str, output: str) -> None:
    snap_path = Path(snapshot_path)
    output_path = Path(output)
    duck = _open_snapshot(snap_path)
    try:
        findings_results = run_rules(duck)

        sidecar = snap_path.parent / f"{snap_path.name}.meta.json"
        if sidecar.exists():
            try:
                snap_meta = json.loads(sidecar.read_text())
            except Exception:
                snap_meta = {}
        else:
            snap_meta = {}

        diff_data = None
        try:
            account = snap_meta.get("account")
            if account:
                snaps = list_history(account)
                older = [s for s in snaps if s.resolve() != snap_path.resolve()]
                if older:
                    prev = older[-1]
                    from dataclasses import asdict
                    diff_obj = compute_diff(prev, snap_path)
                    diff_data = asdict(diff_obj)
        except Exception:
            diff_data = None

        data = {
            "snapshot": {
                "account": snap_meta.get("account"),
                "user": snap_meta.get("user"),
                "role": snap_meta.get("role"),
                "snapshot_at": snap_meta.get("snapshot_at"),
                "lookback_days": snap_meta.get("lookback_days", 30),
                "closure_edges": snap_meta.get("closure_edges"),
                "closure_max_depth": snap_meta.get("closure_max_depth"),
            },
            "views": compute_view_summary(duck),
            "role_origins": compute_role_origin_breakdown(duck),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "category": f.category,
                    "title": f.title,
                    "summary": f.summary,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "audit_packs": f.audit_packs,
                }
                for f in findings_results
            ],
            "admin_reach": compute_admin_reach(duck),
            "direct_grants": compute_direct_user_grants(duck),
            "role_graph": compute_role_graph(duck),
            "role_census": compute_role_census(duck),
            "role_groupings": compute_role_groupings(duck),
            "user_census": compute_user_census(duck),
            "role_impersonation": compute_role_impersonation_surface(duck),
            "role_impersonation_details": compute_all_role_impersonation_details(duck),
            "user_secondary_reach": compute_user_secondary_reach(duck),
            "secondary_role_breakdown": compute_secondary_role_breakdown(duck),
            "user_blast_radius": compute_user_blast_radius(duck),
            "policy_protections": compute_policy_protections(duck),
            "tag_classifications": compute_tag_classifications(duck),
            "diff": diff_data,
        }
    finally:
        duck.close()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_report(data))
    console.print(f"[green]Report written[/green] {output_path}")
    console.print(f"  open {output_path}  (or python -m http.server)")


@main.command()
@click.option(
    "--profile",
    type=click.Choice(["small", "medium", "realistic", "large", "huge"]),
    default="medium",
    show_default=True,
)
@click.option(
    "--output",
    "-o",
    default="synthetic.duckdb",
    show_default=True,
    type=click.Path(),
)
@click.option("--seed", default=42, type=int, show_default=True)
@click.option("--users", type=int, default=None, help="Override user count.")
@click.option("--functional", type=int, default=None, help="Override functional role count.")
@click.option("--databases", type=int, default=None, help="Override database count.")
@click.option(
    "--schemas-total",
    type=int,
    default=None,
    help="Override total schema count (distributed across databases).",
)
@click.option(
    "--tables-per-schema",
    type=int,
    default=None,
    help="Override tables per schema.",
)
def synthetic(
    profile: str,
    output: str,
    seed: int,
    users: int | None,
    functional: int | None,
    databases: int | None,
    schemas_total: int | None,
    tables_per_schema: int | None,
) -> None:
    from uberblick.synthetic import generate

    overrides = {
        "users": users,
        "functional": functional,
        "databases": databases,
        "schemas_total": schemas_total,
        "tables_per_schema": tables_per_schema,
    }
    counts = generate(profile, Path(output), seed=seed, overrides=overrides)
    console.print(f"[green]Synthetic snapshot ({profile}) written[/green] {output}")
    for k, v in counts.items():
        console.print(f"  {k}: {v:,}")


@main.command()
@click.option("--from", "from_path", default=None, type=click.Path(),
              help="Earlier snapshot. Defaults to second-most-recent in history.")
@click.option("--to", "to_path", default=None, type=click.Path(),
              help="Later snapshot. Defaults to most-recent in history.")
@click.option("--account", default=None,
              help="Account locator for history lookup (defaults to env or current).")
@click.option("--json-out", type=click.Path(), default=None)
def diff(
    from_path: str | None,
    to_path: str | None,
    account: str | None,
    json_out: str | None,
) -> None:
    if from_path and to_path:
        from_p = Path(from_path)
        to_p = Path(to_path)
    else:
        if not account:
            console.print(
                "[red]Need either --from + --to OR --account[/red] "
                "(to pull the latest two snapshots from history)."
            )
            sys.exit(2)
        prev, curr = latest_two(account)
        if not prev or not curr:
            console.print(
                f"[yellow]Need at least 2 snapshots in history for {account}.[/yellow] "
                f"Currently have: {len(list_history(account))}."
            )
            sys.exit(2)
        from_p = prev
        to_p = curr

    console.print(f"[dim]Comparing {from_p.name} -> {to_p.name}[/dim]")
    d = compute_diff(from_p, to_p)

    def section(title: str, items: list, fmt):
        if not items:
            return
        console.print()
        console.print(f"[bold]{title}[/bold] ({len(items)})")
        for it in items[:30]:
            console.print(f"  {fmt(it)}")
        if len(items) > 30:
            console.print(f"  [dim]... ({len(items) - 30} more)[/dim]")

    section("[red]Removed roles[/red]", d.removed_roles,
            lambda x: f"- {x['name']} (owner: {x['owner']})")
    section("[green]Added roles[/green]", d.added_roles,
            lambda x: f"+ {x['name']} (owner: {x['owner']})")
    section("[red]Removed users[/red]", d.removed_users,
            lambda x: f"- {x['name']} ({x['type']})")
    section("[green]Added users[/green]", d.added_users,
            lambda x: f"+ {x['name']} ({x['type']})")
    section("[red]Revoked user-role grants[/red]", d.removed_user_role_grants,
            lambda x: f"- {x['user']} -> {x['role']}")
    section("[green]New user-role grants[/green]", d.added_user_role_grants,
            lambda x: f"+ {x['user']} -> {x['role']}")
    section("[yellow]MFA toggled[/yellow]", d.user_mfa_toggled,
            lambda x: f"{x['user']}: {x['from_mfa']} -> {x['to_mfa']}")
    section("[yellow]Default role changed[/yellow]", d.user_default_role_changed,
            lambda x: f"{x['user']}: {x['from_default']} -> {x['to_default']}")
    section("[red]Revoked role grants[/red]", d.removed_role_grants,
            lambda x: f"- {x['grantee']} {x['privilege']} on {x['granted_on']} {x['object']}")
    section("[green]New role grants[/green]", d.added_role_grants,
            lambda x: f"+ {x['grantee']} {x['privilege']} on {x['granted_on']} {x['object']}")

    total = (
        len(d.added_roles) + len(d.removed_roles)
        + len(d.added_users) + len(d.removed_users)
        + len(d.added_user_role_grants) + len(d.removed_user_role_grants)
        + len(d.added_role_grants) + len(d.removed_role_grants)
        + len(d.user_mfa_toggled) + len(d.user_default_role_changed)
    )
    console.print()
    if total == 0:
        console.print("[green]No changes detected.[/green]")
    else:
        console.print(f"[bold]Total changes: {total}[/bold]")

    if json_out:
        from dataclasses import asdict
        Path(json_out).write_text(json.dumps(asdict(d), indent=2))
        console.print(f"[dim]Wrote {json_out}[/dim]")


@main.command()
@click.option("--account", required=True)
def history(account: str) -> None:
    snaps = list_history(account)
    if not snaps:
        console.print(f"[yellow]No history for {account}.[/yellow]")
        console.print(f"  Expected dir: {account_dir(account)}")
        return
    console.print(f"[bold]History for {account}[/bold] ({len(snaps)} snapshots)")
    for s in snaps:
        size_kb = s.stat().st_size / 1024
        console.print(f"  {s.name}  ({size_kb:,.0f} KB)")


@main.command()
@click.argument("role_name")
@click.option(
    "--snapshot",
    "snapshot_path",
    default="snapshot.duckdb",
    show_default=True,
    type=click.Path(),
)
@click.option("--limit", default=50, show_default=True, type=int)
def impersonate(role_name: str, snapshot_path: str, limit: int) -> None:
    duck = _open_snapshot(Path(snapshot_path))
    try:
        detail = compute_role_impersonation_detail(duck, role_name)
    finally:
        duck.close()

    if not detail or not detail.get("inherited_roles"):
        console.print(
            f"[yellow]No data for role {role_name}.[/yellow] "
            f"(Role not in snapshot, or has no closure entries.)"
        )
        return

    inherited = detail["inherited_roles"]
    grants = detail["object_grants"]
    users = detail["users_holding_role"]

    console.print(
        f"[green]Impersonation surface for role[/green] "
        f"[bold]{detail['role']}[/bold]"
    )
    console.print(
        f"  Inherited roles: {len(inherited)} • "
        f"Object grants: {len(grants)} • "
        f"Users holding this role: {len(users)}"
    )
    console.print()

    inh_tbl = Table(title="Roles inherited", show_lines=False, box=None)
    inh_tbl.add_column("Role", style="cyan")
    inh_tbl.add_column("Depth", justify="right")
    for r in inherited[:limit]:
        inh_tbl.add_row(r["name"], str(r["depth"]))
    if len(inherited) > limit:
        inh_tbl.add_row(f"... ({len(inherited) - limit} more)", "")
    console.print(inh_tbl)

    if grants:
        gr_tbl = Table(title="Object grants", show_lines=False, box=None)
        gr_tbl.add_column("Type")
        gr_tbl.add_column("Object", style="cyan")
        gr_tbl.add_column("Privilege")
        gr_tbl.add_column("Via role", style="dim")
        for g in grants[:limit]:
            qualified = ".".join(p for p in (g.get("database"), g.get("schema"), g["name"]) if p)
            gr_tbl.add_row(
                g["object_type"], qualified, g["privilege"], g["via_role"]
            )
        if len(grants) > limit:
            gr_tbl.add_row(f"... ({len(grants) - limit} more)", "", "", "")
        console.print(gr_tbl)

    if users:
        console.print(f"[dim]Users holding this role: {', '.join(users)}[/dim]")


@main.group()
def paths() -> None:
    pass


@paths.command("from-user")
@click.argument("user")
@click.argument("object_name")
@click.option(
    "--privilege",
    default=None,
    help="Optional privilege filter (e.g. SELECT).",
)
@click.option(
    "--snapshot",
    "snapshot_path",
    default="snapshot.duckdb",
    show_default=True,
    type=click.Path(),
)
@click.option("--limit", default=50, show_default=True, type=int)
def paths_from_user(
    user: str,
    object_name: str,
    privilege: str | None,
    snapshot_path: str,
    limit: int,
) -> None:
    duck = _open_snapshot(Path(snapshot_path))
    try:
        results = find_paths_user_to_object(
            duck, user, object_name, privilege=privilege, limit=limit
        )
    finally:
        duck.close()

    if not results:
        console.print(
            f"[yellow]No paths found from USER {user} to {object_name}"
            f"{' [' + privilege + ']' if privilege else ''}.[/yellow]"
        )
        return

    console.print(
        f"[green]{len(results)} path(s)[/green] from USER {user} to {object_name}"
    )
    for i, p in enumerate(results, 1):
        console.print(f"  [dim]{i}.[/dim] {p.render()}")


@paths.command("to-object")
@click.argument("object_name")
@click.option("--privilege", default=None)
@click.option(
    "--snapshot",
    "snapshot_path",
    default="snapshot.duckdb",
    show_default=True,
    type=click.Path(),
)
@click.option("--limit", default=100, show_default=True, type=int)
def paths_to_object(
    object_name: str,
    privilege: str | None,
    snapshot_path: str,
    limit: int,
) -> None:
    duck = _open_snapshot(Path(snapshot_path))
    try:
        results = find_paths_to_object(
            duck, object_name, privilege=privilege, limit=limit
        )
    finally:
        duck.close()

    if not results:
        console.print(
            f"[yellow]No paths found to {object_name}"
            f"{' [' + privilege + ']' if privilege else ''}.[/yellow]"
        )
        return

    by_user: dict[str, list] = {}
    for p in results:
        by_user.setdefault(p.source, []).append(p)
    console.print(
        f"[green]{len(by_user)} user(s)[/green] can reach {object_name} "
        f"via {len(results)} path(s)"
    )
    for user, paths_list in by_user.items():
        console.print(f"  [cyan]{user}[/cyan]")
        for p in paths_list:
            console.print(f"    {p.render()}")


if __name__ == "__main__":
    main()
