#!/usr/bin/env python3
"""
rebuild_project_history.py - WSC Gateway 2.0 ClickHouse History Rebuild & Consolidation Tool

Consolidates fragmented historical tracking data and aggregated metrics across multiple
project IDs (e.g., after reconnects) into a single active canonical project ID in ClickHouse,
merges all hourly/daily tables, and regenerates multi-period report cards.

Usage:
    python scripts/rebuild_project_history.py --target-project proj_b003c85753a2422d --domain searchneedslove.com
"""

import os
import sys
import time
import json
import argparse
import datetime
from typing import List, Dict, Any
import requests

# Ensure worker/ and gateway/ modules are discoverable
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "worker"))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "gateway"))

import clickhouse_connect


def get_credentials():
    host = os.getenv("CLICKHOUSE_HOST", "x1ntpfvvki.europe-west4.gcp.clickhouse.cloud")
    port = int(os.getenv("CLICKHOUSE_PORT", "8443"))
    user = os.getenv("CLICKHOUSE_USER", "default")
    password = os.getenv("CLICKHOUSE_PASS", "")

    if not password:
        env_file = os.path.join(PROJECT_ROOT, ".env")
        if os.path.isfile(env_file):
            with open(env_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("CLICKHOUSE_PASS="):
                        password = line.split("=", 1)[1].strip().strip('"').strip("'")
                    elif line.startswith("CLICKHOUSE_HOST="):
                        host = line.split("=", 1)[1].strip().strip('"').strip("'")
                    elif line.startswith("CLICKHOUSE_PORT="):
                        port = int(line.split("=", 1)[1].strip().strip('"').strip("'"))
                    elif line.startswith("CLICKHOUSE_USER="):
                        user = line.split("=", 1)[1].strip().strip('"').strip("'")

    return host, port, user, password


def exec_sql_post(query: str, host: str, port: int, user: str, password: str) -> str:
    """Execute SQL query via ClickHouse HTTP POST."""
    url = f"https://{host}:{port}/"
    resp = requests.post(
        url,
        params={"user": user, "password": password},
        data=query.strip().encode("utf-8"),
        headers={"Content-Type": "text/plain; charset=utf-8"},
        timeout=120
    )
    if resp.status_code != 200:
        raise RuntimeError(f"ClickHouse HTTP {resp.status_code}: {resp.text}")
    return resp.text


def get_clickhouse_client():
    host, port, user, password = get_credentials()
    print(f"🔌 Connecting to ClickHouse Cloud at {host}:{port} (User: {user})...")
    client = clickhouse_connect.get_client(
        host=host,
        port=port,
        username=user,
        password=password,
        secure=True,
        connect_timeout=30,
        send_receive_timeout=120
    )
    client.command("SELECT 1")
    print("✅ ClickHouse connected successfully.")
    return client


def wait_for_mutations(client, table_name: str, max_wait_sec: int = 180):
    """Wait for all mutations on a given table to complete."""
    print(f"⏳ Waiting for active ClickHouse mutations on table '{table_name}'...")
    start_time = time.time()
    while time.time() - start_time < max_wait_sec:
        rows = client.query(f"SELECT mutation_id, command, is_done FROM system.mutations WHERE table = '{table_name}' AND is_done = 0").result_rows
        if not rows:
            print(f"✅ All mutations on '{table_name}' completed.")
            return True
        print(f"   ... {len(rows)} mutation(s) still in progress. Waiting 3s...")
        time.sleep(3)
    print(f"⚠️ Warning: Mutations on '{table_name}' did not complete within {max_wait_sec}s.")
    return False


def run_migration(target_project: str, domain: str, source_projects: List[str], dry_run: bool = False):
    host, port, user, password = get_credentials()
    client = get_clickhouse_client()

    old_source_ids = [s.strip() for s in source_projects if s.strip() and s.strip() != target_project]
    old_source_ids_tuple_str = "(" + ", ".join([f"'{s}'" for s in old_source_ids]) + ")"

    print("\n" + "="*70)
    print("📊 PRE-MIGRATION STATE ANALYSIS")
    print("="*70)
    print(f"Target Project ID : {target_project}")
    print(f"Target Domain     : {domain}")
    print(f"Source Projects   : {old_source_ids}")

    print("\nProject rows in aggregate tables before migration:")
    tables_to_check = [
        "wsc_daily_overview",
        "wsc_traffic_hourly",
        "wsc_traffic_daily",
        "wsc_engagement_daily",
        "wsc_bot_stats",
        "wsc_top_pages",
        "wsc_assembled_reports"
    ]
    for tbl in tables_to_check:
        try:
            r = client.query(f"SELECT project_id, count(), min(date) FROM {tbl} GROUP BY project_id, date ORDER BY date LIMIT 5").result_rows
            print(f"  {tbl}: sample rows -> {r}")
        except Exception:
            try:
                r = client.query(f"SELECT project_id, count() FROM {tbl} GROUP BY project_id").result_rows
                print(f"  {tbl}: {r}")
            except Exception as e:
                print(f"  {tbl}: {e}")

    if dry_run:
        print("\n🔍 DRY-RUN MODE: No changes executed.")
        return

    print("\n" + "="*70)
    print("🚀 STEP 1: CONSOLIDATING AGGREGATED HISTORIES TO CANONICAL PROJECT")
    print("="*70)

    if not old_source_ids:
        print("No old source project IDs specified.")
        return

    # 1.1 wsc_daily_overview
    print("  Consolidating wsc_daily_overview...")
    exec_sql_post(f"""
        INSERT INTO wsc_daily_overview (project_id, date, pageviews, sessions, unique_visitors, bot_hits, total_events)
        SELECT '{target_project}' AS project_id, date, pageviews, sessions, unique_visitors, bot_hits, total_events
        FROM wsc_daily_overview
        WHERE project_id IN {old_source_ids_tuple_str}
    """, host, port, user, password)

    # 1.2 wsc_traffic_hourly
    print("  Consolidating wsc_traffic_hourly...")
    exec_sql_post(f"""
        INSERT INTO wsc_traffic_hourly (project_id, date, hour, traffic_source, device_type, pageviews, unique_visitors)
        SELECT '{target_project}' AS project_id, date, hour, traffic_source, device_type, pageviews, unique_visitors
        FROM wsc_traffic_hourly
        WHERE project_id IN {old_source_ids_tuple_str}
    """, host, port, user, password)

    # 1.3 wsc_traffic_daily
    print("  Consolidating wsc_traffic_daily...")
    exec_sql_post(f"""
        INSERT INTO wsc_traffic_daily (project_id, date, traffic_source, device_type, pageviews, unique_visitors)
        SELECT '{target_project}' AS project_id, date, traffic_source, device_type, pageviews, unique_visitors
        FROM wsc_traffic_daily
        WHERE project_id IN {old_source_ids_tuple_str}
    """, host, port, user, password)

    # 1.4 wsc_bot_stats
    print("  Consolidating wsc_bot_stats...")
    exec_sql_post(f"""
        INSERT INTO wsc_bot_stats (project_id, date, bot_name, bot_category, bot_type, hits)
        SELECT '{target_project}' AS project_id, date, bot_name, bot_category, bot_type, hits
        FROM wsc_bot_stats
        WHERE project_id IN {old_source_ids_tuple_str}
    """, host, port, user, password)

    # 1.5 wsc_top_pages
    print("  Consolidating wsc_top_pages...")
    exec_sql_post(f"""
        INSERT INTO wsc_top_pages (project_id, date, url_path, views)
        SELECT '{target_project}' AS project_id, date, url_path, views
        FROM wsc_top_pages
        WHERE project_id IN {old_source_ids_tuple_str}
    """, host, port, user, password)

    # 1.6 wsc_engagement_daily
    print("  Consolidating wsc_engagement_daily...")
    try:
        exec_sql_post(f"""
            INSERT INTO wsc_engagement_daily (project_id, date, url_path, total_events, ttfi_sum_ms, ttfi_count, active_time_sum_ms, active_time_count, duration_sum_ms, max_scroll_depth, deep_scroll_count, outbound_clicks)
            SELECT '{target_project}' AS project_id, date, url_path, total_events, ttfi_sum_ms, ttfi_count, active_time_sum_ms, active_time_count, duration_sum_ms, max_scroll_depth, deep_scroll_count, outbound_clicks
            FROM wsc_engagement_daily
            WHERE project_id IN {old_source_ids_tuple_str}
        """, host, port, user, password)
    except Exception as e:
        print(f"  Note on wsc_engagement_daily: {e}")

    # 1.7 wsc_assembled_reports (past snapshots)
    print("  Consolidating wsc_assembled_reports...")
    exec_sql_post(f"""
        INSERT INTO wsc_assembled_reports (project_id, report_type, period_start, period_end, generated_at, payload, has_data)
        SELECT '{target_project}' AS project_id, report_type, period_start, period_end, generated_at, payload, has_data
        FROM wsc_assembled_reports
        WHERE project_id IN {old_source_ids_tuple_str}
    """, host, port, user, password)

    print("\n" + "="*70)
    print("🧹 STEP 2: PURGING OLD PROJECT ENTITIES FROM ALL TABLES")
    print("="*70)

    tables_to_purge = [
        "wsc_daily_overview",
        "wsc_traffic_hourly",
        "wsc_traffic_daily",
        "wsc_engagement_daily",
        "wsc_bot_stats",
        "wsc_top_pages",
        "wsc_assembled_reports"
    ]

    for table in tables_to_purge:
        try:
            del_sql = f"ALTER TABLE {table} DELETE WHERE project_id IN {old_source_ids_tuple_str}"
            client.command(del_sql)
            print(f"  Purged old rows from {table}")
        except Exception as e:
            print(f"  Note on {table}: {e}")

    for table in tables_to_purge:
        try:
            wait_for_mutations(client, table, max_wait_sec=30)
        except Exception:
            pass

    print("\n" + "="*70)
    print("🎁 STEP 3: RE-ASSEMBLING FRESH DASHBOARD CARDS FOR TARGET PROJECT")
    print("="*70)

    import asyncio
    from common import (
        assemble_card1_traffic_report,
        assemble_card2_insights_report,
        assemble_card3_bots_report,
        assemble_card_engagement_report,
        assemble_card_outbound_report,
        assemble_card_ecommerce_report,
    )

    async def assemble_and_store_reports():
        import common
        common.ch_client = client

        now = datetime.datetime.utcnow()
        today = now.date()
        stored_count = 0

        # Card 1 Traffic
        print("  Generating Card 1 (Traffic)...")
        c1 = await assemble_card1_traffic_report(target_project)
        if c1:
            exec_sql_post(f"""
                INSERT INTO wsc_assembled_reports (project_id, report_type, period_start, period_end, generated_at, payload, has_data)
                VALUES ('{target_project}', 'card1_traffic', '{today - datetime.timedelta(days=30)}', '{today}', '{now.strftime("%Y-%m-%d %H:%M:%S")}', '{json.dumps(c1).replace("'", "''")}', 1)
            """, host, port, user, password)
            stored_count += 1

        # Card 2 Insights
        print("  Generating Card 2 (Insights)...")
        c2 = await assemble_card2_insights_report(target_project)
        if c2:
            exec_sql_post(f"""
                INSERT INTO wsc_assembled_reports (project_id, report_type, period_start, period_end, generated_at, payload, has_data)
                VALUES ('{target_project}', 'card2_insights', '{today - datetime.timedelta(days=30)}', '{today}', '{now.strftime("%Y-%m-%d %H:%M:%S")}', '{json.dumps(c2).replace("'", "''")}', 1)
            """, host, port, user, password)
            stored_count += 1

        # Card 3 Bots
        print("  Generating Card 3 (Bots)...")
        c3 = await assemble_card3_bots_report(target_project)
        if c3:
            exec_sql_post(f"""
                INSERT INTO wsc_assembled_reports (project_id, report_type, period_start, period_end, generated_at, payload, has_data)
                VALUES ('{target_project}', 'card3_bots', '{today - datetime.timedelta(days=30)}', '{today}', '{now.strftime("%Y-%m-%d %H:%M:%S")}', '{json.dumps(c3).replace("'", "''")}', 1)
            """, host, port, user, password)
            stored_count += 1

        # Engagement
        print("  Generating Card Engagement...")
        c_eng = await assemble_card_engagement_report(target_project)
        if c_eng:
            exec_sql_post(f"""
                INSERT INTO wsc_assembled_reports (project_id, report_type, period_start, period_end, generated_at, payload, has_data)
                VALUES ('{target_project}', 'card_engagement', '{today - datetime.timedelta(days=30)}', '{today}', '{now.strftime("%Y-%m-%d %H:%M:%S")}', '{json.dumps(c_eng).replace("'", "''")}', 1)
            """, host, port, user, password)
            stored_count += 1

        # Outbound
        print("  Generating Card Outbound...")
        c_out = await assemble_card_outbound_report(target_project)
        if c_out:
            exec_sql_post(f"""
                INSERT INTO wsc_assembled_reports (project_id, report_type, period_start, period_end, generated_at, payload, has_data)
                VALUES ('{target_project}', 'card_outbound', '{today - datetime.timedelta(days=30)}', '{today}', '{now.strftime("%Y-%m-%d %H:%M:%S")}', '{json.dumps(c_out).replace("'", "''")}', 1)
            """, host, port, user, password)
            stored_count += 1

        # E-Commerce
        print("  Generating Card E-Commerce...")
        c_ecom = await assemble_card_ecommerce_report(target_project)
        if c_ecom:
            exec_sql_post(f"""
                INSERT INTO wsc_assembled_reports (project_id, report_type, period_start, period_end, generated_at, payload, has_data)
                VALUES ('{target_project}', 'card_ecommerce', '{today - datetime.timedelta(days=30)}', '{today}', '{now.strftime("%Y-%m-%d %H:%M:%S")}', '{json.dumps(c_ecom).replace("'", "''")}', 1)
            """, host, port, user, password)
            stored_count += 1

        print(f"✅ Generated & stored {stored_count} fresh assembled report cards.")

    asyncio.run(assemble_and_store_reports())

    print("\n" + "="*70)
    print("📈 POST-MIGRATION VERIFICATION & METRICS SUMMARY")
    print("="*70)

    post_daily = client.query(f"SELECT count(), sum(pageviews), sum(unique_visitors), sum(bot_hits), min(date), max(date) FROM wsc_daily_overview WHERE project_id = '{target_project}'").result_rows[0]
    post_hourly = client.query(f"SELECT count(), sum(pageviews) FROM wsc_traffic_hourly WHERE project_id = '{target_project}'").result_rows[0]
    post_bots = client.query(f"SELECT count(), sum(hits) FROM wsc_bot_stats WHERE project_id = '{target_project}'").result_rows[0]
    post_top_pages = client.query(f"SELECT count(), sum(views) FROM wsc_top_pages WHERE project_id = '{target_project}'").result_rows[0]
    post_reports = client.query(f"SELECT count() FROM wsc_assembled_reports WHERE project_id = '{target_project}'").result_rows[0]

    print(f"🎯 Target Project ID              : {target_project}")
    print(f"📅 Daily Overview Records         : {post_daily[0]} days ({post_daily[4]} to {post_daily[5]})")
    print(f"   - Total Pageviews (Daily)      : {post_daily[1]:,}")
    print(f"   - Total Unique Visitors Sum    : {post_daily[2]:,}")
    print(f"   - Total Bot Hits               : {post_daily[3]:,}")
    print(f"⏱️ Hourly Traffic Aggregations    : {post_hourly[0]} rows ({post_hourly[1]:,} pageviews)")
    print(f"🤖 Bot Stats Aggregations         : {post_bots[0]} bot classification rows ({post_bots[1]:,} hits)")
    print(f"📄 Top Pages Records              : {post_top_pages[0]} pages tracked ({post_top_pages[1]:,} views)")
    print(f"📑 Assembled Reports Ready        : {post_reports[0]} reports")
    print("="*70)
    print("🎉 HISTORY REBUILD & UNIFICATION COMPLETED SUCCESSFULLY!")
    print("="*70)


def main():
    parser = argparse.ArgumentParser(description="Consolidate WSC project history in ClickHouse")
    parser.add_argument("--target-project", default="proj_b003c85753a2422d", help="Active project ID")
    parser.add_argument("--domain", default="searchneedslove.com", help="Domain to unify")
    parser.add_argument("--source-projects", default="proj_cef36dd667c34396,proj_2606cb2cc8ec41b7", help="Comma-separated previous project IDs")
    parser.add_argument("--dry-run", action="store_true", help="Inspect without modifying data")
    args = parser.parse_args()

    sources = [s.strip() for s in args.source_projects.split(",") if s.strip()]
    run_migration(
        target_project=args.target_project,
        domain=args.domain,
        source_projects=sources,
        dry_run=args.dry_run
    )


if __name__ == "__main__":
    main()
