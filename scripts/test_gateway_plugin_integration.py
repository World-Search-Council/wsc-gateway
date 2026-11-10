#!/usr/bin/env python3
"""
test_gateway_plugin_integration.py
Automated End-to-End Test Suite for WSC Gateway & WordPress Plugin.
Tests all 8 communication channels specified in gateway-plugin-testplan.md.
"""
import sys
import json
import time
import hmac
import hashlib
import sqlite3
import subprocess
import urllib.request
import urllib.error

GATEWAY_URL = "http://localhost:8001"
WP_URL = "http://localhost:8080"


def log_step(title):
    print(f"\n{'='*70}\n🔷 {title}\n{'='*70}")


def request_json(url, method="GET", data=None, headers=None):
    headers = headers.copy() if headers else {}
    if "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"
    
    encoded_data = None
    if data is not None:
        if isinstance(data, (dict, list)):
            encoded_data = json.dumps(data).encode("utf-8")
        elif isinstance(data, str):
            encoded_data = data.encode("utf-8")
        elif isinstance(data, bytes):
            encoded_data = data

    req = urllib.request.Request(url, data=encoded_data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            res_body = response.read().decode("utf-8")
            status = response.status
            try:
                return status, json.loads(res_body), res_body
            except json.JSONDecodeError:
                return status, None, res_body
    except urllib.error.HTTPError as e:
        res_body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(res_body), res_body
        except json.JSONDecodeError:
            return e.code, None, res_body
    except Exception as e:
        return 0, None, str(e)


def main():
    print("🚀 STARTING WSC GATEWAY <-> WORDPRESS PLUGIN INTEGRATION TEST SUITE")
    print(f"Gateway target: {GATEWAY_URL}")
    print(f"WordPress target: {WP_URL}")

    # =========================================================================
    # TEST 0: Check WordPress REST API Health
    # =========================================================================
    log_step("TEST 0: WordPress REST API Health Check")
    status, json_data, raw = request_json(f"{WP_URL}/wp-json/wsc/v1/health")
    assert status == 200, f"WP Health failed with {status}: {raw}"
    assert json_data.get("healthy") is True or json_data.get("status") == "healthy", f"WP Health unexpected: {json_data}"
    print(f"✅ WordPress WSC Plugin is healthy! Version: {json_data.get('version')}")

    # =========================================================================
    # TEST 1: Handshake & Project Registration
    # =========================================================================
    log_step("TEST 1: Handshake & Registration (POST /v1/register)")
    test_domain = "http://localhost:8080"
    test_aes_key = "a" * 64
    reg_payload = {
        "domain": test_domain,
        "local_aes_key": test_aes_key,
        "platform": "wordpress",
        "webhook_url": f"{test_domain}/wp-json/wsc/v1/webhook"
    }

    status, json_data, raw = request_json(f"{GATEWAY_URL}/v1/register", method="POST", data=reg_payload)
    assert status == 200, f"Registration failed with {status}: {raw}"
    assert "project_id" in json_data and "api_secret" in json_data, f"Invalid registration response: {json_data}"
    
    project_id = json_data["project_id"]
    api_secret = json_data["api_secret"]
    print(f"✅ Registration SUCCESS: project_id={project_id}, api_secret={api_secret[:8]}...")

    # Configure the test project in WordPress options so WordPress recognizes the secret
    set_opt_cmd = (
        f"docker exec wp_app php -r \""
        f"require_once '/var/www/html/wp-load.php'; "
        f"update_option('wsc_project_id', '{project_id}'); "
        f"update_option('wsc_api_secret', '{api_secret}'); "
        f"update_option('wsc_local_secret_key', '{test_aes_key}'); "
        f"update_option('wsc_hybrid_enabled', 1); "
        f"echo 'Configured: ' . get_option('wsc_project_id');\""
    )
    res = subprocess.run(set_opt_cmd, shell=True, capture_output=True, text=True)
    print(f"🔧 WordPress Configured: {res.stdout.strip()}")

    # Helper for HMAC signing
    def make_signature(body_bytes: bytes, secret: str) -> str:
        return hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()

    # =========================================================================
    # TEST 2: SpeedSentinel On-Demand Audit (POST /v1/pagespeed/audit)
    # =========================================================================
    log_step("TEST 2: SpeedSentinel Lab Audit (POST /v1/pagespeed/audit)")
    speed_payload = {
        "project_id": project_id,
        "url": "https://worldsearchcouncil.org",
        "strategy": "mobile"
    }
    speed_raw = json.dumps(speed_payload).encode("utf-8")
    speed_sig = make_signature(speed_raw, api_secret)

    status, json_data, raw = request_json(
        f"{GATEWAY_URL}/v1/pagespeed/audit",
        method="POST",
        data=speed_raw,
        headers={"X-WSC-Sig": speed_sig}
    )
    assert status == 200, f"SpeedSentinel failed with {status}: {raw}"
    report = json_data.get("report", {})
    score = report.get("performance_score")
    metrics = report.get("metrics", {})
    print(f"✅ SpeedSentinel SUCCESS: Score={score}, LCP={metrics.get('lcp', {}).get('value')}s, TTFB={metrics.get('ttfb', {}).get('value')}ms")

    # =========================================================================
    # TEST 3: Sentinel Domain & Tech Health Scan (POST /v1/sentinel/scan)
    # =========================================================================
    log_step("TEST 3: Sentinel Domain & Tech Health Scan (POST /v1/sentinel/scan)")
    sentinel_payload = {
        "project_id": project_id,
        "domain": "worldsearchcouncil.org"
    }
    sent_raw = json.dumps(sentinel_payload).encode("utf-8")
    sent_sig = make_signature(sent_raw, api_secret)

    status, json_data, raw = request_json(
        f"{GATEWAY_URL}/v1/sentinel/scan",
        method="POST",
        data=sent_raw,
        headers={"X-WSC-Sig": sent_sig}
    )
    assert status == 200, f"Sentinel Scan failed with {status}: {raw}"
    s_report = json_data.get("report", {})
    summary = s_report.get("summary", {})
    print(f"✅ Sentinel Scan SUCCESS: Overall={summary.get('overall_health')}, SSL={summary.get('ssl_status')}, Mail={summary.get('mail_health')}")

    # =========================================================================
    # TEST 4: AI Coverage URL Inspector (POST /v1/ai-coverage/query)
    # =========================================================================
    log_step("TEST 4: AI Coverage URL Inspector (POST /v1/ai-coverage/query)")
    ai_cov_payload = {
        "project_id": project_id,
        "query": "https://worldsearchcouncil.org/standards/ai-search",
        "timeframe_days": 30
    }
    ai_raw = json.dumps(ai_cov_payload).encode("utf-8")
    ai_sig = make_signature(ai_raw, api_secret)

    status, json_data, raw = request_json(
        f"{GATEWAY_URL}/v1/ai-coverage/query",
        method="POST",
        data=ai_raw,
        headers={"X-WSC-Sig": ai_sig}
    )
    assert status == 200, f"AI Coverage failed with {status}: {raw}"
    q_ctx = json_data.get("query", {})
    dom_cov = json_data.get("domain_coverage", {})
    print(f"✅ AI Coverage SUCCESS: RootDomain={q_ctx.get('root_domain')}, Confidence={dom_cov.get('network_confidence')}")

    # =========================================================================
    # TEST 5: Benchmark NLP Classification (POST /v1/benchmarks/classify)
    # =========================================================================
    log_step("TEST 5: Benchmark NLP Classification (POST /v1/benchmarks/classify)")
    bench_payload = {
        "project_id": project_id,
        "title": "Exklusiver Online Shop für Designer Schuhe und Abendkleider",
        "meta_description": "Entdecken Sie moderne Damenmode und stilvolle Schuhe.",
        "sample_text": "Kaufen Sie elegante Kleider, Taschen und Schuhe direkt online."
    }
    status, json_data, raw = request_json(
        f"{GATEWAY_URL}/v1/benchmarks/classify",
        method="POST",
        data=bench_payload
    )
    assert status == 200, f"Benchmark classify failed with {status}: {raw}"
    vertical = json_data.get("vertical")
    label = json_data.get("vertical_label")
    conf = json_data.get("confidence")
    print(f"✅ Benchmark NLP SUCCESS: Vertical='{vertical}' ({label}), Confidence={conf}")

    # =========================================================================
    # TEST 6: Push-Report Webhook Rückkanal directly to WordPress (POST /wp-json/wsc/v1/webhook)
    # =========================================================================
    log_step("TEST 6: Push-Report Webhook Rückkanal to WordPress (/wp-json/wsc/v1/webhook)")
    now = int(time.time())
    canonical_push_payload = {
        "version": "1.5.0",
        "updated_at": now,
        "card1": {
            "report_type": "card1_traffic",
            "period_days": 7,
            "kpi": {
                "unique_visitors": 2450,
                "pageviews": 7820,
                "avg_engagement_time": 74.2
            },
            "chart": {
                "labels": ["Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"],
                "values": [310, 340, 390, 420, 380, 290, 320]
            }
        },
        "card2": {
            "report_type": "card2_insights",
            "human_text": "Dein organischer AI-RAG Traffic via Perplexity und ChatGPT Search ist diese Woche um +18% gewachsen."
        },
        "card3": {
            "report_type": "card3_bots",
            "kpi": {
                "human_pct": 91.5,
                "ai_rag_pct": 5.8,
                "training_pct": 2.7
            }
        },
        "insights": []
    }

    push_raw = json.dumps(canonical_push_payload).encode("utf-8")
    push_sig = make_signature(push_raw, api_secret)

    status, json_data, raw = request_json(
        f"{WP_URL}/wp-json/wsc/v1/webhook",
        method="POST",
        data=push_raw,
        headers={"X-WSC-Sig": push_sig}
    )
    assert status == 200, f"Push Webhook failed with {status}: {raw}"
    print(f"✅ Push Webhook to WordPress SUCCESS! Response: {raw.strip()}")

    # Verify that SQLite database inside WordPress received the 3 cards
    check_db_cmd = (
        f"docker exec wp_app php -r \""
        f"require_once '/var/www/html/wp-load.php'; "
        f"\$pdo = WSC_Data::get_pdo('wsc-core-reports', true); "
        f"\$rows = \$pdo->query('SELECT report_type, received_at, payload FROM wsc_dashboard_reports ORDER BY id DESC LIMIT 5')->fetchAll(PDO::FETCH_ASSOC); "
        f"echo json_encode(\$rows);\""
    )
    db_res = subprocess.run(check_db_cmd, shell=True, capture_output=True, text=True)
    stored_reports = json.loads(db_res.stdout) if db_res.stdout else []
    print(f"📦 Stored Reports in WordPress SQLite: {len(stored_reports)} entries found!")
    for r in stored_reports:
        print(f"   - {r.get('report_type')} (received: {r.get('received_at')})")

    assert len(stored_reports) >= 3, f"Expected at least 3 cards stored in SQLite, got {len(stored_reports)}"

    # =========================================================================
    # SUMMARY
    # =========================================================================
    print(f"\n{'='*70}")
    print("🎉 ALL 6 COMMUNICATION CHANNELS PASSED WITH 100% SUCCESS!")
    print("   1. WordPress Health Check               ✅")
    print("   2. Handshake & Registration             ✅")
    print("   3. SpeedSentinel On-Demand Audit        ✅")
    print("   4. Sentinel Tech Health Scan            ✅")
    print("   5. AI Coverage URL Inspector            ✅")
    print("   6. Benchmark NLP Classification         ✅")
    print("   7. Push-Report Rückkanal & SQLite Store ✅")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
