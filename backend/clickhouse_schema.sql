-- ClickHouse schema for WSC Analytics & Industry Benchmark OLAP Warehouse
-- Run against ClickHouse cluster / instance

CREATE DATABASE IF NOT EXISTS default;
USE default;

-- =============================================
-- 1. RAW TIME-SERIES TABLES
-- =============================================

-- Main raw telemetry events
CREATE TABLE IF NOT EXISTS wsc_analytics_raw
(
    project_id     String,
    timestamp      UInt32,
    session_id     String,
    event_type     String,
    domain_uuid    UUID,
    page_uuid      UUID,
    root_domain    String,
    hostname       String,
    url_path       String,
    query_string   String,
    referrer_url   String,
    geo_country    String,
    geo_region     String,
    geo_city       String,
    device_type    String,
    os_name        String,
    browser_name   String,
    resolution     String,
    language       String,
    custom_data    String,
    -- Bot specific fields
    bot_name       String DEFAULT '',
    bot_category   String DEFAULT '',   -- 'ai' or 'search'
    bot_type       String DEFAULT ''    -- 'training', 'rag', 'other'
)
ENGINE = MergeTree()
ORDER BY (project_id, timestamp, page_uuid)
PARTITION BY toYYYYMM(toDateTime(timestamp))
SETTINGS index_granularity = 8192;

-- Tech Health & Sentinel historical audit records
CREATE TABLE IF NOT EXISTS wsc_tech_health_daily
(
    project_id             String,
    scanned_date           Date,
    score                  UInt8,
    has_spf                UInt8,
    spf_status             LowCardinality(String),
    has_dmarc              UInt8,
    dmarc_policy           LowCardinality(String),
    ssl_valid              UInt8,
    ssl_days_left          UInt16,
    hsts_present           UInt8,
    security_headers_score UInt8
)
ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(scanned_date)
ORDER BY (project_id, scanned_date);

-- PageSpeed & Core Web Vitals audit records
CREATE TABLE IF NOT EXISTS wsc_pagespeed_daily
(
    project_id             String,
    audited_date           Date,
    strategy               LowCardinality(String), -- mobile, desktop
    performance_score      UInt8,
    lcp_ms                 UInt32,
    cls_score              Float32,
    fcp_ms                 UInt32,
    ttfb_ms                UInt32,
    tbt_ms                 UInt32
)
ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(audited_date)
ORDER BY (project_id, audited_date, strategy);

-- =============================================
-- 2. HOURLY & DAILY AGGREGATIONS
-- =============================================

-- Stündliche MV für aktuellen Tag (Card 1 Traffic)
CREATE TABLE IF NOT EXISTS wsc_traffic_hourly (
    project_id     String,
    date           Date,
    hour           UInt8,
    traffic_source LowCardinality(String),  -- search, social, direct, ai, referral, bot
    device_type    LowCardinality(String),
    pageviews      SimpleAggregateFunction(sum, UInt64),
    unique_visitors AggregateFunction(uniq, String)
) ENGINE = AggregatingMergeTree()
PARTITION BY (project_id, date)
ORDER BY (project_id, date, hour, traffic_source, device_type);

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_wsc_traffic_hourly
TO wsc_traffic_hourly AS
SELECT
    project_id,
    toDate(toDateTime(timestamp)) AS date,
    toHour(toDateTime(timestamp)) AS hour,
    CASE
        WHEN bot_name != '' THEN 'bot'
        WHEN JSONExtractString(custom_data, 'channel') != '' THEN JSONExtractString(custom_data, 'channel')
        WHEN referrer_url = '' OR domainWithoutWWW(referrer_url) = root_domain THEN 'direct'
        WHEN multiSearchAny(lower(referrer_url), ['chatgpt','perplexity','gemini','claude','grok','anthropic','deepseek','copilot','you.com','phind','kagi','x.ai','poe.com']) THEN 'ai'
        WHEN multiSearchAny(lower(referrer_url), ['google','bing','duckduckgo','ecosia','yahoo','yandex','baidu','startpage','brave']) THEN 'search'
        WHEN multiSearchAny(lower(referrer_url), ['facebook','instagram','linkedin','twitter','t.co','pinterest','tiktok','reddit','threads','youtube']) THEN 'social'
        ELSE 'referral'
    END AS traffic_source,
    device_type,
    count() AS pageviews,
    uniqState(session_id) AS unique_visitors
FROM wsc_analytics_raw
WHERE bot_name = ''
GROUP BY project_id, date, hour, traffic_source, device_type;

-- Comprehensive Daily Project Overview for Benchmark & Dashboard Calculations
CREATE TABLE IF NOT EXISTS wsc_daily_overview
(
    project_id          String,
    date                Date,
    pageviews           UInt64,
    sessions            UInt64,
    unique_visitors     UInt64,
    bot_hits            UInt64,
    total_events        UInt64
)
ENGINE = SummingMergeTree()
ORDER BY (project_id, date)
PARTITION BY toYYYYMM(date);

-- Tägliche Traffic (7/30 Tage Historie)
CREATE TABLE IF NOT EXISTS wsc_traffic_daily (
    project_id     String,
    date           Date,
    traffic_source LowCardinality(String),
    device_type    LowCardinality(String),
    pageviews      SimpleAggregateFunction(sum, UInt64),
    unique_visitors AggregateFunction(uniq, String)
) ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (project_id, date, traffic_source, device_type);

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_wsc_traffic_daily
TO wsc_traffic_daily AS
SELECT
    project_id,
    toDate(toDateTime(timestamp)) AS date,
    CASE
        WHEN bot_name != '' THEN 'bot'
        WHEN JSONExtractString(custom_data, 'channel') != '' THEN JSONExtractString(custom_data, 'channel')
        WHEN referrer_url = '' OR domainWithoutWWW(referrer_url) = root_domain THEN 'direct'
        WHEN multiSearchAny(lower(referrer_url), ['chatgpt','perplexity','gemini','claude','grok','anthropic','deepseek','copilot','you.com','phind','kagi','x.ai','poe.com']) THEN 'ai'
        WHEN multiSearchAny(lower(referrer_url), ['google','bing','duckduckgo','ecosia','yahoo','yandex','baidu','startpage','brave']) THEN 'search'
        WHEN multiSearchAny(lower(referrer_url), ['facebook','instagram','linkedin','twitter','t.co','pinterest','tiktok','reddit','threads','youtube']) THEN 'social'
        ELSE 'referral'
    END AS traffic_source,
    device_type,
    count() AS pageviews,
    uniqState(session_id) AS unique_visitors
FROM wsc_analytics_raw
WHERE bot_name = ''
GROUP BY project_id, date, traffic_source, device_type;

-- Bot stats (aggregated by bot)
CREATE TABLE IF NOT EXISTS wsc_bot_stats
(
    project_id    String,
    date          Date,
    bot_name      String,
    bot_category  String,
    bot_type      String,
    hits          UInt64
)
ENGINE = SummingMergeTree()
ORDER BY (project_id, date, bot_name, bot_category, bot_type)
PARTITION BY toYYYYMM(date);

-- Top pages (daily page counts for top analysis)
CREATE TABLE IF NOT EXISTS wsc_top_pages
(
    project_id    String,
    date          Date,
    url_path      String,
    views         UInt64
)
ENGINE = SummingMergeTree()
ORDER BY (project_id, date, url_path)
PARTITION BY toYYYYMM(date);

-- Assembled Reports Cache (Card 1, Card 2, Card 3, Engagement, Outbound, E-Commerce)
CREATE TABLE IF NOT EXISTS wsc_assembled_reports (
    project_id   String,
    report_type  String,   -- e.g. "card1_traffic", "card2_insights", "card3_bots", "card_engagement", "card_outbound", "card_ecommerce"
    period_start Date,
    period_end   Date,
    generated_at DateTime,
    payload      String,   -- Canonical JSON
    has_data     UInt8
) ENGINE = ReplacingMergeTree(generated_at)
PARTITION BY (project_id, report_type)
ORDER BY (project_id, report_type, period_end);

-- =============================================
-- 3. ENGAGEMENT, OUTBOUND & E-COMMERCE AGGREGATIONS
-- =============================================

-- Engagement Aggregations (TTFI, Focus Time, Deep Read Rate per URL)
CREATE TABLE IF NOT EXISTS wsc_engagement_daily (
    project_id         String,
    date               Date,
    url_path           String,
    total_events       SimpleAggregateFunction(sum, UInt64),
    ttfi_sum_ms        SimpleAggregateFunction(sum, UInt64),
    ttfi_count         SimpleAggregateFunction(sum, UInt64),
    active_time_sum_ms SimpleAggregateFunction(sum, UInt64),
    active_time_count  SimpleAggregateFunction(sum, UInt64),
    duration_sum_ms    SimpleAggregateFunction(sum, UInt64),
    max_scroll_depth   SimpleAggregateFunction(max, UInt8),
    deep_scroll_count  SimpleAggregateFunction(sum, UInt64),
    outbound_clicks    SimpleAggregateFunction(sum, UInt64)
) ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (project_id, date, url_path);

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_wsc_engagement_daily
TO wsc_engagement_daily AS
SELECT
    project_id,
    toDate(toDateTime(timestamp)) AS date,
    url_path,
    count() AS total_events,
    sum(if(event_type = 'time_to_first_interaction' OR event_type = 'time_to_first_scroll' OR event_type = 'time_to_first_click', JSONExtractUInt(custom_data, 'time_ms'), 0)) AS ttfi_sum_ms,
    countIf(event_type = 'time_to_first_interaction' OR event_type = 'time_to_first_scroll' OR event_type = 'time_to_first_click') AS ttfi_count,
    sum(if(event_type = 'time_on_page', JSONExtractUInt(custom_data, 'active_ms'), 0)) AS active_time_sum_ms,
    countIf(event_type = 'time_on_page') AS active_time_count,
    sum(if(event_type = 'time_on_page', JSONExtractUInt(custom_data, 'duration_ms'), 0)) AS duration_sum_ms,
    max(if(event_type = 'scroll_depth', JSONExtractUInt(custom_data, 'percent'), 0)) AS max_scroll_depth,
    countIf(event_type = 'scroll_depth' AND JSONExtractUInt(custom_data, 'percent') >= 75) AS deep_scroll_count,
    countIf(event_type = 'outbound_click' OR custom_data LIKE '%Outbound:%') AS outbound_clicks
FROM wsc_analytics_raw
WHERE bot_name = ''
GROUP BY project_id, date, url_path;

-- Outbound Link Routing Aggregations
CREATE TABLE IF NOT EXISTS wsc_outbound_daily (
    project_id    String,
    date          Date,
    target_host   String,
    target_url    String,
    source_url    String,
    category      LowCardinality(String),
    clicks_count  SimpleAggregateFunction(sum, UInt64),
    last_clicked  SimpleAggregateFunction(max, UInt32)
) ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (project_id, date, target_host, target_url, source_url);

-- E-Commerce Reality & Conversion Funnel
CREATE TABLE IF NOT EXISTS wsc_ecommerce_daily (
    project_id          String,
    date                Date,
    product_views       SimpleAggregateFunction(sum, UInt64),
    add_to_cart_count   SimpleAggregateFunction(sum, UInt64),
    initiate_checkout   SimpleAggregateFunction(sum, UInt64),
    purchases_count     SimpleAggregateFunction(sum, UInt64),
    revenue             SimpleAggregateFunction(sum, Float64),
    orders_with_coupon  SimpleAggregateFunction(sum, UInt64),
    coupon_discount_sum SimpleAggregateFunction(sum, Float64)
) ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (project_id, date);