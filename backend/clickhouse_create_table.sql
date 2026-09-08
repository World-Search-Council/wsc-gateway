-- ClickHouse CREATE TABLE for wsc_analytics_raw
-- Use this in your ClickHouse cloud console or clickhouse-client

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
    bot_name       String DEFAULT '',
    bot_category   String DEFAULT '',   -- 'ai' or 'search'
    bot_type       String DEFAULT ''    -- 'training', 'rag', 'other'
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(toDateTime(timestamp))
ORDER BY (project_id, timestamp, page_uuid)
SETTINGS index_granularity = 8192;

-- Verify
-- SELECT * FROM wsc_analytics_raw LIMIT 5;

-- To add to existing table:
-- ALTER TABLE wsc_analytics_raw ADD COLUMN bot_category String DEFAULT '' AFTER bot_name;
-- ALTER TABLE wsc_analytics_raw ADD COLUMN bot_type String DEFAULT '' AFTER bot_category;

-- =============================================
-- AGGREGATE TABLES
-- =============================================

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

-- To add to existing raw table the bot columns (if not already):
-- ALTER TABLE wsc_analytics_raw ADD COLUMN bot_category String DEFAULT '' AFTER bot_name;
-- ALTER TABLE wsc_analytics_raw ADD COLUMN bot_type String DEFAULT '' AFTER bot_category;

-- Stündliche Traffic für aktuellen Tag (Card 1)
CREATE TABLE IF NOT EXISTS wsc_traffic_hourly (
    project_id     String,
    date           Date,
    hour           UInt8,
    traffic_source LowCardinality(String),
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

-- Assembled Reports table (Worker pipeline)
CREATE TABLE IF NOT EXISTS wsc_assembled_reports (
    project_id String,
    report_type String,
    period_start Date,
    period_end Date,
    generated_at DateTime,
    payload String,
    has_data UInt8
) ENGINE = ReplacingMergeTree(generated_at)
PARTITION BY (project_id, report_type)
ORDER BY (project_id, report_type, period_end);