// =============================================================================
// 04_ato.cypher
// Account Takeover Domain — Node properties and relationship patterns
// Detection: device fingerprint change, IP geo anomaly, behavioral deviation
// Stream-written: Session, DeviceFingerprint, IPAddress
// Batch-written: BehavioralBaseline, DEVIATES_FROM edges, FraudAlert
// =============================================================================


// -----------------------------------------------------------------------------
// NODE: Session
// Login or activity session — core ATO signal unit
// -----------------------------------------------------------------------------
MERGE (s:Session {session_id: $session_id})
ON CREATE SET
    s.timestamp         = $timestamp,           // session start — indexed
    s.ended_at          = $ended_at,
    s.duration_seconds  = $duration_seconds,
    s.event_type        = $event_type,          // login | password_change | tx_initiation | profile_update
    s.status            = $status,              // success | failed | blocked
    s.failure_count     = $failure_count,       // login failures before this session
    // geo — Option B: properties on node
    s.country_code      = $country_code,
    s.city              = $city,
    s.lat               = $lat,
    s.lon               = $lon,
    s.timezone          = $timezone,
    // behavioral features — stream computed
    s.typing_cadence    = $typing_cadence,      // avg ms between keystrokes
    s.mouse_dynamics    = $mouse_dynamics,      // normalized movement pattern hash
    s.is_headless       = $is_headless,         // boolean — headless browser flag
    s.is_emulator       = $is_emulator;         // boolean — device emulator flag


// -----------------------------------------------------------------------------
// NODE: DeviceFingerprint
// Canonical device identity — shared across CC and ATO domains
// -----------------------------------------------------------------------------
MERGE (d:DeviceFingerprint {device_id: $device_id})
ON CREATE SET
    d.user_agent        = $user_agent,
    d.os                = $os,
    d.os_version        = $os_version,
    d.browser           = $browser,
    d.browser_version   = $browser_version,
    d.screen_res        = $screen_res,
    d.timezone          = $timezone,
    d.language          = $language,
    d.plugins_hash      = $plugins_hash,        // hash of installed browser plugins
    d.canvas_hash       = $canvas_hash,         // canvas fingerprint hash
    d.webgl_hash        = $webgl_hash,          // WebGL fingerprint hash
    d.first_seen        = $timestamp,
    d.last_seen         = $timestamp,
    d.is_known_bot      = $is_known_bot         // boolean
ON MATCH SET
    d.last_seen         = $timestamp;


// -----------------------------------------------------------------------------
// NODE: IPAddress
// Shared across CC and ATO domains — geo as properties
// -----------------------------------------------------------------------------
MERGE (ip:IPAddress {address: $address})
ON CREATE SET
    ip.country_code     = $country_code,
    ip.city             = $city,
    ip.lat              = $lat,
    ip.lon              = $lon,
    ip.timezone         = $timezone,
    ip.asn              = $asn,                 // autonomous system number
    ip.isp              = $isp,
    ip.is_vpn           = $is_vpn,
    ip.is_tor           = $is_tor,
    ip.is_proxy         = $is_proxy,
    ip.is_datacenter    = $is_datacenter,       // boolean — cloud/datacenter IP
    ip.risk_score       = $risk_score,          // 0.0-1.0 — from IP reputation service
    ip.first_seen       = $timestamp,
    ip.last_seen        = $timestamp
ON MATCH SET
    ip.last_seen        = $timestamp,
    ip.is_vpn           = $is_vpn,
    ip.is_tor           = $is_tor,
    ip.risk_score       = $risk_score;


// -----------------------------------------------------------------------------
// NODE: BehavioralBaseline
// Per-account behavioral fingerprint — batch-written, updated periodically
// Represents normal behavior for this account — deviations signal ATO
// -----------------------------------------------------------------------------
MERGE (b:BehavioralBaseline {baseline_id: $baseline_id})
ON CREATE SET
    b.account_id        = $account_id,
    b.account_type      = $account_type,        // CreditAccount | BankAccount
    b.computed_at       = $computed_at,
    b.window_days       = $window_days,         // lookback window used — typically 90 days
    // device patterns
    b.known_device_ids  = $known_device_ids,    // list of trusted device_ids
    b.primary_os        = $primary_os,
    b.primary_browser   = $primary_browser,
    // geo patterns
    b.known_countries   = $known_countries,     // list of country_codes seen historically
    b.known_cities      = $known_cities,
    b.primary_timezone  = $primary_timezone,
    // time patterns
    b.active_hours      = $active_hours,        // list of typical active hours [9,10,11...]
    b.active_days       = $active_days,         // list of typical active days [1,2,3,4,5]
    // transaction patterns
    b.avg_tx_amount     = $avg_tx_amount,
    b.max_tx_amount     = $max_tx_amount,
    b.avg_tx_per_day    = $avg_tx_per_day,
    b.typical_merchants = $typical_merchants,   // list of frequent merchant_ids
    b.typical_mccs      = $typical_mccs         // list of frequent MCCs
ON MATCH SET
    b.computed_at       = $computed_at,
    b.known_device_ids  = $known_device_ids,
    b.known_countries   = $known_countries,
    b.avg_tx_amount     = $avg_tx_amount,
    b.avg_tx_per_day    = $avg_tx_per_day;


// -----------------------------------------------------------------------------
// RELATIONSHIPS — ATO Domain
// -----------------------------------------------------------------------------

// Account had a Session
MATCH (a {account_id: $account_id})
MATCH (s:Session {session_id: $session_id})
MERGE (a)-[r:HAD_SESSION]->(s)
ON CREATE SET
    r.created_at = $timestamp;

// Session authenticated with a DeviceFingerprint
MATCH (s:Session {session_id: $session_id})
MATCH (d:DeviceFingerprint {device_id: $device_id})
MERGE (s)-[r:AUTHENTICATED_WITH]->(d)
ON CREATE SET
    r.created_at    = $timestamp,
    r.is_new_device = $is_new_device;           // boolean — first time account uses this device

// Session originated from an IPAddress
MATCH (s:Session {session_id: $session_id})
MATCH (ip:IPAddress {address: $ip_address})
MERGE (s)-[r:ORIGINATED_FROM]->(ip)
ON CREATE SET
    r.created_at = $timestamp;

// DeviceFingerprint associated with IPAddress
// Written by batch — tracks device-to-IP association patterns
MATCH (d:DeviceFingerprint {device_id: $device_id})
MATCH (ip:IPAddress {address: $ip_address})
MERGE (d)-[r:ASSOCIATED_IP]->(ip)
ON CREATE SET
    r.first_seen    = $timestamp,
    r.last_seen     = $timestamp,
    r.frequency     = 1
ON MATCH SET
    r.last_seen     = $timestamp,
    r.frequency     = r.frequency + 1;

// Account has a BehavioralBaseline
MATCH (a {account_id: $account_id})
MATCH (b:BehavioralBaseline {baseline_id: $baseline_id})
MERGE (a)-[r:HAS_BASELINE]->(b)
ON CREATE SET
    r.created_at = $created_at;

// Session deviates from BehavioralBaseline
// Batch-written — only created when deviation_score exceeds threshold
// NOT written on every session — only anomalous ones
MATCH (s:Session {session_id: $session_id})
MATCH (b:BehavioralBaseline {baseline_id: $baseline_id})
MERGE (s)-[r:DEVIATES_FROM]->(b)
ON CREATE SET
    r.deviation_score   = $deviation_score,     // 0.0-1.0
    r.features          = $features,            // list of which features deviated
    r.created_at        = $created_at;


// -----------------------------------------------------------------------------
// DETECTION QUERIES — ATO
// -----------------------------------------------------------------------------

// DETECTION 1: New device on account
// Session used a device not in the account's baseline known_device_ids
MATCH (a {account_id: $account_id})-[:HAS_BASELINE]->(b:BehavioralBaseline)
MATCH (a)-[:HAD_SESSION]->(s:Session)-[:AUTHENTICATED_WITH]->(d:DeviceFingerprint)
WHERE NOT d.device_id IN b.known_device_ids
  AND s.timestamp > datetime() - duration('PT24H')
RETURN
    s.session_id,
    d.device_id,
    d.os,
    d.browser,
    s.timestamp,
    s.country_code;


// DETECTION 2: Geo anomaly — session from country not in baseline
MATCH (a {account_id: $account_id})-[:HAS_BASELINE]->(b:BehavioralBaseline)
MATCH (a)-[:HAD_SESSION]->(s:Session)
WHERE NOT s.country_code IN b.known_countries
  AND s.timestamp > datetime() - duration('PT24H')
RETURN
    s.session_id,
    s.country_code,
    s.city,
    s.timestamp;


// DETECTION 3: High deviation sessions — sessions flagged by batch
MATCH (a {account_id: $account_id})-[:HAD_SESSION]->(s:Session)
      -[r:DEVIATES_FROM]->(b:BehavioralBaseline)
WHERE r.deviation_score > 0.7
RETURN
    s.session_id,
    r.deviation_score,
    r.features,
    s.timestamp
ORDER BY r.deviation_score DESC;


// DETECTION 4: Impossible travel — two sessions from impossible geo distance
// Uses point.distance() on lat/lon properties — no geo nodes needed
MATCH (a {account_id: $account_id})-[:HAD_SESSION]->(s1:Session)
MATCH (a)-[:HAD_SESSION]->(s2:Session)
WHERE s1.session_id <> s2.session_id
  AND s1.timestamp < s2.timestamp
  AND duration.inSeconds(s1.timestamp, s2.timestamp).seconds < 7200
  AND point.distance(
        point({latitude: s1.lat, longitude: s1.lon}),
        point({latitude: s2.lat, longitude: s2.lon})
      ) > 500000                               // 500km — adjust per risk appetite
RETURN
    s1.session_id,
    s1.country_code,
    s1.timestamp,
    s2.session_id,
    s2.country_code,
    s2.timestamp;


// DETECTION 5: Credential stuffing — many failed sessions before success
MATCH (a {account_id: $account_id})-[:HAD_SESSION]->(s:Session)
WHERE s.event_type = 'login'
  AND s.timestamp > datetime() - duration('PT1H')
WITH
    count(CASE WHEN s.status = 'failed'  THEN 1 END) AS failed_count,
    count(CASE WHEN s.status = 'success' THEN 1 END) AS success_count
WHERE failed_count > 5
RETURN failed_count, success_count;
