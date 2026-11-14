use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};

use super::*;

const NOVEMBER: u64 = 1_793_534_400;
const DAY: u64 = 86_400;

const fn now() -> u64 {
    NOVEMBER + 10 * DAY
}
const fn next_period() -> u64 {
    NOVEMBER + 30 * DAY
}

fn config() -> IndexerConfig {
    IndexerConfig::new(
        "billing".into(),
        480,
        B256::repeat_byte(1),
        Address::repeat_byte(2),
        1,
    )
}

fn block(number: u64) -> Value {
    json!({"number":number,"hash":format!("0x{number:064x}")})
}

fn status(head: u64) -> Value {
    let config = config();
    json!({"target":config.target,"generation":"generation-1","chain_id":config.chain_id,
        "genesis_hash":config.genesis_hash.to_string(),"address":config.contract.to_string(),
        "start_block":1,"topic_filter":[[BilledRpUpdated::SIGNATURE_HASH.to_string(),Registered::SIGNATURE_HASH.to_string()]],
        "contract_verified_at":block(head),"startup_head":block(10),"covered_through":block(head),
        "observed_head":block(head),"canonical":"ready","caught_up":true})
}

fn event(id: &str, topics: Vec<String>, data: String, state: &str) -> Value {
    json!({"id":id,"target":"billing","chain_id":480,"address":config().contract.to_string(),
        "transaction_index":0,"log_index":0,"block":block(2),"topics":topics,"data":data,"state":state})
}

fn registered(nullifier: u64, state: &str) -> Value {
    let mut value = event(
        &format!("registration-{nullifier}"),
        vec![
            Registered::SIGNATURE_HASH.to_string(),
            format!("0x{:064x}", 7),
            format!("0x{NOVEMBER:064x}"),
            format!("0x{nullifier:064x}"),
        ],
        "0x".into(),
        state,
    );
    value["transaction_index"] = json!(nullifier);
    value
}

fn billed(rp: u64, flag: bool, state: &str) -> Value {
    let mut value = event(
        &format!("rp-{rp}"),
        vec![
            BilledRpUpdated::SIGNATURE_HASH.to_string(),
            format!("0x{rp:064x}"),
        ],
        format!("0x{:064x}", u64::from(flag)),
        state,
    );
    value["transaction_index"] = json!(rp);
    value
}

fn page(events: Vec<Value>, next: Option<&str>) -> Value {
    json!({"version":1,"events":events,"targets":[status(10)],"next_page":next,"resume_cursor":"resume"})
}

fn change(previous: Option<&str>, event: Value) -> Value {
    json!({"kind":"event","previous":previous,"event":event})
}

fn progress(status: Value) -> Value {
    json!({"kind":"progress","status":status})
}

fn batch(changes: Vec<Value>, first: u64, cursor: &str, more: bool) -> Value {
    let records: Vec<_> = changes
        .into_iter()
        .enumerate()
        .map(|(i, change)| json!({"sequence":first+i as u64,"change":change}))
        .collect();
    json!({"version":1,"records":records,"cursor":cursor,"has_more":more})
}

struct Reply {
    status: StatusCode,
    content_type: &'static str,
    body: String,
}

impl Reply {
    fn json(value: Value) -> Self {
        Self {
            status: StatusCode::OK,
            content_type: "application/json",
            body: value.to_string(),
        }
    }
    fn error(status: StatusCode) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: "{}".into(),
        }
    }
    fn sse(value: Value) -> Self {
        Self {
            status: StatusCode::OK,
            content_type: "text/event-stream",
            body: format!("event: changes\ndata: {value}\n\n"),
        }
    }

    fn into_sse(mut self) -> Self {
        if self.status.is_success() {
            self.content_type = "text/event-stream";
            self.body = format!("event: changes\ndata: {}\n\n", self.body);
        }
        self
    }
}

struct Script {
    snapshots: VecDeque<Reply>,
    bootstrap_drain: Option<Reply>,
    changes: VecDeque<Reply>,
    streams: VecDeque<Reply>,
    calls: Vec<(String, Value)>,
    status: Value,
}

struct Fixture {
    state: Arc<Mutex<Script>>,
    url: Url,
    server: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn start(snapshots: Vec<Reply>, changes: Vec<Reply>, streams: Vec<Reply>) -> Self {
        let state = Arc::new(Mutex::new(Script {
            snapshots: snapshots.into(),
            bootstrap_drain: Some(Reply::json(batch(vec![], 1, "resume", false))),
            changes: changes.into(),
            streams: streams.into(),
            calls: Vec::new(),
            status: json!({"version":1,"targets":[status(10)]}),
        }));
        let app = Router::new()
            .route("/v1/status", get(read_status))
            .route("/v1/snapshot", post(read))
            .route("/v1/changes", post(read))
            .route("/v1/stream", post(read))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { state, url, server }
    }

    fn follower(&self) -> IndexerFollower {
        let mut follower =
            IndexerFollower::new(self.url.clone(), "fixture-token".into(), config()).unwrap();
        follower.clock = now;
        follower
    }

    fn calls(&self) -> Vec<(String, Value)> {
        self.state.lock().unwrap().calls.clone()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn read_status(State(state): State<Arc<Mutex<Script>>>, headers: HeaderMap) -> Json<Value> {
    assert_eq!(headers["authorization"], "Bearer fixture-token");
    let mut script = state.lock().unwrap();
    script.calls.push(("/v1/status".into(), Value::Null));
    Json(script.status.clone())
}

async fn read(
    State(state): State<Arc<Mutex<Script>>>,
    uri: Uri,
    headers: HeaderMap,
    Json(request): Json<Value>,
) -> Response {
    assert_eq!(headers["authorization"], "Bearer fixture-token");
    assert_eq!(request["limit"], 1000);
    let mut script = state.lock().unwrap();
    script.calls.push((uri.path().into(), request));
    let reply = match uri.path() {
        "/v1/snapshot" => script.snapshots.pop_front(),
        "/v1/changes" => script
            .bootstrap_drain
            .take()
            .or_else(|| script.changes.pop_front()),
        "/v1/stream" => script
            .streams
            .pop_front()
            .or_else(|| script.changes.pop_front().map(Reply::into_sse)),
        _ => unreachable!(),
    }
    .expect("unexpected fixture request");
    (
        reply.status,
        [("content-type", reply.content_type)],
        reply.body,
    )
        .into_response()
}

async fn next(follower: &mut IndexerFollower) -> BillingUpdate {
    tokio::time::timeout(Duration::from_secs(5), follower.next())
        .await
        .expect("follower deadline")
        .unwrap()
}

async fn caught_up(follower: &mut IndexerFollower) {
    assert!(!next(follower).await.backfill_done);
    assert!(!next(follower).await.backfill_done);
    assert!(next(follower).await.backfill_done);
}

async fn reset(follower: &mut IndexerFollower, reason: ResetReason) {
    let error = tokio::time::timeout(Duration::from_secs(5), follower.next())
        .await
        .expect("reset deadline")
        .unwrap_err();
    assert!(
        matches!(&error, IndexerError::ResetRequired(actual) if *actual==reason),
        "{error}"
    );
    let repeated = tokio::time::timeout(Duration::from_secs(5), follower.next())
        .await
        .expect("terminal reset deadline");
    assert!(matches!(repeated,Err(IndexerError::ResetRequired(actual)) if actual==reason));
}

#[tokio::test]
async fn bootstrap_streams_pages_before_sorted_bounded_rp_delivery_and_completion() {
    let first: Vec<_> = (1..=1000)
        .rev()
        .map(|rp| billed(rp, true, "unsafe"))
        .collect();
    let fixture = Fixture::start(
        vec![
            Reply::json(page(first, Some("page-2"))),
            Reply::json(page(
                vec![billed(1001, true, "unsafe"), registered(0, "unsafe")],
                None,
            )),
        ],
        vec![],
        vec![],
    )
    .await;
    let mut follower = fixture.follower();
    let update = next(&mut follower).await;
    assert!(update.ops.is_empty());
    assert!(!update.backfill_done);
    let update = next(&mut follower).await;
    assert_eq!(
        update.ops,
        vec![BillingOp::AddRegistration {
            nullifier: FieldElement::from(0u64),
            registration: Registration {
                rp_id: RpId::new(7),
                period_start: NOVEMBER
            }
        }]
    );
    assert!(!update.backfill_done);
    for expected in [(1, 1000), (1001, 1001)] {
        let update = next(&mut follower).await;
        let rps: Vec<_> = update
            .ops
            .into_iter()
            .map(|op| match op {
                BillingOp::SetBilledRp {
                    rp_id,
                    billed: true,
                } => rp_id.into_inner(),
                _ => panic!("RP snapshot op"),
            })
            .collect();
        assert_eq!(rps, (expected.0..=expected.1).collect::<Vec<_>>());
        assert!(!update.backfill_done);
    }
    let update = next(&mut follower).await;
    assert!(update.ops.is_empty());
    assert!(!update.backfill_done);
    let update = next(&mut follower).await;
    assert!(update.ops.is_empty());
    assert!(update.backfill_done);
    assert_eq!(update.head, 10);
    assert_eq!(follower.projection.len(), 1001);
    let calls = fixture.calls();
    assert_eq!(calls[0].1["cursor"], Value::Null);
    assert_eq!(calls[1].1["cursor"], "page-2");
    assert_eq!(
        calls[0].1["scope"]["filters"][1]["topics"][2],
        json!([format!("0x{NOVEMBER:064x}")])
    );
    assert_eq!(calls[calls.len() - 2].0, "/v1/status");
    assert_eq!(calls.last().unwrap().0, "/v1/changes");
}

#[tokio::test]
async fn registration_pages_do_not_consume_rp_history_capacity() {
    let fixture = Fixture::start(
        vec![
            Reply::json(page(
                (0..1000).map(|n| registered(n, "unsafe")).collect(),
                Some("page-2"),
            )),
            Reply::json(page(
                (1000..2000).map(|n| registered(n, "safe")).collect(),
                Some("page-3"),
            )),
            Reply::json(page(vec![registered(2000, "finalized")], None)),
        ],
        vec![],
        vec![],
    )
    .await;
    let mut config = config();
    config.max_rp_events = 1;
    let mut follower =
        IndexerFollower::new(fixture.url.clone(), "fixture-token".into(), config).unwrap();
    follower.clock = now;
    for count in [1000, 1000, 1] {
        let update = next(&mut follower).await;
        assert_eq!(update.ops.len(), count);
        assert!(
            update
                .ops
                .iter()
                .all(|op| matches!(op, BillingOp::AddRegistration { .. }))
        );
        assert!(!update.backfill_done);
        assert_eq!(follower.projection.len(), 0);
    }
    assert!(!next(&mut follower).await.backfill_done);
    assert!(next(&mut follower).await.backfill_done);
}

#[tokio::test]
async fn live_only_emits_canonical_lifecycle_transitions_and_retraction_preimages() {
    let changes = vec![
        change(None, registered(0, "preconfirmed")),
        change(Some("preconfirmed"), registered(0, "unsafe")),
        change(Some("unsafe"), registered(0, "safe")),
        change(Some("safe"), registered(0, "finalized")),
        change(Some("finalized"), registered(0, "removed")),
        change(None, billed(7, true, "unsafe")),
        change(Some("unsafe"), billed(7, true, "safe")),
        change(Some("safe"), billed(7, true, "removed")),
        progress(status(11)),
    ];
    let fixture = Fixture::start(
        vec![Reply::json(page(vec![], None))],
        vec![Reply::json(batch(changes, 1, "live", false))],
        vec![],
    )
    .await;
    let mut follower = fixture.follower();
    caught_up(&mut follower).await;
    let update = next(&mut follower).await;
    let registration = Registration {
        rp_id: RpId::new(7),
        period_start: NOVEMBER,
    };
    assert_eq!(
        update.ops,
        vec![
            BillingOp::AddRegistration {
                nullifier: FieldElement::from(0u64),
                registration
            },
            BillingOp::RemoveRegistration {
                nullifier: FieldElement::from(0u64),
                registration
            },
            BillingOp::SetBilledRp {
                rp_id: RpId::new(7),
                billed: true
            },
            BillingOp::SetBilledRp {
                rp_id: RpId::new(7),
                billed: false
            }
        ]
    );
    assert!(update.backfill_done);
    assert_eq!(update.head, 11);
    assert_eq!(follower.projection.len(), 0);
}

#[tokio::test]
async fn out_of_field_registration_requires_reset_instead_of_becoming_ready() {
    let mut invalid = registered(0, "unsafe");
    invalid["topics"][3] =
        json!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    let fixture =
        Fixture::start(vec![Reply::json(page(vec![invalid], None))], vec![], vec![]).await;
    reset(&mut fixture.follower(), ResetReason::Protocol).await;
}

#[tokio::test]
async fn source_generation_and_recovery_are_sticky_resets_before_batch_application() {
    for (field, value, reason) in [
        ("generation", json!("generation-2"), ResetReason::Generation),
        (
            "canonical",
            json!("recovery_required"),
            ResetReason::Recovery,
        ),
    ] {
        let mut changed = status(11);
        changed[field] = value;
        let fixture = Fixture::start(
            vec![Reply::json(page(vec![], None))],
            vec![Reply::json(batch(
                vec![change(None, billed(7, true, "unsafe")), progress(changed)],
                1,
                "changed",
                false,
            ))],
            vec![],
        )
        .await;
        let mut follower = fixture.follower();
        caught_up(&mut follower).await;
        reset(&mut follower, reason).await;
        assert_eq!(follower.projection.len(), 0);
        assert_eq!(follower.cursor.as_deref(), Some("resume"));
        assert_eq!(fixture.calls().len(), 4);
    }
}

#[tokio::test]
async fn snapshot_completion_rechecks_source_recovery_before_announcing_readiness() {
    let fixture = Fixture::start(vec![Reply::json(page(vec![], None))], vec![], vec![]).await;
    let mut follower = fixture.follower();
    assert!(!next(&mut follower).await.backfill_done);
    fixture.state.lock().unwrap().status["targets"][0]["canonical"] = json!("recovery_required");
    reset(&mut follower, ResetReason::Recovery).await;
    assert!(!follower.announced);
}

#[tokio::test]
async fn cursor_expiry_and_period_rollover_require_explicit_receiver_reset() {
    let fixture = Fixture::start(
        vec![Reply::json(page(vec![], None))],
        vec![Reply::error(StatusCode::GONE)],
        vec![],
    )
    .await;
    let mut follower = fixture.follower();
    caught_up(&mut follower).await;
    reset(&mut follower, ResetReason::Cursor).await;

    let fixture = Fixture::start(
        vec![
            Reply::json(page(vec![registered(1, "unsafe")], Some("page-2"))),
            Reply::error(StatusCode::CONFLICT),
        ],
        vec![],
        vec![],
    )
    .await;
    let mut follower = fixture.follower();
    assert!(!next(&mut follower).await.backfill_done);
    reset(&mut follower, ResetReason::Cursor).await;

    let fixture = Fixture::start(vec![Reply::json(page(vec![], None))], vec![], vec![]).await;
    let mut follower = fixture.follower();
    caught_up(&mut follower).await;
    follower.clock = next_period;
    reset(&mut follower, ResetReason::Period).await;
    assert_eq!(fixture.calls().len(), 3);
}

#[tokio::test]
async fn http_drain_then_sse_reconnects_from_the_last_delivered_cursor() {
    let update = |head, cursor, more| batch(vec![progress(status(head))], head - 10, cursor, more);
    let fixture = Fixture::start(
        vec![Reply::json(page(vec![], None))],
        vec![
            Reply::json(update(11, "drain-1", true)),
            Reply::json(update(12, "drain-2", false)),
            Reply::json(update(14, "drain-3", false)),
        ],
        vec![
            Reply::sse(update(13, "stream-1", false)),
            Reply::sse(update(15, "stream-2", false)),
        ],
    )
    .await;
    fixture.state.lock().unwrap().bootstrap_drain = None;
    let mut follower = fixture.follower();
    assert!(!next(&mut follower).await.backfill_done);
    assert!(!next(&mut follower).await.backfill_done);
    for head in 11..=15 {
        let update = next(&mut follower).await;
        assert_eq!(update.head, head);
        assert!(update.ops.is_empty());
        assert_eq!(update.backfill_done, head >= 12);
    }
    let calls = fixture.calls();
    assert_eq!(
        calls
            .iter()
            .map(|(path, _)| path.as_str())
            .collect::<Vec<_>>(),
        vec![
            "/v1/snapshot",
            "/v1/status",
            "/v1/changes",
            "/v1/changes",
            "/v1/stream",
            "/v1/changes",
            "/v1/stream"
        ]
    );
    assert_eq!(calls[4].1["cursor"], "drain-2");
    assert_eq!(calls[5].1["cursor"], "stream-1");
    assert_eq!(calls[6].1["cursor"], "drain-3");
}

#[tokio::test]
async fn queued_reorg_is_applied_before_the_first_ready_update() {
    let fixture = Fixture::start(
        vec![Reply::json(page(vec![billed(7, true, "unsafe")], None))],
        vec![Reply::json(batch(
            vec![
                change(Some("unsafe"), billed(7, true, "removed")),
                progress(status(11)),
            ],
            1,
            "reconciled",
            false,
        ))],
        vec![],
    )
    .await;
    fixture.state.lock().unwrap().bootstrap_drain = None;
    let mut follower = fixture.follower();
    assert!(!next(&mut follower).await.backfill_done);
    let rps = next(&mut follower).await;
    assert!(!rps.backfill_done);
    assert_eq!(
        rps.ops,
        vec![BillingOp::SetBilledRp {
            rp_id: RpId::new(7),
            billed: true
        }]
    );
    assert!(!next(&mut follower).await.backfill_done);
    assert!(!follower.announced);
    let reconciled = next(&mut follower).await;
    assert!(reconciled.backfill_done);
    assert_eq!(
        reconciled.ops,
        vec![BillingOp::SetBilledRp {
            rp_id: RpId::new(7),
            billed: false
        }]
    );
    assert_eq!(reconciled.head, 11);
    assert_eq!(follower.projection.billed_len(), 0);
}

#[tokio::test]
async fn ordinary_unavailable_progress_preserves_completed_state() {
    let mut unavailable = status(11);
    unavailable["canonical"] = json!("unavailable");
    unavailable["caught_up"] = json!(false);
    let fixture = Fixture::start(
        vec![Reply::json(page(vec![], None))],
        vec![Reply::json(batch(
            vec![progress(unavailable)],
            1,
            "unavailable",
            false,
        ))],
        vec![],
    )
    .await;
    let mut follower = fixture.follower();
    caught_up(&mut follower).await;
    let update = next(&mut follower).await;
    assert!(update.backfill_done);
    assert!(update.ops.is_empty());
    assert_eq!(update.head, 11);
    assert!(matches!(follower.phase, Phase::Live));
}

#[test]
fn source_identity_scope_and_hash_bound_verification_are_checked_before_readiness() {
    let follower = IndexerFollower::new(
        Url::parse("http://127.0.0.1:1/").unwrap(),
        "fixture-token".into(),
        config(),
    )
    .unwrap();
    for (field, value) in [
        ("chain_id", json!(481)),
        ("genesis_hash", json!(B256::repeat_byte(3).to_string())),
        ("address", json!(Address::repeat_byte(3).to_string())),
        ("start_block", json!(2)),
        (
            "topic_filter",
            json!([[BilledRpUpdated::SIGNATURE_HASH.to_string()]]),
        ),
        (
            "topic_filter",
            json!([
                [
                    BilledRpUpdated::SIGNATURE_HASH.to_string(),
                    Registered::SIGNATURE_HASH.to_string()
                ],
                [format!("0x{:064x}", 7)]
            ]),
        ),
    ] {
        let mut invalid = status(10);
        invalid[field] = value;
        let invalid = serde_json::from_value(invalid).unwrap();
        assert!(matches!(
            follower.validate_status(&invalid),
            Err(StepError::Fatal(IndexerError::Source(_)))
        ));
        assert!(!follower.announced);
    }
    let mut invalid = status(10);
    invalid["contract_verified_at"]["hash"] = json!(B256::repeat_byte(4).to_string());
    let invalid = serde_json::from_value(invalid).unwrap();
    assert!(matches!(
        follower.validate_status(&invalid),
        Err(StepError::Reset(ResetReason::Protocol))
    ));
    assert!(!follower.announced);
}

#[tokio::test]
async fn changing_snapshot_cursor_or_frozen_metadata_requires_a_sticky_reset() {
    for change_cursor in [true, false] {
        let mut changed = page(vec![], None);
        if change_cursor {
            changed["resume_cursor"] = json!("different-resume");
        } else {
            changed["targets"][0]["startup_head"] = block(9);
        }
        let fixture = Fixture::start(
            vec![
                Reply::json(page(vec![], Some("page-2"))),
                Reply::json(changed),
            ],
            vec![],
            vec![],
        )
        .await;
        let mut follower = fixture.follower();
        assert!(!next(&mut follower).await.backfill_done);
        reset(&mut follower, ResetReason::Protocol).await;
        assert!(!follower.announced);
        assert_eq!(fixture.calls().len(), 2);
    }
}
