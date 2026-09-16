//! The client must carry a load balancer's affinity cookie between calls.
//!
//! An assignment attests one enclave boot's encryption key, so the match that follows has to
//! reach the same pod. Behind an ALB that affinity is a cookie, and a client that drops it lands
//! on an arbitrary pod and burns an attestation on `reassign_required`.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, header};
use axum::routing::post;
use flamingo_verifier_client::PcrMeasurement;
use flamingo_verifier_client::{Config, FlamingoVerifierClient};
use hex_literal::hex;

/// What a target group's `lb_cookie` stickiness looks like on the wire.
const AFFINITY_COOKIE: &str = "AWSALB=pod-a; Path=/";

fn config(base_url: &str) -> Config {
    let pcrs = vec![PcrMeasurement::new(
        0,
        hex!(
            "108b32466f5dc0a9971e0bc8e3e4074e7821bb2dcad3841bdec9a08b30f173386f0394a01486df181f316b39443dab34"
        ),
    )];

    Config::new(base_url, vec![pcrs]).expect("config should be valid")
}

/// Records the `Cookie` header of the request that follows the assignment.
type SeenCookie = Arc<Mutex<Option<String>>>;

#[tokio::test]
async fn carries_the_affinity_cookie_from_the_assignment_to_the_next_call() {
    let seen: SeenCookie = Arc::new(Mutex::new(None));

    let router = Router::new()
        .route(
            "/v1/enclave-assignment",
            post(
                |State(seen): State<SeenCookie>, headers: HeaderMap| async move {
                    // Records every request, so after two calls this holds the second one's.
                    *seen.lock().expect("lock should not be poisoned") = headers
                        .get(header::COOKIE)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned);

                    (
                        [(header::SET_COOKIE, AFFINITY_COOKIE)],
                        axum::Json(serde_json::json!({
                            "attestation": "hEBAQEA=",
                            "public_key": "a2V5"
                        })),
                    )
                },
            ),
        )
        .with_state(Arc::clone(&seen));

    let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("should bind an ephemeral port");
    let address = listener
        .local_addr()
        .expect("listener should have an address");
    tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("stub should run");
    });

    let client = FlamingoVerifierClient::new(config(&format!("http://{address}")))
        .expect("client should build");

    for _ in 0..2 {
        client
            .request_assignment()
            .await
            .expect_err("transport must preserve affinity even when the evidence is rejected");
    }

    let carried = seen
        .lock()
        .expect("lock should not be poisoned")
        .clone()
        .expect("the second call should have sent a Cookie header");

    assert!(
        carried.contains("AWSALB=pod-a"),
        "affinity cookie was not carried: {carried}"
    );
}
