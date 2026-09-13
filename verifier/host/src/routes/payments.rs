use std::str::FromStr as _;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::B256;
use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection, rejection::PathRejection},
    http::StatusCode,
};
use flamingo_verifier_api_types::{
    ErrorDetails, LaneAuthorizationBody, Payment, PaymentAuthorizationBody,
    ReserveNonceRequestBody, ReserveNonceResponseBody,
};

use crate::AppState;
use crate::error::AppError;
use crate::payments::{AdmitRequest, CapacityProof, LedgerError, ReserveRequest};

/// Largest body these routes accept. They carry fixed-width hex fields and nothing else.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// Reserves the next channel nonce for a request.
///
/// # Errors
///
/// Returns [`AppError`] if the path or body is rejected, the channel is unknown or settles
/// elsewhere, the epoch is not open, capacity is spent, or a dependency failed.
pub async fn reserve(
    State(state): State<AppState>,
    path: Result<Path<String>, PathRejection>,
    body: Result<Json<ReserveNonceRequestBody>, JsonRejection>,
) -> Result<Json<ReserveNonceResponseBody>, AppError> {
    let Path(channel_id) = path.map_err(|rejection| rejected_path(&rejection))?;
    let channel_id = parse_channel_id(&channel_id)?;
    let Json(body) = body.map_err(|rejection| rejected_body(&rejection))?;

    let request = ReserveRequest {
        channel_id,
        epoch: body.epoch,
        issued_at: body.issued_at,
        signature: body.signature,
    };

    let outcome = state
        .payments()
        .reserve(&request, now())
        .await
        .map_err(|error| refused(&error, channel_id, body.epoch, None))?;

    tracing::info!(
        channel_id = %channel_id,
        epoch = body.epoch,
        lane = outcome.lane,
        counter = outcome.counter,
        expires_by = outcome.expires_by,
        "nonce reserved"
    );

    Ok(Json(ReserveNonceResponseBody {
        lane: outcome.lane,
        counter: outcome.counter,
        expires_by: outcome.expires_by,
        previous: outcome.previous.map(|previous| PaymentAuthorizationBody {
            channel_nonce: previous.nonce(),
            signature: previous.signature,
        }),
    }))
}

/// Spends a payment on one verification, or refuses the request.
///
/// Shared with the match route, which is the only place a payment is redeemed. The signature is
/// recovered inside the ledger before it writes, so a stream of invalid payments cannot multiply
/// into store traffic.
///
/// # Errors
///
/// Returns [`AppError`] when a payment is required and absent, or when the ledger refuses it.
pub(super) async fn admit(state: &AppState, payment: Option<&Payment>) -> Result<(), AppError> {
    let Some(payment) = payment else {
        if state.payments().config().payment_required() {
            return Err(AppError::new(
                StatusCode::PAYMENT_REQUIRED,
                "payment_required",
                "This verifier requires a payment for every match",
                false,
            ));
        }

        return Ok(());
    };

    let request = AdmitRequest {
        channel_id: payment.channel_id,
        epoch: payment.epoch,
        nonce: payment.channel_nonce,
        signature: payment.signature,
    };

    state
        .payments()
        .admit(&request, now())
        .await
        .map_err(|error| {
            refused(
                &error,
                payment.channel_id,
                payment.epoch,
                Some((
                    payment.channel_nonce.lane(),
                    payment.channel_nonce.counter(),
                )),
            )
        })?;

    tracing::info!(
        channel_id = %payment.channel_id,
        epoch = payment.epoch,
        lane = payment.channel_nonce.lane(),
        counter = payment.channel_nonce.counter(),
        "payment admitted"
    );

    Ok(())
}

/// Maps a ledger refusal, carrying the channel and nonce into the log the error already writes.
///
/// The signature stays out of the log: it is the caller's payload, and a refusal says nothing
/// more by repeating it. A capacity refusal is the one that carries evidence to the client.
fn refused(
    error: &LedgerError,
    channel_id: B256,
    epoch: u64,
    nonce: Option<(u32, u64)>,
) -> AppError {
    let context = || {
        let (lane, counter) = nonce.unzip();

        format!(
            "channel_id={channel_id}; epoch={epoch}; lane={}; counter={}",
            lane.map_or_else(|| "-".to_owned(), |lane| lane.to_string()),
            counter.map_or_else(|| "-".to_owned(), |counter| counter.to_string()),
        )
    };

    if let Some(special) = carries_evidence(error) {
        return special.with_detail(context());
    }

    let (status, code, message, allow_retry) = status_for(error);

    AppError::new(status, code, message, allow_retry).with_detail(context())
}

/// The refusals that carry more than a status: a dependency name, or evidence for the client.
fn carries_evidence(error: &LedgerError) -> Option<AppError> {
    let mapped = match error {
        // The two dependency failures. Retryable, and each names itself so a dashboard can tell
        // a store outage from a node outage without reading the message.
        LedgerError::Store(_) => AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "payments_store_unavailable",
            "The payments store is unavailable",
            true,
        )
        .with_dependency("payments_store"),
        LedgerError::Escrow(_) => AppError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "escrow_unavailable",
            "The fee escrow cannot be read",
            true,
        )
        .with_dependency("fee_escrow_rpc"),
        // Carries the proof: an operator told the channel is spent can check every signature
        // listed and add up the counters instead of taking the number on trust.
        LedgerError::CapacityExhausted(proof) => AppError::new(
            StatusCode::CONFLICT,
            "capacity_exhausted",
            "The channel has spent its capacity for this epoch",
            false,
        )
        .with_details(details(proof)),
        // Nothing is spent yet, so waiting is what helps. The proof carries the deadline of the
        // earliest outstanding reservation rather than leaving the caller to guess.
        LedgerError::CapacityReserved(proof) => AppError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "capacity_reserved",
            "The channel's capacity is held by outstanding reservations",
            true,
        )
        .with_details(details(proof)),
        _ => return None,
    };

    Some(mapped)
}

/// Status, code and retryability for every refusal that carries nothing else.
const fn status_for(error: &LedgerError) -> (StatusCode, &'static str, &'static str, bool) {
    match error {
        LedgerError::UnknownChannel => (
            StatusCode::NOT_FOUND,
            "unknown_channel",
            "The fee escrow does not know this channel",
            false,
        ),
        LedgerError::WrongCollector => (
            StatusCode::FORBIDDEN,
            "wrong_collector",
            "The channel settles to another verifier",
            false,
        ),
        LedgerError::ChannelTermsRejected => (
            StatusCode::FORBIDDEN,
            "channel_terms_rejected",
            "The channel's token or price is not accepted here",
            false,
        ),
        LedgerError::InvalidReservation => (
            StatusCode::UNAUTHORIZED,
            "invalid_signature",
            "The reservation was not signed by the channel spend key",
            false,
        ),
        LedgerError::StaleReservation => (
            StatusCode::BAD_REQUEST,
            "stale_reservation",
            "The reservation was issued too far from this verifier's clock",
            false,
        ),
        LedgerError::InvalidEpoch => (
            StatusCode::BAD_REQUEST,
            "invalid_epoch",
            "The epoch is neither the current one nor the next",
            false,
        ),
        // The epoch is at its bound now, not forever: a reservation expiring frees a counter.
        LedgerError::TooManyPending => (
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_pending",
            "Too many reservations are outstanding for this epoch",
            true,
        ),
        LedgerError::UnknownReservation => (
            StatusCode::NOT_FOUND,
            "unknown_reservation",
            "No reservation matches this lane and counter",
            false,
        ),
        LedgerError::ReservationExpired => (
            StatusCode::GONE,
            "reservation_expired",
            "The reservation expired before the payment arrived",
            false,
        ),
        LedgerError::InvalidSignature => (
            StatusCode::UNAUTHORIZED,
            "invalid_signature",
            "The signature does not match the channel spend key",
            false,
        ),
        // Deliberately not a cached result: the nonce paid for one verification and that
        // verification already ran. Returning the earlier outcome is out of scope here.
        LedgerError::AlreadyAdmitted => (
            StatusCode::CONFLICT,
            "already_admitted",
            "The channel nonce has already been spent on a verification",
            false,
        ),
        // Handled by `carries_evidence`, which runs first.
        LedgerError::Store(_)
        | LedgerError::Escrow(_)
        | LedgerError::CapacityExhausted(_)
        | LedgerError::CapacityReserved(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Internal server error",
            false,
        ),
    }
}

/// Turns the ledger's proof into the wire shape a refusal carries.
fn details(proof: &CapacityProof) -> ErrorDetails {
    ErrorDetails {
        epoch: proof.epoch,
        admitted_units: proof.admitted_units,
        capacity: proof.capacity,
        retry_after: proof.retry_after,
        authorizations: proof
            .authorizations
            .iter()
            .map(|authorization| LaneAuthorizationBody {
                lane: authorization.lane,
                channel_nonce: authorization.nonce(),
                signature: authorization.signature,
            })
            .collect(),
    }
}

/// The `0x` prefix is required here, unlike in `B256::from_str`, which treats it as optional.
/// One spelling per id keeps a client from finding two that work and a log from carrying both.
fn parse_channel_id(value: &str) -> Result<B256, AppError> {
    if !value.starts_with("0x") {
        return Err(invalid_channel_id());
    }

    B256::from_str(value).map_err(|_| invalid_channel_id())
}

const fn invalid_channel_id() -> AppError {
    AppError::new(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "The channel id must be 32 bytes of 0x-prefixed hex",
        false,
    )
}

/// Maps a path the extractor refused, so it carries the same envelope as everything else.
fn rejected_path(rejection: &PathRejection) -> AppError {
    AppError::new(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "The request path was not the expected shape",
        false,
    )
    .with_detail(rejection.body_text())
}

/// Maps a body the extractor refused. See `matches::rejected_body` for why this exists.
fn rejected_body(rejection: &JsonRejection) -> AppError {
    let (status, code, message) = if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_too_large",
            "The request was larger than this route accepts",
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The request body was not the expected JSON",
        )
    };

    AppError::new(status, code, message, false)
        .with_detail(format!("{}; limit={MAX_BODY_BYTES}", rejection.body_text()))
}

/// Unix seconds. A clock before the epoch would be a broken host, and reads as time zero rather
/// than as every reservation being live forever.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
