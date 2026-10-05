//! End-to-end pairing over real iroh endpoints on loopback (no relay, no discovery).
#![allow(missing_docs)]

use device_pairing::net::{ALPN, accept, join};
use device_pairing::{PairError, PairingWindow};
use iroh::endpoint::presets;
use iroh::{Endpoint, SecretKey};

async fn endpoint(seed: u8) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&[seed; 32]))
        .alpns(vec![ALPN.to_vec()])
        .clear_address_lookup()
        .clear_relay_transports()
        .bind()
        .await
        .expect("bind loopback endpoint")
}

async fn pair(
    host_code_ok: bool,
) -> (
    Result<device_pairing::net::Paired, PairError>,
    Result<device_pairing::net::Paired, PairError>,
) {
    let host = endpoint(1).await;
    let joiner = endpoint(2).await;
    let mut window = PairingWindow::open();
    let typed = if host_code_ok {
        window.code()
    } else {
        "22222222".to_string()
    };
    let addr = host.addr();
    let h = host.clone();
    let host_task = tokio::spawn(async move {
        let incoming = h.accept().await.expect("incoming");
        let conn = incoming
            .accept()
            .expect("accepting")
            .await
            .expect("handshake");
        accept(&h, conn, &mut window).await
    });
    let j = join(&joiner, addr, &typed).await;
    let h = host_task.await.expect("host task");
    joiner.close().await;
    host.close().await;
    (h, j)
}

#[tokio::test(flavor = "multi_thread")]
async fn right_code_pairs_both_sides_with_the_same_key() {
    let (h, j) = pair(true).await;
    let (h, j) = (h.expect("host paired"), j.expect("joiner paired"));
    assert_eq!(*h.session_key, *j.session_key);
    assert_eq!(
        h.peer_id,
        *SecretKey::from_bytes(&[2; 32]).public().as_bytes()
    );
    assert_eq!(
        j.peer_id,
        *SecretKey::from_bytes(&[1; 32]).public().as_bytes()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_code_fails_on_both_sides() {
    let (h, j) = pair(false).await;
    assert_eq!(h.map(|_| ()), Err(PairError::Mismatch));
    assert!(j.is_err());
}
