//! The code exchange over an iroh QUIC connection (feature `iroh`).
//!
//! iroh's TLS proves each side holds the secret key for its endpoint id, so
//! the ids fed into [`CodeExchange`] are authenticated by the transport and
//! the code proves the human intended this pairing.
//!
//! Wire, on one bidirectional stream opened by the joiner:
//! `PAKE msg (33) ->`, `<- PAKE msg (33)`, `tag (32) ->`, `<- tag (32)`.

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr};
use zeroize::Zeroizing;

use crate::exchange::CONFIRM_LEN;
use crate::{CodeExchange, PAKE_MSG_LEN, PairError, PairingWindow};

/// ALPN for the pairing protocol. Use it on a dedicated endpoint, or add it
/// to your endpoint's ALPN list next to your application protocol.
pub const ALPN: &[u8] = b"device-pairing/1";

/// Result of a successful pairing.
#[derive(Debug)]
pub struct Paired {
    /// The peer's endpoint id bytes, authenticated by TLS and the code.
    pub peer_id: [u8; 32],
    /// Shared 32-byte key from the exchange.
    pub session_key: Zeroizing<[u8; 32]>,
}

fn net<E: std::fmt::Display>(e: E) -> PairError {
    PairError::Network(e.to_string())
}

async fn read_exact<const N: usize>(recv: &mut RecvStream) -> Result<[u8; N], PairError> {
    let mut buf = [0u8; N];
    recv.read_exact(&mut buf).await.map_err(net)?;
    Ok(buf)
}

async fn run(
    local: [u8; 32],
    remote: [u8; 32],
    code: &str,
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<Zeroizing<[u8; 32]>, PairError> {
    let x = CodeExchange::start(code, &local, &remote);
    send.write_all(x.message()).await.map_err(net)?;
    let peer_msg: [u8; PAKE_MSG_LEN] = read_exact(recv).await?;
    let confirmed = x.finish(&peer_msg)?;
    send.write_all(&confirmed.tag()).await.map_err(net)?;
    let peer_tag: [u8; CONFIRM_LEN] = read_exact(recv).await?;
    confirmed.verify_peer(&peer_tag)
}

/// Joiner side: dial the host and run the exchange with the code the user typed.
///
/// # Errors
/// [`PairError::Mismatch`] for a wrong code, [`PairError::Network`] for transport failures.
pub async fn join(
    endpoint: &Endpoint,
    host: EndpointAddr,
    code: &str,
) -> Result<Paired, PairError> {
    let conn = endpoint.connect(host, ALPN).await.map_err(net)?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(net)?;
    let local = *endpoint.id().as_bytes();
    let remote = *conn.remote_id().as_bytes();
    let key = run(local, remote, code, &mut send, &mut recv).await;
    let _ = send.finish();
    // Wait for the host to finish its side before dropping the connection, on
    // success and on failure: otherwise a mismatch races the host's read of our
    // tag and the host reports "connection lost" instead of a mismatch.
    let _ = recv.read_to_end(64).await;
    Ok(Paired {
        peer_id: remote,
        session_key: key?,
    })
}

/// Host side: run the exchange on an accepted connection against the open
/// window. The window is consumed by this call, whatever the outcome.
///
/// # Errors
/// [`PairError::Consumed`], [`PairError::Expired`], [`PairError::Mismatch`] or [`PairError::Network`].
pub async fn accept(
    endpoint: &Endpoint,
    conn: Connection,
    window: &mut PairingWindow,
) -> Result<Paired, PairError> {
    let code = window.begin_attempt();
    let (mut send, mut recv) = conn.accept_bi().await.map_err(net)?;
    let code = match code {
        Ok(c) => c,
        Err(e) => {
            conn.close(1u32.into(), b"window closed");
            return Err(e);
        }
    };
    let local = *endpoint.id().as_bytes();
    let remote = *conn.remote_id().as_bytes();
    let key = run(local, remote, &code, &mut send, &mut recv).await;
    let _ = send.finish();
    let _ = send.stopped().await;
    match key {
        Ok(session_key) => Ok(Paired {
            peer_id: remote,
            session_key,
        }),
        Err(e) => {
            conn.close(2u32.into(), b"pairing failed");
            Err(e)
        }
    }
}
