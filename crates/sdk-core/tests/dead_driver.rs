//! A session whose driver ends before the protocol is over fails the step in
//! progress, whichever step that is.

use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use futures::io::{AsyncRead, AsyncWrite};
use tlsn_sdk_core::{HttpRequest, ProverConfig, ProverMode, Reveal, SdkError, SdkProver};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

/// A transport that can be cut from outside: once cut, every read and write
/// fails with `BrokenPipe`, the way a dropped network connection does.
struct Cuttable {
    inner: Compat<tokio::io::DuplexStream>,
    cut: Arc<AtomicBool>,
}

impl Cuttable {
    fn new(io: tokio::io::DuplexStream) -> (Self, Arc<AtomicBool>) {
        let cut = Arc::new(AtomicBool::new(false));
        (
            Self {
                inner: io.compat(),
                cut: Arc::clone(&cut),
            },
            cut,
        )
    }

    fn broken(&self) -> Option<std::io::Error> {
        self.cut
            .load(Ordering::Acquire)
            .then(|| std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    }
}

impl AsyncRead for Cuttable {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        if let Some(error) = self.broken() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Cuttable {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if let Some(error) = self.broken() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

/// The verifier side of a session, low level so the test can end it the way
/// a notary that drops a session does: the accepted verifier and the driver
/// go, and the transport with them.
struct Peer {
    driver: tokio::task::JoinHandle<tlsn::Result<Compat<tokio::io::DuplexStream>>>,
}

impl Peer {
    fn leave(self) {
        self.driver.abort();
    }
}

fn request() -> HttpRequest {
    HttpRequest::get(format!("https://{SERVER_DOMAIN}/bytes?size=16"))
        .header("Host", SERVER_DOMAIN)
        .header("Connection", "close")
}

fn verifier_config() -> tlsn::config::verifier::VerifierConfig {
    tlsn::config::verifier::VerifierConfig::builder()
        .root_store(tlsn::webpki::RootCertStore {
            roots: vec![tlsn::webpki::CertificateDer(CA_CERT_DER.to_vec())],
        })
        .build()
        .unwrap()
}

/// A prover through setup against a verifier that accepted it, the prover's
/// transport cuttable. `run` takes the verifier through the request as well,
/// with the target fixture behind it.
async fn session(run: bool) -> (SdkProver, Peer, Arc<AtomicBool>) {
    let (prover_io, verifier_io) = tokio::io::duplex(1 << 17);
    let (prover_io, cut) = Cuttable::new(prover_io);

    let mut v_session = tlsn::Session::new(verifier_io.compat());
    let verifier = v_session.new_verifier(verifier_config()).unwrap();
    let (v_driver, _v_handle) = v_session.split();
    let driver = tokio::spawn(v_driver);

    let prover_config = ProverConfig::builder(SERVER_DOMAIN)
        .mode(ProverMode::Proxy)
        .root_certs(vec![CA_CERT_DER.to_vec()])
        .build()
        .unwrap();
    let mut prover = SdkProver::new(prover_config).unwrap();

    let (setup, verifier) = tokio::join!(prover.setup(prover_io), async {
        let tlsn::verifier::VerifierCommitStart::Proxy(verifier) = verifier.commit().await.unwrap()
        else {
            panic!("proxy mode expected");
        };
        verifier.accept().await.unwrap()
    });
    setup.unwrap();

    if run {
        let (server_io, target_io) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            let _ = tlsn_server_fixture::bind(target_io.compat()).await;
        });
        let (response, verifier) = tokio::join!(
            prover.send_request_proxy(request()),
            verifier.run(server_io.compat())
        );
        assert_eq!(response.unwrap().status, 200);
        drop(verifier.unwrap());
    } else {
        drop(verifier);
    }
    (prover, Peer { driver }, cut)
}

async fn reveal_within(prover: &mut SdkProver, wait: Duration) -> SdkError {
    let transcript = prover.transcript().unwrap();
    let reveal = Reveal::new()
        .sent(0..transcript.sent.len())
        .recv(0..transcript.recv.len());
    tokio::time::timeout(wait, prover.reveal(reveal, None))
        .await
        .expect("reveal kept waiting after the session ended")
        .unwrap_err()
}

async fn request_within(prover: &mut SdkProver, wait: Duration) -> SdkError {
    tokio::time::timeout(wait, prover.send_request_proxy(request()))
        .await
        .expect("the request kept waiting after the session ended")
        .unwrap_err()
}

/// The verifier drops the session after setup: its transport goes, the
/// prover's driver ends, and the request fails instead of waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_fails_when_the_peer_left() {
    let (mut prover, peer, _cut) = session(false).await;
    peer.leave();
    let error = request_within(&mut prover, Duration::from_secs(5)).await;
    assert!(
        !error.to_string().is_empty(),
        "the request failed without a reason"
    );
}

/// The prover's transport breaks after setup: the request fails instead of
/// waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_fails_when_the_transport_broke() {
    let (mut prover, _peer, cut) = session(false).await;
    cut.store(true, Ordering::Release);
    let error = request_within(&mut prover, Duration::from_secs(5)).await;
    assert!(
        !error.to_string().is_empty(),
        "the request failed without a reason"
    );
}

/// The verifier drops the session after the request: the reveal fails
/// instead of waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reveal_fails_when_the_peer_left() {
    let (mut prover, peer, _cut) = session(true).await;
    peer.leave();
    let error = reveal_within(&mut prover, Duration::from_secs(5)).await;
    assert!(
        !error.to_string().is_empty(),
        "reveal failed without a reason"
    );
}

/// The prover's transport breaks after the request: the reveal fails instead
/// of waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reveal_fails_when_the_transport_broke() {
    let (mut prover, _peer, cut) = session(true).await;
    cut.store(true, Ordering::Release);
    let error = reveal_within(&mut prover, Duration::from_secs(5)).await;
    assert!(
        !error.to_string().is_empty(),
        "reveal failed without a reason"
    );
}

/// The verifier drops the session while setup is in flight: the prover's
/// setup fails instead of waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_fails_when_the_peer_left_during_it() {
    let (prover_io, verifier_io) = tokio::io::duplex(1 << 17);
    let mut v_session = tlsn::Session::new(verifier_io.compat());
    let verifier = v_session.new_verifier(verifier_config()).unwrap();
    let (v_driver, _v_handle) = v_session.split();
    let driver = tokio::spawn(v_driver);

    let prover_config = ProverConfig::builder(SERVER_DOMAIN)
        .mode(ProverMode::Proxy)
        .root_certs(vec![CA_CERT_DER.to_vec()])
        .build()
        .unwrap();
    let mut prover = SdkProver::new(prover_config).unwrap();

    // The verifier starts its commit, then leaves before the prover's is done.
    let leaving = tokio::spawn(async move {
        // The commit future is dropped with the timeout, mid-protocol.
        let _ = tokio::time::timeout(Duration::from_millis(200), verifier.commit()).await;
        driver.abort();
    });
    let error = tokio::time::timeout(Duration::from_secs(5), prover.setup(prover_io.compat()))
        .await
        .expect("setup kept waiting after the session ended")
        .unwrap_err();
    leaving.await.unwrap();
    assert!(
        !error.to_string().is_empty(),
        "setup failed without a reason"
    );
}

/// The prover's transport breaks while setup is in flight: setup fails
/// instead of waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_fails_when_the_transport_broke_during_it() {
    let (prover_io, verifier_io) = tokio::io::duplex(1 << 17);
    let (prover_io, cut) = Cuttable::new(prover_io);
    let mut v_session = tlsn::Session::new(verifier_io.compat());
    let verifier = v_session.new_verifier(verifier_config()).unwrap();
    let (v_driver, _v_handle) = v_session.split();
    let _driver = tokio::spawn(v_driver);

    let prover_config = ProverConfig::builder(SERVER_DOMAIN)
        .mode(ProverMode::Proxy)
        .root_certs(vec![CA_CERT_DER.to_vec()])
        .build()
        .unwrap();
    let mut prover = SdkProver::new(prover_config).unwrap();

    let breaking = tokio::spawn(async move {
        let _ = tokio::time::timeout(Duration::from_millis(200), verifier.commit()).await;
        cut.store(true, Ordering::Release);
    });
    let error = tokio::time::timeout(Duration::from_secs(5), prover.setup(prover_io))
        .await
        .expect("setup kept waiting after the transport broke")
        .unwrap_err();
    breaking.await.unwrap();
    assert!(
        !error.to_string().is_empty(),
        "setup failed without a reason"
    );
}
