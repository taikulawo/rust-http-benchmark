use std::{
    io::{self, Cursor},
    sync::Arc,
};

use crate::{echo, CERT, KEY};
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ALL_VERSIONS};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}
pub(super) async fn run_server(incoming: TcpListener) -> anyhow::Result<()> {
    #[cfg(feature = "aws-lc-rs")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    // set file limits
    let li = libc::rlimit {
        rlim_cur: 1000000,
        rlim_max: 1000000,
    };
    unsafe {
        if libc::setrlimit(libc::RLIMIT_NOFILE, &li) == -1 {
            panic!("setrlimit error")
        }
    };

    fn load_certs() -> io::Result<Vec<CertificateDer<'static>>> {
        let mut reader = io::BufReader::new(Cursor::new(CERT));
        rustls_pemfile::certs(&mut reader).collect()
    }

    fn load_private_key() -> io::Result<PrivateKeyDer<'static>> {
        let mut reader = io::BufReader::new(Cursor::new(KEY));
        rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap())
    }

    let certs = load_certs()?;
    let key = load_private_key()?;

    println!("serve tls server on {}", incoming.local_addr().unwrap());

    let server_config = ServerConfig::builder_with_protocol_versions(ALL_VERSIONS)
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| error(e.to_string()))?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
    let service = service_fn(echo);
    loop {
        let (tcp_stream, _remote_addr) = match incoming.accept().await {
            Ok(x) => x,
            Err(err) => {
                eprintln!("tcp accept error: {err:#}");
                continue;
            }
        };
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let s = match tls_acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => tls_stream,
                Err(err) => {
                    eprintln!("failed to perform tls handshake: {err:#}");
                    return;
                }
            };
            let mut h1 = http1::Builder::new();
            h1.keep_alive(false);
            let _ = h1.serve_connection(TokioIo::new(s), service).await;
        });
    }
}
