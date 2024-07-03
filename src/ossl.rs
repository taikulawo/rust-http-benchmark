use std::{io, pin::Pin, sync::Arc};

use anyhow::bail;
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use openssl::{
    pkey::PKey,
    ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslSessionCacheMode},
    x509::X509,
};
use tokio::net::TcpListener;
use tokio_openssl::SslStream;

use crate::{echo, CERT, DEFAULT_TLS12_CIPHER, DEFAULT_TLS13_CIPHER, KEY};

pub(super) async fn run_openssl_server(incoming: TcpListener) -> anyhow::Result<()> {
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
    println!("serve tls server on {}", incoming.local_addr().unwrap());
    let ctx = create_openssl_config().await.unwrap();
    let service = service_fn(echo);
    loop {
        let (tcp_stream, _remote_addr) = match incoming.accept().await {
            Ok(x) => x,
            Err(err) => {
                eprintln!("tcp accept error: {err:#}");
                continue;
            }
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let mut ssl = Ssl::new(&ctx).unwrap();
            ssl.set_accept_state();
            let mut s = SslStream::new(ssl, tcp_stream).unwrap();
            if let Err(err) = Pin::new(&mut s).do_handshake().await {
                eprintln!("{err}");
                return;
            }
            let mut h1 = http1::Builder::new();
            h1.keep_alive(false);
            let _ = h1.serve_connection(TokioIo::new(s), service).await;
        });
    }
}
pub async fn create_openssl_config() -> anyhow::Result<Arc<SslContext>> {
    let mut builder = SslContext::builder(SslMethod::tls_server())?;
    let (certs, pkey) = (CERT.to_owned(), KEY.to_owned());
    set_cert_and_key(&mut builder, &certs, &pkey)?;
    builder.set_cipher_list(DEFAULT_TLS12_CIPHER)?;
    builder.set_ciphersuites(DEFAULT_TLS13_CIPHER)?;
    builder.set_session_cache_mode(SslSessionCacheMode::BOTH);
    // disable tls1.3 early data
    builder.set_max_early_data(0)?;
    let ctx = builder.build();
    let shared_ctx = Arc::new(ctx);
    Ok(shared_ctx)
}
fn set_cert_and_key(
    builder: &mut SslContextBuilder,
    cert_content: &Vec<u8>,
    key_content: &Vec<u8>,
) -> anyhow::Result<()> {
    let mut cert_contents = vec![];
    let mut r = io::Cursor::new(cert_content);
    for cert in rustls_pemfile::certs(&mut r) {
        match cert {
            Ok(cert) => {
                cert_contents.push(X509::from_der(cert.as_ref())?.to_pem()?);
            }
            Err(err) => {
                bail!("bad certificate {err}");
            }
        }
    }
    for (index, cert) in cert_contents.iter().enumerate() {
        if index == 0 {
            let cert = X509::from_pem(cert)?;
            builder.set_certificate(cert.as_ref())?;
        } else {
            let x509 = X509::from_pem(cert)?;
            builder.add_extra_chain_cert(x509)?;
        }
    }
    let pkey = PKey::private_key_from_pem(key_content)?;
    builder.set_private_key(pkey.as_ref())?;
    Ok(())
}
