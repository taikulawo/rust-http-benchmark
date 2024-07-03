use std::io::Cursor;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::{env, io};

use anyhow::{bail, Context};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use openssl::pkey::PKey;
use openssl::ssl::{
    Ssl, SslContext, SslContextBuilder, SslMethod, SslSessionCacheMode, SslVersion,
};
use openssl::x509::X509;
use pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::NoServerSessionStorage;
use rustls::ServerConfig;
use socket2::{Domain, Type};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
#[cfg(all(feature = "ossl", not(feature = "rustls")))]
mod ossl;
#[cfg(all(not(target_env = "msvc"), feature = "jemallocator"))]
use jemallocator::Jemalloc;

#[cfg(all(not(target_env = "msvc"), feature = "jemallocator"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

static CERT: &[u8] = include_bytes!("../certs/www.example.org.full.cert.pem");
static KEY: &[u8] = include_bytes!("../certs/www.example.org.full.key.pem");
fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

fn create_listener_socket(port: usize) -> anyhow::Result<TcpListener> {
    let socket = socket2::Socket::new(Domain::IPV6, Type::STREAM, None)?;
    // enable dual net stack ipv4 and ipv6
    socket.set_nonblocking(true)?;
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nodelay(true)?;
    let s = format!("[::]:{}", port);
    let addr = s.parse::<SocketAddr>()?;
    let addr = addr.into();
    socket.bind(&addr)?;
    socket.listen(65535)?;
    TcpListener::from_std(socket.into()).map_err(anyhow::Error::from)
}

fn spawn_local(port: usize) {
    let mut builder = tokio::runtime::Builder::new_current_thread();
    let runtime = builder.enable_all().build().unwrap();
    runtime
        .block_on(async move {
            let listener = create_listener_socket(port).unwrap();
            #[cfg(feature = "rustls")]
            run_server(listener).await.unwrap();
            #[cfg(all(feature = "ossl", not(feature = "rustls")))]
            {
                use ossl::run_openssl_server;
                run_openssl_server(listener).await.unwrap();
            }
            Ok::<_, io::Error>(())
        })
        .unwrap();
}

fn spawn_worker(port: usize) {
    let count = num_cpus::get();
    for idx in 0..count {
        let mut t = std::thread::Builder::new();
        t = t.name(format!("tls-rustls-server-t{}", idx));
        t.spawn(move || {
            spawn_local(port);
            ()
        })
        .unwrap();
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut it = args.iter();
    let mut port: usize = 0;
    let mut daemon = false;
    while let Some(c) = it.next() {
        match c.as_str() {
            "--port" => {
                if let Some(p) = it.next() {
                    port = p.parse::<usize>().expect("a valid net port number");
                } else {
                    panic!("need --port")
                }
            }
            "--daemon" => daemon = true,
            _ => {}
        }
    }
    if port == 0 {
        panic!("port need")
    }
    dbg!(port);
    dbg!(daemon);
    if daemon {
        make_daemon().unwrap();
    }
    spawn_worker(port);
    spawn_local(port);
}

fn make_daemon() -> anyhow::Result<()> {
    unsafe {
        match libc::fork() {
            0 => {
                // child
            }
            -1 => {
                panic!("fork error");
            }
            _ => {
                // parent
                std::process::exit(0);
            }
        }
        if libc::setsid() == -1 {
            bail!("setsid failed");
        }
        libc::umask(0);
    }
    return Ok(());
}
#[cfg(feature = "rustls")]
async fn run_server(incoming: TcpListener) -> anyhow::Result<()> {
    use rustls::ALL_VERSIONS;

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

    let mut server_config = ServerConfig::builder_with_protocol_versions(ALL_VERSIONS)
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| error(e.to_string()))?;
    // disable tls session cache
    server_config.session_storage = Arc::new(NoServerSessionStorage {});
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
pub const DEFAULT_CIPHER: &str = "HIGH:!aNULL:!MD5";
pub const DEFAULT_TLS12_CIPHER: &str = DEFAULT_CIPHER;
pub const DEFAULT_TLS13_CIPHER: &str = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384";

async fn echo(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let mut response = Response::default();
    *response.status_mut() = StatusCode::OK;
    Ok(response)
}
