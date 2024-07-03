use std::net::SocketAddr;
use std::{env, io};

use anyhow::bail;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use socket2::{Domain, Type};
use tokio::net::TcpListener;
#[cfg(all(feature = "ossl", not(feature = "rustls")))]
mod ossl;
#[cfg(feature = "rustls")]
mod rustls;
#[cfg(all(not(target_env = "msvc"), feature = "jemallocator"))]
use jemallocator::Jemalloc;

#[cfg(all(not(target_env = "msvc"), feature = "jemallocator"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

static CERT: &[u8] = include_bytes!("../certs/www.example.org.full.cert.pem");
static KEY: &[u8] = include_bytes!("../certs/www.example.org.full.key.pem");

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
            {
                use rustls::run_server;
                run_server(listener).await.unwrap();
            }
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
pub const DEFAULT_CIPHER: &str = "HIGH:!aNULL:!MD5";
pub const DEFAULT_TLS12_CIPHER: &str = DEFAULT_CIPHER;
pub const DEFAULT_TLS13_CIPHER: &str = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384";

async fn echo(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let mut response = Response::default();
    *response.status_mut() = StatusCode::OK;
    Ok(response)
}
