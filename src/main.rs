#[cfg(not(target_os = "linux"))]
compile_error!("This management-only service currently targets Linux.");

use gravenlace_management::{AppState, router, validate_token};
use std::env;
use std::fs::File;
use std::future::IntoFuture;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::oneshot;
use tokio::time::timeout;

const IO_LIMIT: Duration = Duration::from_secs(2);

struct Config {
    bind: SocketAddr,
    token: String,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn load_config() -> io::Result<Config> {
    let bind: SocketAddr = env::var("GRAVENLACE_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8000".to_owned())
        .parse()
        .map_err(|_| invalid("GRAVENLACE_BIND must be an IP address and port"))?;
    if !bind.ip().is_loopback() && env::var("GRAVENLACE_ALLOW_NON_LOOPBACK").as_deref() != Ok("1") {
        return Err(invalid("non-loopback binding requires an explicit opt-in"));
    }
    let path = env::var("GRAVENLACE_TOKEN_FILE")
        .map_err(|_| invalid("GRAVENLACE_TOKEN_FILE is required"))?;
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(invalid("token must be a regular file with private permissions"));
    }
    let mut raw = String::new();
    file.take(1025).read_to_string(&mut raw)?;
    if raw.len() > 1024 {
        return Err(invalid("token file is too large"));
    }
    Ok(Config { bind, token: validate_token(&raw).map_err(invalid)? })
}

async fn run_server() -> io::Result<()> {
    let config = load_config()?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let listener = TcpListener::bind(config.bind).await?;
    let state = AppState::new(config.token);
    let app = router(state.clone());
    let (notifier, mut stopping) = oneshot::channel();
    let shutdown = async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
        state.stopping.store(true, Ordering::Relaxed);
        eprintln!("{{\"event\":\"shutdown_started\"}}");
        let _ = notifier.send(());
    };
    eprintln!("{{\"event\":\"started\",\"scope\":\"management-only\"}}");
    let server = axum::serve(listener, app).with_graceful_shutdown(shutdown).into_future();
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => result?,
        _ = &mut stopping => {
            timeout(Duration::from_secs(8), &mut server).await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "shutdown drain deadline exceeded"))??;
        }
    }
    eprintln!("{{\"event\":\"shutdown_complete\"}}");
    Ok(())
}

fn health_check() -> io::Result<()> {
    let address: SocketAddr = env::var("GRAVENLACE_HEALTH_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8000".to_owned())
        .parse()
        .map_err(|_| invalid("invalid health-check address"))?;
    if !address.ip().is_loopback() {
        return Err(invalid("health-check address must be loopback"));
    }
    let mut stream = TcpStream::connect_timeout(&address, IO_LIMIT)?;
    stream.set_read_timeout(Some(IO_LIMIT))?;
    stream.set_write_timeout(Some(IO_LIMIT))?;
    stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut status = String::new();
    BufReader::new(stream.take(256)).read_line(&mut status)?;
    if !status.starts_with("HTTP/1.1 200 ") {
        return Err(invalid("health check failed"));
    }
    Ok(())
}

async fn run() -> io::Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [] => run_server().await,
        [arg] if arg == "--health-check" => health_check(),
        [arg] if arg == "--check-config" => {
            let _config = load_config()?;
            println!("configuration valid");
            Ok(())
        }
        [arg] if arg == "--help" => {
            println!("gravenlace-management [--check-config | --health-check | --help]");
            Ok(())
        }
        _ => Err(invalid("unsupported arguments; use --help")),
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("gravenlace-management: {error}");
            ExitCode::FAILURE
        }
    }
}
