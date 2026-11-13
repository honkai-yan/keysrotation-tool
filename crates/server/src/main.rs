use keyrotation_server::{store::Repository, worker::DbWorker};
use std::{
    io::{self, IsTerminal, Read},
    path::PathBuf,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first().map(String::as_str) else {
        return Err(usage().into());
    };
    if matches!(command, "--help" | "-h") {
        println!("{}", usage());
        return Ok(());
    }
    let mut options = std::collections::BTreeMap::new();
    let mut index = 1;
    while index < args.len() {
        let option = &args[index];
        if option == "--password-stdin" {
            if options.insert(option.as_str(), "").is_some() {
                return Err("duplicate option".into());
            }
            index += 1;
            continue;
        }
        if !matches!(
            option.as_str(),
            "--data-dir"
                | "--username"
                | "--source"
                | "--public-url"
                | "--listen"
                | "--tls-cert"
                | "--tls-key"
        ) {
            return Err(format!("unknown option: {option}").into());
        }
        let value = args
            .get(index + 1)
            .filter(|value| !value.starts_with("--"))
            .ok_or("option needs a value")?;
        if options.insert(option.as_str(), value.as_str()).is_some() {
            return Err("duplicate option".into());
        }
        index += 2;
    }
    let value = |name: &str| -> Result<&str, Box<dyn std::error::Error>> {
        options
            .get(name)
            .copied()
            .ok_or_else(|| format!("missing {name}\n{}", usage()).into())
    };
    let directory = PathBuf::from(value("--data-dir")?);
    match command {
        "init" | "import" | "reset-password" => {
            let username = value("--username")?;
            if !args.iter().any(|arg| arg == "--password-stdin") || io::stdin().is_terminal() {
                return Err("provide password through redirected stdin with --password-stdin; passwords are not accepted in command arguments".into());
            }
            let mut password = zeroize::Zeroizing::new(String::new());
            io::stdin().take(1026).read_to_string(&mut password)?;
            if password.ends_with('\n') {
                password.pop();
                if password.ends_with('\r') {
                    password.pop();
                }
            }
            match command {
                "init" => {
                    Repository::create(&directory, username, &password)?;
                }
                "import" => {
                    Repository::import_legacy(
                        &directory,
                        &PathBuf::from(value("--source")?),
                        username,
                        &password,
                    )?;
                }
                _ => Repository::open(&directory)?.reset_password(username, &password)?,
            }
            if command != "reset-password" {
                keyrotation_server::identity::create(&directory)?;
            }
            println!("{command} completed");
        }
        "public-key" => println!(
            "{}",
            keyrotation_server::identity::load(&directory)?.public_base64()
        ),
        "serve" => {
            use keyrotation_server::{dispatcher, http, identity};
            use keyrotation_transport::Endpoint;
            use std::{net::SocketAddr, sync::Arc};
            let endpoint = Endpoint::parse(value("--public-url")?)?;
            let address: SocketAddr = value("--listen")?.parse()?;
            let dispatch = dispatcher(DbWorker::open(&directory)?);
            let identity = if endpoint.is_http() {
                Some(Arc::new(identity::load(&directory)?))
            } else {
                None
            };
            let is_http = endpoint.is_http();
            let app = http::router(endpoint, identity, dispatch)?;
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(async {
                if is_http {
                    let listener = tokio::net::TcpListener::bind(address).await?;
                    eprintln!("keyrotation-server listening on {address}");
                    axum::serve(listener, app)
                        .with_graceful_shutdown(shutdown_signal())
                        .await?;
                } else {
                    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
                        value("--tls-cert")?,
                        value("--tls-key")?,
                    )
                    .await?;
                    let handle = axum_server::Handle::new();
                    let shutdown = handle.clone();
                    tokio::spawn(async move {
                        shutdown_signal().await;
                        shutdown.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
                    });
                    eprintln!("keyrotation-server listening on {address} (TLS)");
                    axum_server::bind_rustls(address, config)
                        .handle(handle)
                        .serve(app.into_make_service())
                        .await?;
                }
                eprintln!("keyrotation-server stopped");
                Ok::<(), Box<dyn std::error::Error>>(())
            })?;
        }
        "check" => {
            let worker = DbWorker::open(&directory)?;
            worker.call(|repository| repository.check_health())?;
            println!("database healthy");
        }
        _ => return Err(usage().into()),
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

fn usage() -> &'static str {
    "keyrotation-server <init|import|reset-password|check|public-key|serve> --data-dir PATH [--username NAME --password-stdin] [--source LEGACY_DB] [--public-url URL --listen IP:PORT] [--tls-cert PEM --tls-key PEM]"
}
