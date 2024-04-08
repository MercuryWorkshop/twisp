use std::{error::Error, ffi::OsString, net::SocketAddr, result};

use bytes::Bytes;
use clap::Parser;
use fastwebsockets::{upgrade, FragmentCollectorRead, WebSocketError};
use futures_util::TryFutureExt;
use http_body_util::Empty;
use hyper::{body::Incoming, server::conn::http1, service::service_fn, Request, Response};
use hyper_util::rt::TokioIo;
use log::{error, info};
use pty_process::{Command, Pty, Size};
use tokio::{io::copy_bidirectional, net::TcpListener};
use wisp_mux::{CloseReason, ConnectPacket, MuxStream, ServerMux, StreamType};

type Result<T> = std::result::Result<T, Box<dyn Error + Sync + Send>>;

#[derive(Debug, Parser)]
struct Cli {
    #[clap(short, long)]
    bind: SocketAddr,
}

async fn handle_mux(connect: ConnectPacket, mut stream: MuxStream) -> Result<()> {
    if connect.stream_type == StreamType::Tcp {
        let mut stream = stream.into_io().into_asyncrw();
        let mut pty = Pty::new()?;
        let pts = pty.pts()?;
        pty.resize(Size::new(24, 80))?;
        let args: Vec<OsString> = connect
            .destination_hostname
            .split(' ')
            .map(|x| x.to_string().into())
            .collect();
        let mut cmd = Command::new(&args[0]).args(&args[1..]).spawn(&pts)?;
        if let Err(err) = copy_bidirectional(&mut stream, &mut pty).await {
            error!("Failed to proxy to pty: {:?}", err);
        }
        cmd.wait().await?;
    } else {
        stream
            .close(CloseReason::ServerStreamBlockedAddress)
            .await?;
    }
    Ok(())
}

async fn handle(fut: upgrade::UpgradeFut) -> Result<()> {
    let (rx, tx) = fut.await?.split(tokio::io::split);
    let rx = FragmentCollectorRead::new(rx);

    let (mut server, fut) = ServerMux::new(rx, tx, u32::MAX);

    tokio::spawn(fut);

    while let Some((connect, stream)) = server.server_new_stream().await {
        tokio::spawn(async move {
            let mut close_err = stream.get_close_handle();
            let mut close_ok = stream.get_close_handle();
            let _ = handle_mux(connect, stream)
                .or_else(|err| async move {
                    let _ = close_err.close(CloseReason::Unexpected).await;
                    Err(err)
                })
                .and_then(|_| async move { Ok(close_ok.close(CloseReason::Voluntary).await?) })
                .await;
        });
    }

    Ok(())
}

async fn upgrade(req: Request<Incoming>) -> result::Result<Response<Empty<Bytes>>, WebSocketError> {
    let (response, fut) = upgrade::upgrade(req)?;
    tokio::spawn(async move {
        if let Err(err) = handle(fut).await {
            error!("Failed to handle connection: {:?}", err);
        }
    });
    Ok(response)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Cli::parse();

    let listener = TcpListener::bind(&args.bind).await?;
    info!("Server started on {}", args.bind);

    while let Ok((stream, addr)) = listener.accept().await {
        info!("{} connected", addr);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let fut = http1::Builder::new()
                .serve_connection(io, service_fn(upgrade))
                .with_upgrades();
            if let Err(err) = fut.await {
                error!("Failed to serve connection to {}: {:?}", addr, err);
            }
        });
    }
    Ok(())
}
