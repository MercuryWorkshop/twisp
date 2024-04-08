use std::{error::Error, future::Future};

use bytes::Bytes;
use fastwebsockets::{handshake, FragmentCollectorRead};
use futures::future::select_all;
use http_body_util::Empty;
use hyper::{
    header::{CONNECTION, UPGRADE},
    Request,
};
use tokio::{
    io::{copy, split},
    net::TcpStream,
};
use wisp_mux::{ClientMux, StreamType};

pub struct RawGuard {
    termios: nix::sys::termios::Termios,
}

impl Default for RawGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl RawGuard {
    pub fn new() -> Self {
        let termios = nix::sys::termios::tcgetattr(std::io::stdin()).unwrap();
        let mut termios_raw = termios.clone();
        nix::sys::termios::cfmakeraw(&mut termios_raw);
        nix::sys::termios::tcsetattr(
            std::io::stdin(),
            nix::sys::termios::SetArg::TCSANOW,
            &termios_raw,
        )
        .unwrap();
        Self { termios }
    }
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        let stdin = std::io::stdin();
        let _ = nix::sys::termios::tcsetattr(
            stdin,
            nix::sys::termios::SetArg::TCSANOW,
            &self.termios,
        );
    }
}

struct SpawnExecutor;

impl<Fut> hyper::rt::Executor<Fut> for SpawnExecutor
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    fn execute(&self, fut: Fut) {
        tokio::task::spawn(fut);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Sync + Send>> {
    let socket = TcpStream::connect("127.0.0.1:4000").await?;

    let req = Request::builder()
        .method("GET")
        .uri("/")
        .header("Host", "127.0.0.1")
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "upgrade")
        .header(
            "Sec-WebSocket-Key",
            fastwebsockets::handshake::generate_key(),
        )
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Protocol", "wisp-v1")
        .body(Empty::<Bytes>::new())?;

    let (ws, _) = handshake::client(&SpawnExecutor, req, socket).await?;

    let (rx, tx) = ws.split(tokio::io::split);
    let rx = FragmentCollectorRead::new(rx);

    let (mux, fut) = ClientMux::new(rx, tx).await?;

    tokio::spawn(fut);

    let stream = mux
        .client_new_stream(StreamType::Tcp, "/bin/fish".to_owned(), 0)
        .await?
        .into_io()
        .into_asyncrw();

    let (mut rx, mut tx) = split(stream);

    let mut handles = Vec::new();

    let _rawguard = RawGuard::new();

    handles.push(tokio::spawn(async move {
        copy(&mut rx, &mut tokio::io::stdout()).await
    }));

    handles.push(tokio::spawn(async move {
        copy(&mut tokio::io::stdin(), &mut tx).await
    }));

    Ok(select_all(handles.into_iter()).await.0.map(|_| ())?)
}
