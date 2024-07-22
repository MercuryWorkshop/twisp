use std::{error::Error, future::Future, time::Duration};

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
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
	time::sleep,
};
use wisp_mux::{
	extensions::{AnyProtocolExtension, ProtocolExtension, ProtocolExtensionBuilder},
	ws::{LockedWebSocketWrite, WebSocketRead},
	ClientMux, StreamType, WispError,
};

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
		let _ =
			nix::sys::termios::tcsetattr(stdin, nix::sys::termios::SetArg::TCSANOW, &self.termios);
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

const STREAM_TYPE_TERM: u8 = 0x03;

#[derive(Debug)]
struct TWispClientProtocolExtension();

impl TWispClientProtocolExtension {
	const ID: u8 = 0xF0;

	fn create_resize_request(rows: u16, cols: u16) -> Bytes {
		let mut packet = BytesMut::with_capacity(4);
		packet.put_u16_le(rows);
		packet.put_u16_le(cols);
		packet.freeze()
	}
}

#[async_trait]
impl ProtocolExtension for TWispClientProtocolExtension {
	fn get_id(&self) -> u8 {
		Self::ID
	}

	fn get_supported_packets(&self) -> &'static [u8] {
		&[]
	}

	fn encode(&self) -> Bytes {
		Bytes::new()
	}

	async fn handle_handshake(
		&mut self,
		_: &mut dyn WebSocketRead,
		_: &LockedWebSocketWrite,
	) -> Result<(), WispError> {
		Ok(())
	}

	async fn handle_packet(
		&mut self,
		_: Bytes,
		_: &mut dyn WebSocketRead,
		_: &LockedWebSocketWrite,
	) -> Result<(), WispError> {
		Ok(())
	}

	fn box_clone(&self) -> Box<dyn ProtocolExtension + Sync + Send> {
		Box::new(TWispClientProtocolExtension())
	}
}

struct TWispClientProtocolExtensionBuilder();

impl ProtocolExtensionBuilder for TWispClientProtocolExtensionBuilder {
	fn get_id(&self) -> u8 {
		TWispClientProtocolExtension::ID
	}

	fn build_from_bytes(
		&self,
		_: Bytes,
		_: wisp_mux::Role,
	) -> Result<AnyProtocolExtension, WispError> {
		Ok(AnyProtocolExtension::new(TWispClientProtocolExtension()))
	}

	fn build_to_extension(&self, _: wisp_mux::Role) -> AnyProtocolExtension {
		AnyProtocolExtension::new(TWispClientProtocolExtension())
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
		.body(Empty::<Bytes>::new())?;

	let (ws, _) = handshake::client(&SpawnExecutor, req, socket).await?;

	let (rx, tx) = ws.split(tokio::io::split);
	let rx = FragmentCollectorRead::new(rx);

	let (mux, fut) = ClientMux::create(
		rx,
		tx,
		Some(&[Box::new(TWispClientProtocolExtensionBuilder())]),
	)
	.await?
	.with_required_extensions(&[TWispClientProtocolExtension::ID])
	.await?;

	tokio::spawn(async move { dbg!(fut.await) });

	let stream = mux
		.client_new_stream(
			StreamType::Unknown(STREAM_TYPE_TERM),
			"/bin/fish".to_owned(),
			0,
		)
		.await?;
	let pext_stream = stream.get_protocol_extension_stream();
	let stream = stream.into_io().into_asyncrw();

	let (mut rx, mut tx) = split(stream);

	let mut handles = Vec::new();

	let _rawguard = RawGuard::new();

	tokio::spawn(async move {
		sleep(Duration::from_secs(5)).await;
		pext_stream
			.send(
				0xF0,
				TWispClientProtocolExtension::create_resize_request(100, 100),
			)
			.await
	});

	handles.push(tokio::spawn(async move {
		copy(&mut rx, &mut tokio::io::stdout()).await
	}));

	handles.push(tokio::spawn(async move {
		copy(&mut tokio::io::stdin(), &mut tx).await
	}));

	Ok(select_all(handles.into_iter()).await.0.map(|_| ())?)
}
