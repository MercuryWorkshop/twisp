mod pty;

use std::{
	collections::HashMap,
	error::Error,
	ffi::OsString,
	net::SocketAddr,
	os::fd::{AsRawFd, RawFd},
	path::PathBuf,
	result,
	sync::Arc,
};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use clap::{Args, Parser};
use fastwebsockets::{upgrade, FragmentCollectorRead, WebSocketError};
use http_body_util::Empty;
use hyper::{body::Incoming, server::conn::http1, service::service_fn, Request, Response};
use hyper_util::rt::TokioIo;
use log::{error, info, LevelFilter};
use pty_process::{Command, Pty, Size};
use tokio::{io::copy, net::TcpListener, select, sync::Mutex};
use tokio_util::compat::{FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt};
use wisp_mux::{
	extensions::{AnyProtocolExtension, ProtocolExtension, ProtocolExtensionBuilder},
	ws::{LockedWebSocketWrite, WebSocketRead},
	CloseReason, ConnectPacket, MuxStream, ServerMux, StreamType, WispError,
};

type Result<T> = std::result::Result<T, Box<dyn Error + Sync + Send>>;

/// Wisp protocol server that exposes PTYs over the Wisp connection.
#[derive(Debug, Parser)]
#[command(version = clap::crate_version!())]
struct Cli {
	#[clap(flatten)]
	backend: Backend,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct Backend {
	/// PTY device to multiplex over
	#[arg(short, long)]
	pty: Option<PathBuf>,
	/// Socket to bind to
	#[arg(short, long)]
	bind: Option<SocketAddr>,
}

const STREAM_TYPE_TERM: u8 = 0x03;

#[derive(Debug, Clone)]
struct TWispServerProtocolExtension(Arc<Mutex<HashMap<u32, RawFd>>>);

impl TWispServerProtocolExtension {
	const ID: u8 = 0xF0;
}

#[async_trait]
impl ProtocolExtension for TWispServerProtocolExtension {
	fn get_id(&self) -> u8 {
		Self::ID
	}

	fn get_supported_packets(&self) -> &'static [u8] {
		// Resize PTY
		&[0xF0]
	}

	fn encode(&self) -> Bytes {
		Bytes::new()
	}

	async fn handle_handshake(
		&mut self,
		_: &mut dyn WebSocketRead,
		_: &LockedWebSocketWrite,
	) -> std::result::Result<(), WispError> {
		Ok(())
	}

	async fn handle_packet(
		&mut self,
		mut packet: Bytes,
		_: &mut dyn WebSocketRead,
		_: &LockedWebSocketWrite,
	) -> std::result::Result<(), WispError> {
		if packet.remaining() < 4 + 2 + 2 {
			return Err(WispError::PacketTooSmall);
		}
		let stream_id = packet.get_u32_le();
		let row = packet.get_u16_le();
		let col = packet.get_u16_le();

		info!(
			"received request to resize stream_id {:?} to {}x{}",
			stream_id, row, col
		);

		if let Some(pty) = self.0.lock().await.get(&stream_id) {
			if let Err(err) = set_term_size(*pty, Size::new(row, col)) {
				error!("Failed to resize stream_id {:?}: {:?}", stream_id, err);
			}
		}
		Ok(())
	}

	fn box_clone(&self) -> Box<dyn ProtocolExtension + Sync + Send> {
		Box::new(self.clone())
	}
}

impl From<TWispServerProtocolExtension> for AnyProtocolExtension {
	fn from(value: TWispServerProtocolExtension) -> Self {
		AnyProtocolExtension::new(value)
	}
}

struct TWispServerProtocolExtensionBuilder(Arc<Mutex<HashMap<u32, RawFd>>>);

impl ProtocolExtensionBuilder for TWispServerProtocolExtensionBuilder {
	fn get_id(&self) -> u8 {
		TWispServerProtocolExtension::ID
	}

	fn build_from_bytes(
		&self,
		_: Bytes,
		_: wisp_mux::Role,
	) -> std::result::Result<AnyProtocolExtension, WispError> {
		Ok(TWispServerProtocolExtension(self.0.clone()).into())
	}

	fn build_to_extension(&self, _: wisp_mux::Role) -> AnyProtocolExtension {
		TWispServerProtocolExtension(self.0.clone()).into()
	}
}

fn set_term_size(fd: RawFd, size: Size) -> Result<()> {
	let size = libc::winsize::from(size);
	let ret = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, std::ptr::addr_of!(size)) };
	if ret == -1 {
		Err(rustix::io::Errno::from_raw_os_error(
			std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
		)
		.into())
	} else {
		Ok(())
	}
}

async fn handle_muxstream(
	connect: ConnectPacket,
	stream: MuxStream,
	map: Arc<Mutex<HashMap<u32, RawFd>>>,
) {
	if connect.stream_type != StreamType::Unknown(STREAM_TYPE_TERM) {
		let _ = stream.close(CloseReason::ServerStreamBlockedAddress).await;
	}
	let closer = stream.get_close_handle();
	let id = stream.stream_id;
	let stream = stream.into_io().into_asyncrw();
	let ret: Result<()> = async {
		let mut pty = Pty::new()?;
		let pts = pty.pts()?;
		pty.resize(Size::new(24, 80))?;
		let args: Vec<OsString> = shell_words::split(&connect.destination_hostname)?
			.iter()
			.map(|x| x.into())
			.collect();
		map.lock().await.insert(id, pty.as_raw_fd());
		let mut cmd = Command::new(&args[0]).args(&args[1..]).spawn(&pts)?;

		let (mut ptyrx, mut ptytx) = pty.split();
		let (streamrx, streamtx) = stream.into_split();
		let mut streamrx = streamrx.compat();
		let mut streamtx = streamtx.compat_write();

		select! {
			x = copy(&mut ptyrx, &mut streamtx) => x.map(|_| {}),
			x = copy(&mut streamrx, &mut ptytx) => x.map(|_| {}),
			x = cmd.wait() => x.map(|_| {}),
		}?;
		let _ = cmd.kill().await;
		Ok(())
	}
	.await;
	match ret {
		Ok(_) => {
			let _ = closer.close(CloseReason::Voluntary).await;
		}
		Err(x) => {
			error!("error while creating pty: {:?}", x);
			let _ = closer.close(CloseReason::Unexpected).await;
		}
	}
}

async fn handle_mux(server: ServerMux, map: Arc<Mutex<HashMap<u32, RawFd>>>) -> Result<()> {
	while let Some((connect, stream)) = server.server_new_stream().await {
		let map = map.clone();
		tokio::spawn(async move {
			let id = stream.stream_id;
			handle_muxstream(connect, stream, map.clone()).await;
			map.lock().await.remove(&id);
		});
	}
	Ok(())
}

async fn handle_ws(fut: upgrade::UpgradeFut) -> Result<()> {
	let (rx, tx) = fut.await?.split(tokio::io::split);
	let rx = FragmentCollectorRead::new(rx);

	let map = Arc::new(Mutex::new(HashMap::new()));

	let (mux, fut) = ServerMux::create(
		rx,
		tx,
		u32::MAX,
		Some(&[Box::new(TWispServerProtocolExtensionBuilder(map.clone()))]),
	)
	.await?
	.with_required_extensions(&[TWispServerProtocolExtension::ID])
	.await?;

	tokio::spawn(fut);

	handle_mux(mux, map).await
}

async fn upgrade_ws(
	req: Request<Incoming>,
) -> result::Result<Response<Empty<Bytes>>, WebSocketError> {
	let (response, fut) = upgrade::upgrade(req)?;
	tokio::spawn(async move {
		if let Err(err) = handle_ws(fut).await {
			error!("Failed to handle connection: {:?}", err);
		}
	});
	Ok(response)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
	env_logger::Builder::new()
		.filter_level(LevelFilter::Info)
		.parse_env("RUST_LOG")
		.init();
	let args = Cli::parse();

	if let Some(bind) = args.backend.bind {
		let listener = TcpListener::bind(&bind).await?;
		info!("Server started on {}", bind);

		while let Ok((stream, addr)) = listener.accept().await {
			info!("{} connected", addr);
			tokio::spawn(async move {
				let io = TokioIo::new(stream);
				let fut = http1::Builder::new()
					.serve_connection(io, service_fn(upgrade_ws))
					.with_upgrades();
				if let Err(err) = fut.await {
					error!("Failed to serve connection to {}: {:?}", addr, err);
				}
			});
		}
	} else if let Some(pty) = args.backend.pty {
		let (rx, tx) = pty::open_pty(&pty).await?;

		let map = Arc::new(Mutex::new(HashMap::new()));

		let (mux, fut) = ServerMux::create(
			rx,
			tx,
			u32::MAX,
			Some(&[Box::new(TWispServerProtocolExtensionBuilder(map.clone()))]),
		)
		.await?
		.with_required_extensions(&[TWispServerProtocolExtension::ID])
		.await?;

		tokio::spawn(fut);

		info!("Connected to pty {:?}", pty);

		handle_mux(mux, map).await?;
	} else {
		unreachable!("neither bind nor pty specified");
	}
	Ok(())
}
