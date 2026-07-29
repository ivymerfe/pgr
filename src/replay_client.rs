use std::{
    collections::BTreeMap,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{Sink, Stream, StreamExt};
use pgwire::{
    api::client::{
        ClientInfo, Config, ReadyState, ServerInformation,
        auth::{DefaultStartupHandler, StartupHandler},
    },
    messages::{
        PgWireFrontendMessage,
        ProtocolVersion::{self, PROTOCOL3_2},
    },
    tokio::client::PgWireMessageClientCodec,
};
use pin_project::pin_project;
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::mpsc};
use tokio_util::codec::Framed;
use tracing::{error, info};

type ClientChannel = mpsc::UnboundedSender<Vec<u8>>;

#[pin_project]
struct ReplaySocket {
    #[pin]
    socket: Framed<TcpStream, PgWireMessageClientCodec>,
    config: Arc<Config>,
    server_information: ServerInformation,
}

impl ClientInfo for ReplaySocket {
    fn config(&self) -> &Config {
        &self.config
    }

    fn server_parameters(&self) -> &BTreeMap<String, String> {
        &self.server_information.parameters
    }

    fn process_id(&self) -> i32 {
        self.server_information.process_id
    }

    fn protocol_version(&self) -> ProtocolVersion {
        PROTOCOL3_2
    }
}

impl Sink<PgWireFrontendMessage> for ReplaySocket {
    type Error =
        <Framed<TcpStream, PgWireMessageClientCodec> as Sink<PgWireFrontendMessage>>::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().socket.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: PgWireFrontendMessage) -> Result<(), Self::Error> {
        self.project().socket.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().socket.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().socket.poll_close(cx)
    }
}

impl Stream for ReplaySocket {
    type Item = <Framed<TcpStream, PgWireMessageClientCodec> as Stream>::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().socket.poll_next(cx)
    }
}

pub struct ReplayClient {
    pub tx: ClientChannel,
    pub addr: SocketAddr,
}

pub async fn spawn_client(
    pcap_addr: SocketAddr,
    config: Arc<Config>,
) -> Result<ReplayClient, Box<dyn std::error::Error>> {
    let addr = *config.get_hostaddrs().first().expect("no hostaddr");
    let port = *config.get_ports().first().expect("no port");
    let socket_addr = SocketAddr::new(addr, port);
    let stream = TcpStream::connect(socket_addr).await?;
    let local_addr = stream.local_addr()?;

    let socket = Framed::new(stream, PgWireMessageClientCodec::default());

    let mut client = ReplaySocket {
        socket,
        config,
        server_information: ServerInformation::default(),
    };

    let mut startup_handler = DefaultStartupHandler::new();
    startup_handler.startup(&mut client).await?;

    loop {
        let msg = client
            .next()
            .await
            .ok_or("connection closed during startup")??;
        if let ReadyState::Ready(server_info) = startup_handler.on_message(&mut client, msg).await?
        {
            client.server_information = server_info;
            break;
        }
    }

    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(client_io_loop(local_addr, pcap_addr, client.socket, rx));
    Ok(ReplayClient {
        tx,
        addr: local_addr,
    })
}

async fn client_io_loop(
    local_addr: SocketAddr,
    pcap_addr: SocketAddr,
    mut socket: Framed<TcpStream, PgWireMessageClientCodec>,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    info!("[{local_addr};pcap={pcap_addr}] Connected");
    loop {
        tokio::select! {
            frame = rx.recv() => {
                match frame {
                    Some(raw) => {
                        if let Err(e) = socket.get_mut().write_all(&raw).await {
                            error!("[{local_addr};pcap={pcap_addr}] send failed: {e}");
                            break;
                        }
                    }
                    None => break,
                }
            }
            msg = socket.next() => {
                match msg {
                    Some(Ok(_backend_msg)) => {}
                    Some(Err(e)) => {
                        error!("[{local_addr};pcap={pcap_addr}] recv failed: {e}");
                        break;
                    }
                    None => break,
                }
            }
        }
    }
    info!("[{local_addr};pcap={pcap_addr}] Disconnected");
}
