use std::{
    collections::BTreeMap,
    error::Error,
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
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_util::codec::Framed;

#[pin_project]
pub struct ReplaySocket {
    #[pin]
    socket: Framed<TcpStream, PgWireMessageClientCodec>,
    config: Arc<Config>,
    server_information: ServerInformation,
    pub addr: SocketAddr,
}

impl ReplaySocket {
    pub async fn connect(
        addr: SocketAddr,
        config: Arc<Config>,
    ) -> Result<ReplaySocket, Box<dyn Error>> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        let local_addr = stream.local_addr()?;

        let socket = Framed::new(stream, PgWireMessageClientCodec::default());

        let mut client = ReplaySocket {
            socket,
            addr: local_addr,
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
            if let ReadyState::Ready(server_info) =
                startup_handler.on_message(&mut client, msg).await?
            {
                client.server_information = server_info;
                break;
            }
        }
        Ok(client)
    }

    pub async fn send_packet(&mut self, bytes: &[u8]) -> Result<(), std::io::Error> {
        let writer = self.socket.get_mut();
        writer.write_all(bytes).await?;
        Ok(())
    }
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
