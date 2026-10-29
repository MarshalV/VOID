//! Dual-decode codec for `/void/chat/1.0.0`.
//!
//! Read accepts JSON or CBOR. Write follows [`WireMsg::cbor`], which the swarm
//! sets only after both Hellos carried `HELLO_CAP_CBOR`.

use std::io;

use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::StreamProtocol;

use void_frames::protocol::V1Packet;
use void_frames::wire::{self, WireEncoding};

#[derive(Debug, Clone)]
pub struct WireMsg {
    pub packet: V1Packet,
    /// Исходящий кадр. На приёме выставляется по фактическим байтам.
    pub cbor: bool,
}

#[derive(Clone)]
pub struct ChatCodec {
    request_size_maximum: u64,
    response_size_maximum: u64,
}

impl ChatCodec {
    pub fn new() -> Self {
        Self {
            request_size_maximum: wire::REQUEST_MAX_BYTES,
            response_size_maximum: wire::RESPONSE_MAX_BYTES,
        }
    }
}

impl Default for ChatCodec {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl libp2p::request_response::Codec for ChatCodec {
    type Protocol = StreamProtocol;
    type Request = WireMsg;
    type Response = WireMsg;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<WireMsg>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io, self.request_size_maximum).await
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<WireMsg>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io, self.response_size_maximum).await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: WireMsg,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &req, self.request_size_maximum).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: WireMsg,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &res, self.response_size_maximum).await
    }
}

async fn read_frame<T>(io: &mut T, max: u64) -> io::Result<WireMsg>
where
    T: AsyncRead + Unpin + Send,
{
    let mut buf = Vec::new();
    io.take(max).read_to_end(&mut buf).await?;
    let (packet, encoding) = wire::decode_v1_packet(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(WireMsg {
        packet,
        cbor: encoding == WireEncoding::Cbor,
    })
}

async fn write_frame<T>(io: &mut T, msg: &WireMsg, max: u64) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    let encoding = if msg.cbor {
        WireEncoding::Cbor
    } else {
        WireEncoding::Json
    };
    let bytes = wire::encode_v1_packet(&msg.packet, encoding)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if bytes.len() as u64 > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("chat frame {} exceeds {max}", bytes.len()),
        ));
    }
    io.write_all(&bytes).await?;
    Ok(())
}
