use std::io;
use std::net::{SocketAddr, UdpSocket};

/// Datagram I/O for an ordinary unconnected UDP socket. Socket errors are
/// returned as I/O errors. Apply the configured WTLS budget in the adapter.
pub struct SocketTransport {
    socket: UdpSocket,
    buffer: Vec<u8>,
}

impl SocketTransport {
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            socket,
            // Larger than any ordinary IPv4 or IPv6 UDP payload, so the
            // adapter sees even a datagram that exceeds its configured budget.
            buffer: vec![0; usize::from(u16::MAX) + 1],
        }
    }

    /// For socket options such as timeouts and local address reporting.
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Receive one complete datagram. A saturated buffer could represent a
    /// truncated IPv6 jumbogram and is rejected without exposing its prefix.
    pub fn receive(&mut self) -> io::Result<(SocketAddr, &[u8])> {
        let (size, remote) = self.socket.recv_from(&mut self.buffer)?;
        if size == self.buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UDP datagram exceeds receive buffer",
            ));
        }
        Ok((remote, &self.buffer[..size]))
    }

    /// Send one complete datagram to the destination supplied by the adapter.
    pub fn send(&self, remote: SocketAddr, bytes: &[u8]) -> io::Result<()> {
        if self.socket.send_to(bytes, remote)? != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "incomplete UDP datagram send",
            ));
        }
        Ok(())
    }
}
