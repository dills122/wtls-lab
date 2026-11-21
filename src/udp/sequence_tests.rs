use crate::handshake::Role;
use crate::wire::decode_server_hello;
use crate::wire::sequence_tests::{EXHAUSTED, NOW, contexts, seed_last_write};
use crate::{CipherSpec, decode_datagram};

use super::*;

const CLIENT: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 49152);
const SERVER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9203);
const NEW_CLIENT: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 49153);
const NEW_SERVER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9204);

fn send(events: &[Event], destination: SocketAddr) -> &[u8] {
    let mut sends = events.iter().filter_map(|event| match event {
        Event::Send { remote, bytes } => {
            assert_eq!(*remote, destination);
            Some(bytes.as_slice())
        }
        Event::Diagnostic { reason, .. } => panic!("unexpected diagnostic: {reason}"),
        _ => None,
    });
    let bytes = sends.next().expect("one outbound datagram");
    assert!(sends.next().is_none());
    bytes
}

fn assert_established(events: &[Event], destination: SocketAddr, kind: HandshakeKind) {
    assert!(events.iter().any(|event| matches!(
        event,
        Event::Established { remote, kind: actual } if *remote == destination && *actual == kind
    )));
}

fn assert_delivered(events: &[Event], source: SocketAddr, expected: &[u8]) {
    assert!(matches!(
        events,
        [Event::Deliver { remote, payload }] if *remote == source && payload == expected
    ));
}

#[test]
fn sequence_exhaustion_reports_protocol_and_reuses_the_retired_slot_for_both_roles() {
    for role in [Role::Client, Role::Server] {
        let (clients, servers) = contexts();
        let capacity = |local| NonZeroUsize::new(if role == local { 1 } else { 2 }).unwrap();
        let mut client = Adapter::new(None, DatagramBudget::new(1200), capacity(Role::Client));
        let mut server = Adapter::new(
            Some(servers),
            DatagramBudget::new(1200),
            capacity(Role::Server),
        );

        let offer = client.connect(SERVER, &clients, NOW, 0);
        let flight = server.receive(CLIENT, send(&offer, SERVER), NOW, 1);
        let records = decode_datagram(send(&flight, CLIENT)).unwrap();
        let id = decode_server_hello(records[0].fragment).unwrap().session_id;
        let client_commit = client.receive(SERVER, send(&flight, CLIENT), NOW, 2);
        let server_commit = server.receive(CLIENT, send(&client_commit, SERVER), NOW, 3);
        assert_established(&server_commit, CLIENT, HandshakeKind::Full);
        assert_established(
            &client.receive(SERVER, send(&server_commit, CLIENT), NOW, 4),
            SERVER,
            HandshakeKind::Full,
        );

        let (sender, receiver, from, to) = match role {
            Role::Client => (&mut client, &mut server, CLIENT, SERVER),
            Role::Server => (&mut server, &mut client, SERVER, CLIENT),
        };
        seed_last_write(&mut sender.associations.get_mut(&to).unwrap().peer);
        let last = sender.send_application(to, vec![1]);
        let bytes = send(&last, to);
        assert_eq!(decode_datagram(bytes).unwrap()[0].sequence, u16::MAX);
        assert_delivered(&receiver.receive(from, bytes, NOW, 5), from, &[1]);
        assert!(matches!(
            sender.send_application(to, vec![2]).as_slice(),
            [Event::Diagnostic { remote, reason: Diagnostic::Protocol(EXHAUSTED) }]
                if *remote == to
        ));
        assert_eq!(sender.status(to), None);
        assert_eq!(receiver.status(from), Some(Status::Open));

        let offer = client.connect(NEW_SERVER, &clients, NOW, 10);
        let records = decode_datagram(send(&offer, NEW_SERVER)).unwrap();
        assert_eq!(
            decode_client_hello(records[0].fragment).unwrap().session_id,
            id
        );
        let flight = server.receive(NEW_CLIENT, send(&offer, NEW_SERVER), NOW, 11);
        let records = decode_datagram(send(&flight, NEW_CLIENT)).unwrap();
        assert_eq!(
            decode_server_hello(records[0].fragment).unwrap().session_id,
            id
        );
        let commit = client.receive(NEW_SERVER, send(&flight, NEW_CLIENT), NOW, 12);
        assert_established(&commit, NEW_SERVER, HandshakeKind::Resumed);
        assert_established(
            &server.receive(NEW_CLIENT, send(&commit, NEW_SERVER), NOW, 13),
            NEW_CLIENT,
            HandshakeKind::Resumed,
        );
        let data = server.send_application(NEW_CLIENT, vec![3]);
        let bytes = send(&data, NEW_CLIENT);
        let records = decode_datagram(bytes).unwrap();
        assert_eq!(records[0].cipher_spec, CipherSpec::Current);
        assert_eq!(records[0].sequence, 1);
        assert_delivered(
            &client.receive(NEW_SERVER, bytes, NOW, 14),
            NEW_SERVER,
            &[3],
        );
        let data = client.send_application(NEW_SERVER, vec![4]);
        assert_delivered(
            &server.receive(NEW_CLIENT, send(&data, NEW_SERVER), NOW, 15),
            NEW_CLIENT,
            &[4],
        );
    }
}
