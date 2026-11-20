//! Single-PDU WTP/WSP smoke responder for the BlackBerry lab.

const PAGE: &str = concat!(
    "<?xml version=\"1.0\"?>\n",
    "<!DOCTYPE wml PUBLIC \"-//WAPFORUM//DTD WML 1.1//EN\" ",
    "\"http://www.wapforum.org/DTD/wml_1.1.xml\">\n",
    "<wml><card id=\"lab\"><p>WTLS lab close and reconnect</p></card></wml>",
);

#[derive(Default)]
pub(super) struct Session {
    pending_page: Option<u16>,
}

pub(super) enum Request {
    Reply {
        bytes: Vec<u8>,
        page_tid: Option<u16>,
    },
    PageAck(u16),
    Ignore,
}

impl Session {
    pub(super) fn receive(&mut self, payload: &[u8]) -> Request {
        match payload {
            [0x18, high, low] => {
                let tid = u16::from_be_bytes([high & 0x7f, *low]);
                if self.pending_page == Some(tid) {
                    self.pending_page = None;
                    Request::PageAck(tid)
                } else {
                    Request::Ignore
                }
            }
            [0x08 | 0x0a, high, low, flags, pdu, ..] if flags & 0x03 == 2 => {
                let mut bytes = vec![0x16, high | 0x80, *low];
                let page_tid = match pdu {
                    0x01 => {
                        bytes.extend_from_slice(&[0x02, 1, 0, 0]);
                        None
                    }
                    0x40 => {
                        bytes.extend_from_slice(&[0x04, 0x20, 0x01, 0x88]);
                        bytes.extend_from_slice(PAGE.as_bytes());
                        Some(u16::from_be_bytes([high & 0x7f, *low]))
                    }
                    _ => return Request::Ignore,
                };
                Request::Reply { bytes, page_tid }
            }
            _ => Request::Ignore,
        }
    }

    pub(super) fn page_sent(&mut self, tid: u16) {
        self.pending_page = Some(tid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blackberry_class_two_connect_and_get_return_single_results() {
        // WTLS-207 BlackBerry compatibility: both Invoke octets are seen
        // in class 2, and the Result sets the high bit of the TID.
        let mut wsp = Session::default();
        let Request::Reply { bytes, page_tid } = wsp.receive(&[0x08, 0x01, 0x02, 0x12, 0x01])
        else {
            panic!("expected Connect result");
        };
        assert_eq!(bytes, [0x16, 0x81, 0x02, 0x02, 1, 0, 0]);
        assert_eq!(page_tid, None);

        let Request::Reply { bytes, page_tid } =
            wsp.receive(&[0x0a, 0x23, 0x45, 0x02, 0x40, 0x01, b'/'])
        else {
            panic!("expected GET result");
        };
        assert_eq!(&bytes[..7], &[0x16, 0xa3, 0x45, 0x04, 0x20, 0x01, 0x88]);
        assert!(
            std::str::from_utf8(&bytes[7..])
                .unwrap()
                .contains("WTLS lab close and reconnect")
        );
        assert_eq!(page_tid, Some(0x2345));
        assert!(matches!(
            wsp.receive(&[0x0a, 0x23, 0x45, 0x01, 0x40]),
            Request::Ignore
        ));
    }

    #[test]
    fn only_the_matching_page_ack_is_consumed() {
        let mut wsp = Session::default();
        assert!(matches!(wsp.receive(&[0x18, 0x23, 0x45]), Request::Ignore));
        wsp.page_sent(0x2345);
        for ack in [[0x18, 0x23, 0x46], [0x19, 0x23, 0x45]] {
            assert!(matches!(wsp.receive(&ack), Request::Ignore));
        }
        assert!(matches!(
            wsp.receive(&[0x18, 0xa3, 0x45]),
            Request::PageAck(0x2345)
        ));
        assert!(matches!(wsp.receive(&[0x18, 0x23, 0x45]), Request::Ignore));
    }
}
