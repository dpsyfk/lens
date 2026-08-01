#![no_main]

use lens_core::Direction;
use lens_proto_http2::Http2Decoder;
use lens_protocol::StreamingDecoder;
use libfuzzer_sys::fuzz_target;

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fuzz_target!(|data: &[u8]| {
    let mut decoder = Http2Decoder::new(4 * 1024);
    let _ = decoder.push(Direction::ClientToServer, CLIENT_PREFACE);
    for (index, fragment) in data.chunks(23).enumerate() {
        let direction = if index % 2 == 0 {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        };
        let _ = decoder.push(direction, fragment);
    }
    let _ = decoder.finish(Direction::ClientToServer);
    let _ = decoder.finish(Direction::ServerToClient);
});
