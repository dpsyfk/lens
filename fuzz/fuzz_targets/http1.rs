#![no_main]

use lens_core::Direction;
use lens_proto_http1::Http1Decoder;
use lens_protocol::StreamingDecoder;
use libfuzzer_sys::fuzz_target;

const VALID_REQUEST: &[u8] =
    b"GET /health HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nping";

fuzz_target!(|data: &[u8]| {
    let mut decoder = Http1Decoder::new(4 * 1024);

    // Always enter a valid HTTP state before exercising the mutated tail. This
    // reaches pipelining and recovery paths even with a brand-new corpus.
    let _ = decoder.push(Direction::ClientToServer, VALID_REQUEST);
    for (index, fragment) in data.chunks(17).enumerate() {
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
