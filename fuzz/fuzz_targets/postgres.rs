#![no_main]

use lens_core::Direction;
use lens_proto_postgres::PostgresDecoder;
use lens_protocol::StreamingDecoder;
use libfuzzer_sys::fuzz_target;

const STARTUP: &[u8] = b"\0\0\0\x20\0\x03\0\0user\0lens\0database\0dev\0\0";

fuzz_target!(|data: &[u8]| {
    let mut decoder = PostgresDecoder::new(4 * 1024);

    // Seed the state machine with a valid protocol startup, then alternate the
    // mutated fragments across both wire directions.
    let _ = decoder.push(Direction::ClientToServer, STARTUP);
    for (index, fragment) in data.chunks(19).enumerate() {
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
