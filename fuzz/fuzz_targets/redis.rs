#![no_main]

use lens_core::Direction;
use lens_proto_redis::RedisDecoder;
use lens_protocol::StreamingDecoder;
use libfuzzer_sys::fuzz_target;

const VALID_COMMAND: &[u8] = b"*2\r\n$3\r\nGET\r\n$6\r\nhealth\r\n";

fuzz_target!(|data: &[u8]| {
    let mut decoder = RedisDecoder::new(4 * 1024);
    let _ = decoder.push(Direction::ClientToServer, VALID_COMMAND);
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
