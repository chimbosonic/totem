//! Every parser that reads YKOATH card responses, on arbitrary bytes. The
//! card is trusted only so far: a faulty or hostile one must cause an
//! error, never a panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use totem::oath::{crypto, proto, tlv};

fuzz_target!(|data: &[u8]| {
    let _ = tlv::parse_all(data);
    let _ = tlv::parse_exact(data);
    if let Ok(response) = proto::Response::parse(data) {
        let _ = response.into_data(proto::Command::CalculateAll);
    }
    let _ = proto::parse_select(data);
    if let Ok(entries) = proto::parse_calculate_all(data) {
        for entry in entries {
            let name = proto::parse_name(&entry.name);
            let _ = crypto::validity_window(1_800_000_000, name.period);
            if let proto::EntryState::Code(code) = entry.state {
                let _ = code.to_code();
            }
        }
    }
    if let Ok(code) = proto::parse_calculate(data) {
        let _ = code.to_code();
    }
    let _ = proto::parse_name(data);
    let _ = proto::verify_validate_response(data, crypto::Algorithm::Sha1, b"key", b"challenge");
});
