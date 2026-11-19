use std::io::Read;

fn pax_records(records: &[(&str, &[u8])], payload: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    builder
        .append_pax_extensions(records.iter().copied())
        .unwrap();
    let mut bytes = builder.get_ref().clone();
    let mut header = tar::Header::new_ustar();
    header.set_path("file").unwrap();
    header.set_mode(0o644);
    header.set_size(0);
    header.set_cksum();
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend_from_slice(payload);
    bytes.resize(bytes.len().next_multiple_of(512) + 1024, 0);
    bytes
}

#[test]
fn record_lengths_keep_newlines_and_raw_keys() {
    let mut records = tar::PaxExtensions::new(b"11 key=a\nb\n12 user.\xff=x\n5 k=\n");
    let first = records.next().unwrap().unwrap();
    assert_eq!(first.key_bytes(), b"key");
    assert_eq!(first.value_bytes(), b"a\nb");
    let second = records.next().unwrap().unwrap();
    assert_eq!(second.key_bytes(), b"user.\xff");
    assert_eq!(second.value_bytes(), b"x");
    let empty = records.next().unwrap().unwrap();
    assert_eq!(empty.value_bytes(), b"");
    assert!(records.next().is_none());
}

#[test]
fn a_size_record_after_a_binary_value_sizes_the_entry() {
    let bytes = pax_records(&[("key", b"a\nb"), ("size", b"3")], b"abc");
    let mut archive = tar::Archive::new(bytes.as_slice());
    let mut entry = archive.entries().unwrap().next().unwrap().unwrap();
    let mut read = Vec::new();
    entry.read_to_end(&mut read).unwrap();
    assert_eq!((entry.size(), read.as_slice()), (3, b"abc".as_slice()));
}

#[test]
fn the_builder_and_reader_agree_on_binary_values() {
    let mut builder = tar::Builder::new(Vec::new());
    builder
        .append_pax_extensions([("key", b"a\nb".as_slice())])
        .unwrap();
    let mut header = tar::Header::new_ustar();
    header.set_size(0);
    builder
        .append_data(&mut header, "file", std::io::empty())
        .unwrap();
    let bytes = builder.into_inner().unwrap();
    let mut archive = tar::Archive::new(bytes.as_slice());
    let mut entry = archive.entries().unwrap().next().unwrap().unwrap();
    let record = entry
        .pax_extensions()
        .unwrap()
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(record.key().unwrap(), "key");
    assert_eq!(record.value().unwrap(), "a\nb");
}

#[test]
fn malformed_records_fail_once_and_stop() {
    for bytes in [
        b"bad".as_slice(),
        b" key=x\n",
        b"+8 k=x\n",
        b"x k=x\n",
        b"0 k=x\n",
        b"1 k=x\n",
        b"99 k=x\n",
        b"6 k=x!",
        b"5 kx\n",
        b"99999999999999999999999 k=x\n",
    ] {
        let mut records = tar::PaxExtensions::new(bytes);
        assert!(records.next().unwrap().is_err(), "{bytes:?}");
        assert!(records.next().is_none());
    }
    assert!(tar::PaxExtensions::new(b"").next().is_none());
}
