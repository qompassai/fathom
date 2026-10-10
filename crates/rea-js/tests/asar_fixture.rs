//! Cross-validation against the real tool: `sample.asar` was
//! produced by `npx @electron/asar pack` (verified 2026-10-10)
//! from a directory holding a.txt ("hello asar world"),
//! package.json ({"name":"x"}), and sub/b.txt
//! ("nested file contents here"). If this test fails, the
//! reader's format model is wrong — not the fixture.

use rea_js::asar::{extract, parse_asar};

#[test]
fn validation_real_asar_fixture() {
    let bytes = include_bytes!("fixtures/sample.asar");
    let archive = parse_asar(bytes).expect("real @electron/asar output must parse");
    let paths: Vec<&str> = archive.entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(paths, vec!["a.txt", "package.json", "sub", "sub/b.txt"]);
    let a = archive
        .entries
        .iter()
        .find(|e| e.path == "a.txt")
        .expect("a.txt entry");
    assert_eq!(extract(bytes, &archive, a).unwrap(), b"hello asar world");
    let b = archive
        .entries
        .iter()
        .find(|e| e.path == "sub/b.txt")
        .expect("sub/b.txt entry");
    assert_eq!(
        extract(bytes, &archive, b).unwrap(),
        b"nested file contents here"
    );
}
