//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use std::assert;

use client_wasm::{debug, register_class_sierra};
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn deploy_world_wasm() {
    debug();
    let json = include_bytes!("../test-fixtures/world.json");
    let json = String::from_utf8_lossy(json);

    let class_declared = register_class_sierra("0xbeef".into(), json.into());
    assert!(class_declared);
}
