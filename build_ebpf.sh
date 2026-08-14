#!/bin/bash
set -e
cargo +nightly build --package capture-ebpf --target bpfel-unknown-none -Z build-std=core --release
