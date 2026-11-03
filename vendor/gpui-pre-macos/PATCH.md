Upstream: gpui-pre-macos 0.3.10 (Apache-2.0), crates.io.

Local patch: replace the three Option::map_or_default calls in src/window.rs
with map_or_else(Default::default, ...) for stable Rust 1.96 compatibility.
No other runtime changes. Remove this patch once an upstream compatible release
is adopted. Upstream licenses are retained.
