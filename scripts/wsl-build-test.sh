#!/usr/bin/env bash
# Run as the normal WSL user. Never copy .local, .env, database files or Windows target/.
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
repo=$(cd "$(dirname "$0")/.." && pwd)
task_dir=${KEYROTATION_WSL_WORK:-$HOME/projects/keyrotation-systemd-validation}
mkdir -p "$task_dir"
tar -C "$repo" --exclude=.local --exclude=.git --exclude=target --exclude='.env*' --exclude='*.db' --exclude='*.db-*' --exclude='*.sqlite*' -cf - Cargo.toml Cargo.lock crates tools examples vendor src scripts deploy | tar -C "$task_dir" -xf -
cd "$task_dir"
cargo build --locked -p keyrotation-server -p keyrotation-e2e
cargo test --locked -p keyrotation-protocol -p keyrotation-transport -p keyrotation-server
printf 'WSL workspace: %s\n' "$task_dir"
