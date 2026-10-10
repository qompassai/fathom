# #################################################################
# /qompassai/fathom/shell.nix
# Qompass AI Flake-Compat Shell Shim
# SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0
# Copyright (c) 2026 Qompass AI
#
# Non-flake entry point: lands `nix-shell` users in the same shell
# flake.nix defines, via flake-compat. The canonical definition is
# the flake; edit that, not this.
(import (
  let
    lock = builtins.fromJSON (builtins.readFile ./flake.lock);
  in
    fetchTarball {
      url = "https://github.com/edolstra/flake-compat/archive/${lock.nodes.flake-compat.locked.rev}.tar.gz";
      sha256 = lock.nodes.flake-compat.locked.narHash;
    }
) {src = ./.;})
.shellNix
