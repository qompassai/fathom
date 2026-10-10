# #################################################################
# /qompassai/rea-rust/flake.nix
# Qompass AI rea-rust — Flake
# SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0
# Copyright (c) 2026 Qompass AI
#
# Original work of Qompass AI (clean-room port, 2026-10-10).
# #################################################################
{
  description = "rea-rust — clean-room Rust port of REA: evidence-first reverse-engineering MCP/A2A server";

  inputs = {
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = {
    fenix,
    nixpkgs,
    self,
    ...
  }: let
    forAllSystems = nixpkgs.lib.genAttrs ["x86_64-linux"];
  in {
    devShells = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      toolchain = fenix.packages.${system}.fromToolchainFile {
        dir = ./.;
        sha256 = "sha256-3ok3kaNc8lhDSnZ9bZAJwmHgUrdB9CC5m+ZJBwFPWnA=";
      };
    in {
      default = pkgs.mkShell {
        packages = [
          pkgs.ghidra
          pkgs.mdbook
          toolchain
        ];
      };
    });

    packages = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      toolchain = fenix.packages.${system}.fromToolchainFile {
        dir = ./.;
        sha256 = "sha256-3ok3kaNc8lhDSnZ9bZAJwmHgUrdB9CC5m+ZJBwFPWnA=";
      };
      rustPlatform = pkgs.makeRustPlatform {
        cargo = toolchain;
        rustc = toolchain;
      };
    in {
      default = self.packages.${system}.rea-rust;
      rea-rust = rustPlatform.buildRustPackage {
        pname = "rea-rust";
        version = "0.1.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;
        cargoBuildFlags = ["--package" "rea-cli"];
        doCheck = false;
        meta.license = with pkgs.lib.licenses; [agpl3Only asl20];
      };
    });
  };
}
