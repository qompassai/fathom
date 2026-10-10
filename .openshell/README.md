# OpenShell configuration for rea-rust

<!-- SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0 -->
<!-- Copyright (c) 2026 Qompass AI -->

RECONCILED WITH THE ESTATE PATTERN, NOT ORIGINATED: the established
OpenShell pattern in this estate is machine-level — the NVIDIA
OpenShell gateway configuration in the operator's home
(`~/.config/openshell/gateway.toml`, schema version 2, podman
compute driver, primary listener on loopback `127.0.0.1:17670`,
mutual TLS by default), documented by
`agents/openshell/CONFIGURATION.md` in the Daelin configuration
tree (`~/.GH/Qompass/Daelin/agents/openshell/`). Project repos do
not carry their own gateway state.

This directory is the minimal repo-level equivalent, following the
shape volta and vongola established: `gateway.toml.example`
mirrors the machine gateway's shape with rea-rust-specific
naming, so a rea-rust development sandbox can run behind the same
gateway conventions. It contains no secrets; real gateway state
stays in the operator's home configuration.
