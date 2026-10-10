# OpenShell configuration for fathom

<!-- SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0 -->
<!-- Copyright (c) 2026 Qompass AI -->

This directory follows the estate OpenShell pattern; it is not
an originated design. The pattern's source of truth is
machine-level: the OpenShell gateway configuration reference
kept with the diver configuration at
`agents/openshell/CONFIGURATION.md`, and the operator's active
gateway config at `~/.config/openshell/gateway.toml` (schema
version 2, podman driver pinned, mTLS on by default).

`gateway.toml.example` is that gateway shape carrying fathom's
values, so a fathom development sandbox runs behind the same
gateway conventions as the rest of the estate. It contains no
secrets; real gateway state stays in the operator's home
configuration, and TLS material is auto-generated under
`~/.local/state/openshell/tls/`.

History: this directory was originated independently during the
2026-10-10 Rust port scaffold, before the estate pattern was
located in full, and was reconciled to the pattern the same day
after a cross-repo audit. The originated sketch used invented
`[gateway]` and `[sandbox]` sections with `address`/`driver`/`mtls`
fields; the schema's real shape is `[openshell]` with `version = 2`,
`[openshell.gateway]` (`bind_address`, `compute_driver`, mTLS
by default), and `[openshell.drivers.podman]`.
