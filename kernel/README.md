# Real Kernel Layout

This directory no longer builds the old output-only fake kernel.

Current layout:
- upstream-based kernel source: `starry-next/`
- pinned upstream commit: `overlay/upstream.lock`
- local delta patch: `overlay/starry-next-local.patch`
- local delta diffstat: `overlay/starry-next-local.diffstat.txt`
- bootstrap/build helper: `scripts/bootstrap_starry_overlay.sh`
- transient build outputs: `work/`

Why this layout exists:
- it replaces the old fake kernel entry under `OSKernel2026/kernel`
- it moves the real kernel source tree into a non-hidden directory
- it keeps generated artifacts separate from the vendored source tree

Important:
- this repository now explicitly vendors the upstream-based kernel source
- the contest docs allow using an existing open-source kernel as the base, but require a clear statement of local modifications
- see `../docs/delta.md` and `../docs/attribution.md` for the current provenance and delta summary

The previous fake scaffold is preserved under `legacy_fake/` only for reference.
