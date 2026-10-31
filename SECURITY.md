# Security Policy

## Supported Versions

Only the latest release of LeafFuzz receives security fixes. Older versions are not backported.

| Version | Supported |
|---------|-----------|
| Latest  | ✅ Yes    |
| Older   | ❌ No     |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in LeafFuzz, please report it privately so it can be assessed and patched before public disclosure.

### How to Report

Use GitHub's private vulnerability reporting:
1. Go to the [Security Advisories](https://github.com/LeafCraftDev/LeafFuzz/security/advisories/new) page of this repository.
2. Click **"Report a vulnerability"**.
3. Fill in the details: affected version, reproduction steps, and potential impact.

### What to Include

- LeafFuzz version (`/fuzz test` output)
- Server platform and version (`/version` output)
- A clear description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (if safe to share)

## Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgement | Within 72 hours |
| Initial assessment | Within 7 days |
| Patch release (if confirmed) | Within 30 days |

## Scope

This policy covers:
- `resource/LeafFuzz` modules (`common`, `paper`, `fabric`, `neoforge`, `plugin`)
- Bundled multi-platform SDK modules (`api/*`)

## Out of Scope

- Vulnerabilities in Minecraft itself, the underlying JVM, or host operating system
- Upstream vulnerabilities in server software (Spigot, Paper, Folia, Fabric Loader, NeoForge)
- Issues caused by operator misconfiguration or insecure permissions setups
- Denial-of-service vectors that require operator-level (`OP`) permissions to trigger

## Vulnerability Disclosure History

| Advisory ID / CVE | Severity | Affected Versions | Fixed In | Summary | Published Date |
|---|---|---|---|---|---|
| *None* | - | - | - | No public vulnerabilities recorded to date. | - |
