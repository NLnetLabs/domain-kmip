# Changelog

<!-- Changelog template (remove empty sections on release of a version)
## Unreleased version

Released yyyy-mm-dd.

### Breaking changes
### New
### Bug fixes
### Other changes
### Documentation improvements
### Known issues
### Acknowledgements
-->

## Unreleased version

### Bug fixes

- Fortanix DSM fixes. ([#9] by @ximon18)

### Other

- Use kmip-protocol from crates.io now that it has been published. ([#8] by
  @ximon18)

[#8]: https://github.com/NLnetLabs/domain-kmip/pull/8
[#9]: https://github.com/NLnetLabs/domain-kmip/pull/9


## 0.1.0

Released 2026-11-06.

Initial release. This crate provides a [`domain::crypto`] compatible
cryptographic backend that generates keys and signs with them by sending
requests via TCP+TLS to an [Oasis KMIP] compatible HSM.

[`domain::crypto`]: https://docs.rs/domain/0.13.0/domain/crypto/
[Oasis KMIP]: https://www.oasis-open.org/tc-kmip/
