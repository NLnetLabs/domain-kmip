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

## 0.2.0

Released 2026-11-25.

### Breaking changes

- Remove `DestroyError` as it loses critical information. ([#10] by @ximon18)

### Bug fixes

- Handle RSA key material from Fortanix DSM HSMs correctly. ([#9] by @ximon18)

### Other changes

- Improved KMIP server compatibility. ([#12] by @ximon18)
- Update dependencies to crates.io versions to enable publication of this
  crate to crates.io. ([#8] and [#12] by @ximon18)

### Documentation improvements

- Update the RustDoc index page. ([#13] by @ximon18)

[#8]: https://github.com/NLnetLabs/domain-kmip/pull/8
[#9]: https://github.com/NLnetLabs/domain-kmip/pull/9
[#10]: https://github.com/NLnetLabs/domain-kmip/pull/10
[#12]: https://github.com/NLnetLabs/domain-kmip/pull/12
[#13]: https://github.com/NLnetLabs/domain-kmip/pull/13


## 0.1.0

Released 2026-11-06.

Initial release. This crate provides a [`domain::crypto`] compatible
cryptographic backend that generates keys and signs with them by sending
requests via TCP+TLS to an [Oasis KMIP] compatible HSM.

[`domain::crypto`]: https://docs.rs/domain/0.13.0/domain/crypto/
[Oasis KMIP]: https://www.oasis-open.org/tc-kmip/
