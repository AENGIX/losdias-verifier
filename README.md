# losdias-verify

Command-line checker for [losdias](https://losdias.aengix.com) broadcasts. It checks a spec 3.0.0 validation file: hardware attestation, the fragment hash chain, assertion signatures, Cloudflare Roughtime, and capture continuity.

Recordings come from the apps:

- [Android open beta](https://play.google.com/store/apps/details?id=com.aengix.losdias.android)
- [iOS TestFlight](https://testflight.apple.com/join/d6tEfQUH)

The specification and the trust anchors:

- [Video attestation technology](https://losdias.aengix.com/technology)
- [Public keys](https://losdias.aengix.com/pki)
- [Trust-anchor API](https://api.losdias.aengix.com/v1/pki)

## Usage

```
losdias-verify [flags] <broadcast-id | validation.txt | url>
```

A broadcast id is loaded from the losdias CDN. The process exits 0 when the report passes and 1 when it fails. `-version` prints the version. `-json` prints the report as JSON.

## Build

Requires Go 1.27.1 or newer.

```
./build.sh
./build.sh all
```

`./build.sh` writes the binary for this machine to `dist/`. `./build.sh all` writes the release binaries for macOS, Linux, and Windows. The version is `VERSION.json`. `./release.sh` builds those binaries and publishes a GitHub release.

## License

GPL-3.0. See [LICENSE](LICENSE).
