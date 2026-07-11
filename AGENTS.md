# AGENTS.md

## Build & Test Commands

```bash
./gradlew assembleDebug          # build debug APK
./gradlew lintDebug              # lint (CI runs this first)
./gradlew testDebugUnitTest      # unit tests (Robolectric)
```

CI order: lint → build → test. Follow this locally if unsure.

Single test class:
```bash
./gradlew :app:testDebugUnitTest --tests "com.notcvnt.rknhardering.checker.VerdictEngineTest"
```

Marketplace hash regeneration (after editing any `.rkncheck` profile):
```bash
./gradlew :app:testDebugUnitTest --tests "com.notcvnt.rknhardering.customcheck.MarketplaceHashGeneratorTest" -i
```
Paste output into `expected_hash` in `marketplace/catalog.json` for the matching profile.

## SDK & Toolchain Requirements

- JDK 17+ (CI uses JDK 21)
- Android SDK: `platforms;android-36`, `build-tools;35.0.0`
- NDK `28.2.13676358`, CMake `3.22.1`
- Kotlin 1.9.25, AGP 8.9.2
- ABI filters: `arm64-v8a`, `armeabi-v7a`, `x86_64` (no x86)

## Project Structure

Two Gradle modules:
- **`:app`** — main Android application (Kotlin + JNI/C++)
- **`:xray-protos`** — protobuf/gRPC stubs for Xray API (java-library, no Android)

Entry point: `app/src/main/java/com/notcvnt/rknhardering/`

Native code (`app/src/main/cpp/`): two shared libraries built via CMake:
- `native_curl_probe` — HTTP probes using vendored curl + mbedTLS
- `native_signs_probe` — JNI checks (interfaces, routes, /proc, emulator detection)

Third-party native sources are vendored zips in `app/src/main/cpp/third_party/`.

## Robolectric Tests

Tests use Robolectric with offline mode. The build configures:
- `robolectric.offline=true`
- SDK 33 and 35 runtime jars copied to `build/robolectric-runtime-deps`
- Isolated `user.home` and `java.io.tmpdir` under `build/`

Do not override these system properties manually. Golden fixtures live in `app/src/test/resources/export/golden/`.

## Version Management

- Default version in `gradle.properties`: `appVersionName=2.6.8`
- Release builds: version derived from git tag (`v1.2.3` → `versionName=1.2.3`, `versionCode=major*10000+minor*100+patch`)
- Release CI validates that `versionName`/`versionCode` in `app/build.gradle.kts` match the tag
- Reproducible builds via `SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)`

## Marketplace Profiles

Profiles are `.rkncheck` JSON files in `marketplace/checks/`. Catalog at `marketplace/catalog.json` is signed (`catalog.sig`). See `marketplace/CONTRIBUTING.md` for full schema and submission process.

After editing any profile body, regenerate the hash (command above) and update the catalog in the same PR.

## Key Architecture

Checkers run in parallel via `VpnCheckRunner`. `VerdictEngine` computes the final verdict from evidence. `IpConsensusBuilder` cross-references GeoIP, IP comparison, CDN, and probe signals.

`IpComparisonChecker` is diagnostic only (shown in UI) — it feeds `IpConsensusBuilder` but does not directly enter `VerdictEngine`.

## .gitignore Note

`*.md` is gitignored at root. `AGENTS.md` and `CONTRIBUTING.md` have explicit exceptions. If you add new root-level `.md` files, add a `!filename` exception to `.gitignore`.
