# Releasing

A release is a tag. Everything after the tag is CI: `.github/workflows/release.yml`
builds for `aarch64-apple-darwin`, signs with the Developer ID, publishes a GitHub
Release with the tarball and its checksum, and rewrites `Formula/nhop.rb` in
`pkarpovich/homebrew-apps`.

## Steps

1. Bump `version` in the workspace `Cargo.toml` and let `cargo` update `Cargo.lock`.
   Do it in a pull request together with whatever is being released - CI refuses a
   tag whose version disagrees with the crate.
2. Merge the pull request.
3. Tag the merge commit on `main` and push the tag:

   ```sh
   git checkout main && git pull
   git tag -a v0.1.2 -m "nhop 0.1.2"
   git push origin v0.1.2
   ```

   Tags are annotated. `v0.1.1` is the one lightweight tag in the history; it was
   not rewritten because re-pushing a tag re-runs the release and replaces a
   published tarball with one that has a different checksum.
4. Watch the run: `gh run watch $(gh run list --workflow=release.yml -L1 --json databaseId -q '.[0].databaseId')`.
5. Replace the generated release notes. The workflow publishes with
   `generate_release_notes: true`, which is only a list of merged pull requests, so
   write what changed and what a user has to do about it:

   ```sh
   gh release edit v0.1.2 --title "nhop 0.1.2" --notes-file notes.md
   ```

## Verifying

```sh
curl -sfL https://raw.githubusercontent.com/pkarpovich/homebrew-apps/main/Formula/nhop.rb
brew update && brew upgrade nhop && brew services restart nhop
nhop doctor
```

The `sha256` in the formula has to match `checksums.txt` on the release, and
`nhop doctor` has to pass all seven checks against the upgraded daemon.

## Secrets

The workflow reads four repository secrets: `MACOS_CERT_P12_BASE64` and
`MACOS_CERT_PASSWORD` (the exported Developer ID Application certificate),
`MACOS_TEAM_ID`, and `HOMEBREW_TAP_TOKEN` (a fine-grained token with write access
to `pkarpovich/homebrew-apps` and nothing else). They are stored in 1Password.

`BUNDLE_ID` must never change. macOS ties the Local Network permission to the
signing identity plus that identifier, so a different value loses the grant and
the daemon starts reporting the upstream as unreachable.
