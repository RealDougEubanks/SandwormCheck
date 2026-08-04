# References

Source material for the indicators in `signatures/shai-hulud-2026-08.conf`.

## Primary vendor reporting

- Wiz — *keyv and cacheable npm supply chain attack*
  <https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack>
  Source for: payload filenames, SHA-1 hashes, C2 and staging domains, the embedded
  threat string, the `Shai-Hulud: Here We Go Again` exfil repo description, the
  `Bun/1.3.13` user agent, the `chore: update config` commit message, and the
  Ethereum-contract C2 discovery mechanism.

- Socket — *Popular npm packages in the keyv and cacheable namespaces compromised in
  active supply chain attack*
  <https://socket.dev/blog/popular-npm-packages-in-the-keyv-and-cacheable-namespaces-compromised-in-active-supply-chain>
  Source for: the exact compromised package/version list, SHA-256 hashes for the
  payload and both `setup.mjs` variants, the full `gh-token-monitor` persistence chain,
  the targeted credential inventory, and the OIDC trusted-publishing propagation path.

- CyberKendra — *npm worm hits keyv and cacheable*
  <https://www.cyberkendra.com/2026/08/npm-worm-hits-keyv-and-cacheable.html>
  Source for: publication timeline, the `file-entry-cache` / `flat-cache` transitive
  vector, `loginctl enable-linger` on Linux, the 24-hour TTL self-destruct, and the
  Microsoft Defender detection name `Trojan:npm/MalBun.A`.

## Discrepancies noted while encoding

- Wiz labels three 40-hex-character values as SHA256. They are 40 chars, so they are
  SHA-1 digests. Both interpretations are encoded (`SH25-H004` through `SH25-H006` as
  `SHA1`) rather than picking one and risking a miss.
- Socket and Wiz cite different `setup.mjs` SHA-256 values; both are encoded, since the
  loader had at least two variants (npm tarball and repository-injected).
- CyberKendra cites `169.254.170.2` as a GCP metadata endpoint. It is in fact the ECS
  task metadata endpoint on AWS. This does not affect any signature — metadata IPs are
  not used as filesystem indicators — but the error is worth flagging for anyone
  building network detections from that post.

## Cross-checks worth running alongside this scanner

SandwormCheck reads the filesystem only. It cannot see what your registry saw. Pair it
with:

- `npm audit signatures` and your registry's own audit log.
- A lockfile sweep across all repositories for the versions in the `PKGVER` block —
  catches projects that pinned a bad version but have not installed it on any host.
- GitHub organization audit log review for repositories created around 2026-08-04 with
  the `Shai-Hulud: Here We Go Again` description, and for unexpected npm publishes.
- Rotation of any npm, GitHub, cloud, or Vault credential that was present in an
  environment where a `CONFIRMED` finding landed. See `docs/remediation.md`.
