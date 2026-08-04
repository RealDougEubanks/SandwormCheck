# References and credits

Source material for the indicators in `signatures/`.

**None of the detection content in this repository is original research.** Every
indicator was published by one of the teams below; this project contributes only the
scanner that checks for them. Credit to Wiz, Socket, JFrog, CyberKendra, and Aikido for
investigating and disclosing this campaign. Vendor names are used for attribution only and
imply no endorsement or affiliation.

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

## Package list sources

The `PKGVER` records in `signatures/shai-hulud-2026-08-packages.conf` come from the union
of two machine-readable feeds, which each covered the other's gap:

- **Wiz IOC CSV** — <https://github.com/wiz-sec-public/wiz-research-iocs/blob/main/reports/keyv-packages.csv>
  2,235 pairs across 443 package names. Omits the entire `@keyv/*` scope.
- **JFrog** — <https://research.jfrog.com/post/shai-hulud-is-back-august/>
  1,738 pairs across 463 names. The only source carrying all 19 `@keyv/*` packages.

- **Socket CSV** — <https://socket.dev/api/public/supply-chain-attacks/keyv-and-cacheable-compromise/packages.csv>
  2,236 pairs across 444 package names. Columns:
  `Ecosystem,Namespace,Name,Version,Artifact,Published,Detected`. Verified as a **strict
  subset** of the list below — it contributed no pair we did not already have.

Union: **2,255 pairs across 463 package names.** A 25-pair random sample was checked
against the npm registry directly; all 25 were published 2026-08-04 and subsequently
unpublished, which is the expected takedown signature.

### Two of the three feeds omit the campaign's namesake scope

Both the Wiz CSV and Socket's CSV omit **every `@keyv/*` package**. Only JFrog published
them. Those 19 entries (`@keyv/redis@6.0.0`, `@keyv/postgres@6.0.0`, `@keyv/valkey@6.0.0`,
and so on) were independently confirmed against the npm registry as published on
2026-08-04 and since unpublished, so they are genuine, not vendor noise.

The practical consequence: **refreshing from any single feed would silently delete real
packages.** `tools/merge-package-list.sh` therefore unions rather than replaces, and
reports how many already-known pairs a feed is missing. Do not bypass it.

Do **not** merge `shai-hulud-2-packages.csv` from the same Wiz repository — that is the
November 2025 campaign.

Cross-checked against **Aikido**
(<https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack>),
the vendor claiming the widest impact: "At least 434 packages (across 1381 versions) have
been compromised by the worm". That is fewer than the 463 names / 2,255 versions encoded
here, and all 16 packages the post names are covered — including `ecto` and the five
community-spread packages outside the keyv/cacheable namespaces (`@deliveroo/reevent`,
`@or-sdk/invitations`, `@picsart/ai-sdk`, `@qlik/embed-runtime`, `picasso.js`). Aikido
publishes no downloadable export; the post enumerates only those 16 as examples.

Still outstanding: Socket's real-time campaign page returns HTTP 403 to scripted fetches
and needs a browser session.

At the time of collection **OSV.dev held no advisories for this campaign at all** — no
GHSA, no `MAL-`, no CVE. Worth re-querying, since an OSV feed would be the cleanest
long-term source.

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
