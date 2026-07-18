# Changelog

## [0.6.0](https://github.com/cresset-tools/sconce/compare/sconce-v0.5.0...sconce-v0.6.0) (2026-07-18)


### Features

* **api:** add data profiles as a snapshot dimension (small|full|perf) ([#33](https://github.com/cresset-tools/sconce/issues/33)) ([708059d](https://github.com/cresset-tools/sconce/commit/708059d669d1078f4ecc82b266a6b29f3394e343))
* **api:** advertise a per-remote database snapshot source in the team manifest ([#29](https://github.com/cresset-tools/sconce/issues/29)) ([dda3e39](https://github.com/cresset-tools/sconce/commit/dda3e39600f4876766e8be5ddb1b61a757aac00a))
* **api:** advertise named database sources in the team manifest ([#32](https://github.com/cresset-tools/sconce/issues/32)) ([4d5a1c9](https://github.com/cresset-tools/sconce/commit/4d5a1c95be26fff753c3667535adc6b9e52a685e))
* **api:** expose license-key merge in the management API ([7189da7](https://github.com/cresset-tools/sconce/commit/7189da79ad6c54b5bb22c47ff183000fcb818744))
* **api:** expose license-key merge in the management API ([9f79e4e](https://github.com/cresset-tools/sconce/commit/9f79e4ea69ac8bc02bbe2715f66e23cd95aba623))
* **api:** serve a git-remote-keyed team manifest (GET /api/v1/manifest) ([0c3f4d2](https://github.com/cresset-tools/sconce/commit/0c3f4d20b27ffbfed5147d898b8a023786e87b59))
* **api:** serve a git-remote-keyed team manifest (GET /api/v1/manifest) ([ef03d63](https://github.com/cresset-tools/sconce/commit/ef03d631e2259f167269183df5cc85268f92e357))
* **auth:** accept a set of introspect secrets for zero-downtime rotation ([59ff675](https://github.com/cresset-tools/sconce/commit/59ff6752e6de3de5ec5f54382df68a95392f8fbe))
* **auth:** zero-downtime rotation for the introspect secret ([19ba5c6](https://github.com/cresset-tools/sconce/commit/19ba5c6296d8c55f91895108d650f8cb797e9289))
* **publish:** zero-secret publishes from GitLab CI via id_tokens ([#34](https://github.com/cresset-tools/sconce/issues/34)) ([834db43](https://github.com/cresset-tools/sconce/commit/834db4351e8da655399a942169e6a27d835e3dcd))
* **ui:** collapse a package's versions into one row on the Packages tab ([b6f8469](https://github.com/cresset-tools/sconce/commit/b6f84693978fcd24861e0f5eefb6b80fca9d70f4))
* **ui:** collapse a package's versions into one row on the Packages tab ([94ed951](https://github.com/cresset-tools/sconce/commit/94ed9514a209b37d54f6dd7e9c70e789ae2e29d4))


### Bug Fixes

* **catalog:** stable newest-first snapshot ordering with a monotonic seq ([#31](https://github.com/cresset-tools/sconce/issues/31)) ([e6b9e81](https://github.com/cresset-tools/sconce/commit/e6b9e817d081d5d8f6769b4d29b3239deeba3d0f))

## [0.5.0](https://github.com/cresset-tools/sconce/compare/sconce-v0.4.0...sconce-v0.5.0) (2026-07-09)


### Features

* **api:** GET /api/v1/repos to list an org token's repositories ([7f9da3d](https://github.com/cresset-tools/sconce/commit/7f9da3d0704eb2639177a32fc8bdf4894922724e))
* **api:** GET /api/v1/repos to list an org token's repositories ([6ffe5b4](https://github.com/cresset-tools/sconce/commit/6ffe5b4f06d1149c9684703ff5ebd3d7df00c140))
* **api:** report the edition's edge bound on issue(account)/add responses ([0712650](https://github.com/cresset-tools/sconce/commit/0712650e40403a62157be9b6447739a0924b5d39))
* **auth:** OAuth 2.0 device authorization grant for CLI login ([b24120e](https://github.com/cresset-tools/sconce/commit/b24120eab7d74e58a1b2c10b2b1816fe90d3a9a0))
* **auth:** OAuth 2.0 device authorization grant for CLI login ([8840f01](https://github.com/cresset-tools/sconce/commit/8840f01f0511a65703e5d62b3c3687648022afa4))
* **licensing:** account-key issuance — bound on the edge from day one ([159066c](https://github.com/cresset-tools/sconce/commit/159066cd97019f2324f7f9f890401fccc754b715))
* **licensing:** per-entitlement update bounds — one key per customer ([7da945b](https://github.com/cresset-tools/sconce/commit/7da945bdcad0b6b31a0a42d317ae86cecb9478ce))
* **ui:** merge two license keys from the admin UI ([c2065d4](https://github.com/cresset-tools/sconce/commit/c2065d4a8bcfec8e8fd806958f2215c2491d72ab))


### Bug Fixes

* **ui:** show each set edge's own update bound on the license row ([bf685de](https://github.com/cresset-tools/sconce/commit/bf685de17469789615b8656cf8a4972190769b35))

## [0.4.0](https://github.com/cresset-tools/sconce/compare/sconce-v0.3.0...sconce-v0.4.0) (2026-07-08)


### Features

* **cli:** add `sconce snapshot push` to upload a snapshot from CI ([28283e8](https://github.com/cresset-tools/sconce/commit/28283e8d017642c7aa802dd7de6ad448a26581fc))
* **cli:** add `sconce snapshot push` to upload a snapshot from CI ([f135303](https://github.com/cresset-tools/sconce/commit/f135303989a7d66ff99092931b5d7028b528c43d))
* **licensing:** accumulate editions onto a repeat buyer's key ([68ba78e](https://github.com/cresset-tools/sconce/commit/68ba78e51baccc427d5032fb9e5427acc54b1747))
* **licensing:** accumulate editions onto a repeat buyer's key ([dab0f42](https://github.com/cresset-tools/sconce/commit/dab0f42bad9caa7a8a842fd83ba4b7beaa80be68))
* **snapshots:** add database snapshot object with upload + latest download ([435bd65](https://github.com/cresset-tools/sconce/commit/435bd6557f1b618ad895eb14c68a822b4c3516d9))
* **snapshots:** add database snapshot object with upload + latest download ([7505c3a](https://github.com/cresset-tools/sconce/commit/7505c3a16f760340afa17376248e76721e04b7d9))
* **snapshots:** download by pinned digest + scheduled-dump example ([ffd9e8e](https://github.com/cresset-tools/sconce/commit/ffd9e8eecd1e2445954080fe45a47cee2fa840c2))
* **snapshots:** download by pinned digest + scheduled-dump example ([12ff7ef](https://github.com/cresset-tools/sconce/commit/12ff7ef9be8a9c9f08b7d8f0ed249050fcb6fee5))

## [0.3.0](https://github.com/cresset-tools/sconce/compare/sconce-v0.2.0...sconce-v0.3.0) (2026-07-08)


### Features

* **api:** /api/v1 management API for license provisioning ([ad5d98f](https://github.com/cresset-tools/sconce/commit/ad5d98fc406fa2b6c53b733aa1094308efed83cf))
* **cas:** blob reference counting + garbage collection ([a042636](https://github.com/cresset-tools/sconce/commit/a0426362112ef2aeae40554d0159b77617ff9453))
* **cas:** S3-compatible blob store + presigned 302 dist serving ([c2226ae](https://github.com/cresset-tools/sconce/commit/c2226aed4112d3429ea073ba061d37dd27eb6c52))
* **catalog:** per-org storage metering (full logical size, no dedup credit) ([a5c61a3](https://github.com/cresset-tools/sconce/commit/a5c61a394281c648997b27826191401ac8b2c613))
* **entitlements:** neutral per-org resource throttle + feature gates ([9a3ac03](https://github.com/cresset-tools/sconce/commit/9a3ac0335a6c9eb8162531f6b298b48b8d42fc0d))
* **licensing:** store license keys encrypted at rest for recovery ([3eb853d](https://github.com/cresset-tools/sconce/commit/3eb853d20d8ca0bf1514bc41ce715ad26d6ffaad))
* **observability:** /healthz endpoints + tracing structured logs ([11c1179](https://github.com/cresset-tools/sconce/commit/11c11799108f840e99d64437b7cbc9de5f935b6e))
* **publish:** push/publish packages via OIDC-authenticated upload ([0ec1da3](https://github.com/cresset-tools/sconce/commit/0ec1da3cae9d5212e5b8e4f8e59b44e0ccb8a227))
* **publish:** push/publish packages via OIDC-authenticated upload ([0a1b676](https://github.com/cresset-tools/sconce/commit/0a1b676b5c815b436907824abfd03c9c1ae70365))
* **security:** harden the admin UI (CSRF, Secure cookies, rate limiting) ([d03caf0](https://github.com/cresset-tools/sconce/commit/d03caf06a7beb80ad7705b3162cb5f6d1d0364b6))
* **seller:** first-class editions (SKUs) keys are issued against ([53f41bc](https://github.com/cresset-tools/sconce/commit/53f41bcbcc63233c5b1524f3ef53bbe758bfda48))
* **ui:** close the Approvals-tab gaps against the Approvals.dc.html design ([d14fec6](https://github.com/cresset-tools/sconce/commit/d14fec6a96b51c91e08d863cf661bc1f1f9bc192))


### Bug Fixes

* **editions:** resolve code-review findings on issuance, renewal, and caps ([3be7ab0](https://github.com/cresset-tools/sconce/commit/3be7ab037a593ae2af44af1e063a1391243a03eb))

## [0.2.0](https://github.com/cresset-tools/sconce/compare/sconce-v0.1.0...sconce-v0.2.0) (2026-06-30)


### Features

* autogrant from a shared package set (Phase C2) ([26e9281](https://github.com/cresset-tools/sconce/commit/26e9281361fecf3616d1ad8a1c4e1f44143b58dd))
* grant-scoped supply-chain policy (Phase B3) ([96fc642](https://github.com/cresset-tools/sconce/commit/96fc6424ee99efed8247ec88b92581d79a1eba8f))
* **licensing:** entitle a license to a whole package set ([111bce6](https://github.com/cresset-tools/sconce/commit/111bce696a720ae0c92d14bf6d66348f111fe802))
* **mirror:** multi-require subscriptions + monorepo ingest ([54fbc99](https://github.com/cresset-tools/sconce/commit/54fbc99b355d7055c1d255c5d12758ba14f9763c))
* package sets — the shared collection primitive (Phase B1) ([8cfaf8a](https://github.com/cresset-tools/sconce/commit/8cfaf8a9da87815b32c743ef06dd8915f7123cde))
* perpetual-fallback licensing — update bound (Phase B2) ([396d760](https://github.com/cresset-tools/sconce/commit/396d76088c4872b7c60a22a7eca0a05ee474993e))
* **ui:** build the repo Approvals tab into a real approval queue ([df97046](https://github.com/cresset-tools/sconce/commit/df970460a427c36f2381528820680df94b471557))
* **ui:** password-reset (forgot password) flow ([ffa6bb5](https://github.com/cresset-tools/sconce/commit/ffa6bb5f2205bc94214015faaffb659481fb869a))
* **ui:** persist the repo detail tab in the URL #hash ([6604ea7](https://github.com/cresset-tools/sconce/commit/6604ea76ea4531f0d1974bae7809075908e8d6ef))
* **ui:** tabbed repository view + full-page Upstreams (design impl) ([fa7552e](https://github.com/cresset-tools/sconce/commit/fa7552e42ceaef86156b39f883a5f58fbd5aadbd))
* **version:** adopt composer-semver (normalization, constraints, sort) ([5a36fd7](https://github.com/cresset-tools/sconce/commit/5a36fd704fa54c39c9011581781c5485044c9d0e))
* **version:** use composer-semver for normalization, constraints, and sort ([ab04d8b](https://github.com/cresset-tools/sconce/commit/ab04d8b1edf70e9f9525d385d17f74940f017b6e))


### Bug Fixes

* **oidc:** clean up expired login flows on consume ([5643e1f](https://github.com/cresset-tools/sconce/commit/5643e1f1c82bafb8d93b0b53af6a811774b29eed))
