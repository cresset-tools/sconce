# Changelog

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
