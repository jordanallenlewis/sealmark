# Regression corpus

Every public MCP server that exposed a Sealmark bug (a crash, a false positive, a false negative, a hang) gets one
manifest here, so the bug stays fixed. Entries come from the fleet triage issues (label `from-fleet`); the fixing PR adds the file.

Add `cli/corpus/<server-id>.json`:

```json
{
  "id": "example-server",
  "issue": 123,
  "exposed": "crash | false-positive | false-negative | slow | hardening",
  "ecosystem": "npm | pypi | github",
  "launch": "npx -y example-server@1.2.3",
  "note": "one line: what Sealmark got wrong",
  "expect": {
    "noCrash": true,
    "maxSeconds": 300,
    "checks": { "check-id": "pass | fail | part | inconclusive | na" },
    "worstAtLeast": "B"
  }
}
```

Rules: the launch command pins an exact version (`@1.2.3`, `==1.2.3` or a commit); `issue` is the Sealmark issue it closed;
no secrets, tokens or private paths in a manifest. `npm test` validates the manifests offline. `corpus.yml` replays them against
the built CLI on a throwaway GitHub-hosted runner with no secrets (weekly, on release, and on changes here), because the servers are untrusted third-party code.
Never run `scripts/corpus-replay.mjs` on a machine you care about.
