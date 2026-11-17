# Evidence improvement plan

**Date:** 2026-11-17  
**Status:** Draft — not an ADR; a working document for prioritising upcoming work  
**Input:** Internal analysis of the evidence model + external architectural review
([gh-baseline-service-boundaries-and-data-model.md](../gh-baseline-service-boundaries-and-data-model.md))

---

## The core concern

`gh-baseline` is used in scheduled audits that alert on a non-zero exit code.
For that use-case to be trustworthy, two requirements must hold:

1. When a check fails, the evidence for the failure must justify the name on the
   finding.
2. When a check is inconclusive, the audit must not silently look clean.

Several checks fall short of one or both requirements today.

---

## Assessment of the external architectural review

The external review is well-reasoned. Its strongest ideas are incorporated below.
Where it overshoots is the package restructure (`cmd/baseline`, `internal/app`,
`internal/domain`): those layers are appropriate for a multi-binary service but
add pure indirection to a single-command tool.  The snapshot is already the
correct anti-corruption boundary between GitHub's API model and
`gh-baseline`'s security-policy model; the data-model improvements the review
proposes are the right way to strengthen it without a disruptive reorganisation.

The review's highest-value items in order:

1. `Observation[T]` — formalises the three states (available, unavailable, error)
   that `*bool + Errors map` currently conflates
2. `ReasonCode` — replaces fragile message-string matching with stable domain codes
3. `WorkflowEvidence` — separates parsing from checking; solves the class of
   problems this plan addresses in Gaps 3–5 and 8
4. `SchemaVersion` on the snapshot — offline re-evaluation is a first-class feature;
   without a version field, schema changes silently break old snapshots
5. Snapshot freshness — surfacing `CapturedAt` and a `--max-snapshot-age` guard
   prevents evidence from silently going stale

What the external review does not cover (addressed here):
- The `--fail-on-unknown` exit-code gap (most immediately dangerous)
- The `dependabot-actions` regex matching YAML comments
- Trigger blindness in `workflow.stale-secrets`
- Bracket notation and `secrets: inherit` in secret extraction

---

## Part A — Behavioural gaps (ordered by impact on a scheduled audit)

### Gap 1 — `unknown` does not cause a non-zero exit

**Where:** `main.go`, `if report.Summarize(findings).Fail > 0`

**What happens today:** `unknown` findings appear in the table and in SARIF at
`warning` level but do not contribute to the exit code.  Only `fail` causes
exit 1.

**Why this matters most:** If the token loses the permissions a check needs
(rotated credentials, reduced scopes, changed fine-grained-token policy), every
affected check becomes `unknown`.  The audit exits 0.  The alert does not fire.
The operator infers everything is fine — the opposite of the truth.

This is not hypothetical.  An account that only partially grants
secrets/actions/environments read gets a silent partial pass today.

**Proposed fix:** Add `--fail-on-unknown` to make any `unknown` finding
contribute to exit 1 (or use a distinct exit code 3).  For scheduled audit
workflows this flag should be the default recommendation in the README.  The flag
is not on by default because legitimate sources of `unknown` exist (e.g.
a snapshot collected before `security.security-policy` was added) where callers
may prefer to filter, not fail.

**Relationship to `Observation[T]`:** When the data model is strengthened
(Part B), the distinction between `ObservationUnavailable` (feature not on the
plan) and `ObservationError` (token lacked permission) can drive finer exit-code
semantics.  For now, `--fail-on-unknown` is the correct short-term fix.

---

### Gap 2 — `workflow.dependabot-actions` applies a regex to raw YAML text

**Where:** `internal/check/check.go`,
`dependabotActions.MatchString(in.Repo.Dependabot.Content)`

**The gap:** A YAML comment `# package-ecosystem: github-actions` causes a false
pass.  This is the same class of problem the line-based workflow parser had before
`yaml.v3` was introduced; the dependabot.yml parser was never updated.

**Proposed fix:** Parse `dependabot.yml` with `yaml.v3` and check whether any
entry in the `updates` array has `package-ecosystem == "github-actions"`:

```go
type dependabotDoc struct {
    Updates []struct {
        Ecosystem string `yaml:"package-ecosystem"`
    } `yaml:"updates"`
}
```

Extend the existing fuzz-test pattern to cover the new function.

---

### Gap 3 — `workflow.stale-secrets` doesn't consider whether the workflow can run

**Where:** `internal/check/check.go`, `workflow.stale-secrets` Run function

**What the evidence shows:** The repository hasn't been pushed to in `staleDays`
days, at least one workflow references `${{ secrets.NAME }}`, and that secret
exists.

**Gap — trigger blindness:** A push-only workflow will never run on a stale repo.
Its secrets are unreachable without a push.  A `schedule`-triggered workflow runs
continuously regardless of push activity.  The check treats both identically,
overstating risk for push-only repos and understating urgency for scheduled ones.

**Gap — `secrets: inherit`:** A reusable workflow called with `secrets: inherit`
passes every secret to the callee without naming them.  `secretsUsed` returns
nothing for such a workflow, so the check never fails despite the full secret set
being accessible on the next scheduled run.

**Gap — bracket notation:** `${{ secrets['DEPLOY_KEY'] }}` is valid expression
syntax and is not matched by the `secretRef` regex.

**Proposed fixes:**

1. Parse the `on:` block with `yaml.v3` (already a dependency) and extract trigger
   types.  If the only triggers are `push`, `pull_request`, `workflow_dispatch`,
   and similar human-initiated events, add a contextual message: "stale push-only
   repo — secrets unreachable without a push" and downgrade to `medium`.  If
   `schedule` or `repository_dispatch` is present, keep `high`.
2. Scan for `secrets: inherit` at the job or reusable-workflow-call level and
   return a sentinel so the check can emit: "uses inherited secrets — audit the
   callee".
3. Extend `secretRef` to also match `secrets\[['"]([A-Za-z0-9_]+)['"]\]`.

**Relationship to `WorkflowEvidence`:** The clean long-term fix for all three
sub-gaps is Part B's `WorkflowEvidence` struct, which makes trigger types,
secret references, and inheritance explicit domain facts rather than regex
matches over raw text.

---

### Gap 4 — `workflow.token-permissions` checks declaration, not value

**Where:** `internal/check/workflow.go`, `hasTopLevelPermissions`

**The gap:** `permissions: write-all` passes.  The check is about explicit
declaration, not least-privilege.  Its name implies the latter.

**Proposed fix (two stages):**

1. Clarify the remediation message now: "Declare `permissions:` explicitly.
   Default to `permissions: contents: read` and grant more per job only where
   needed."  This aligns the expectation without breaking history.
2. Add `workflow.token-permissions-scope` as a separate check that fails on
   `write-all` or any top-level scope set to `write`.  The existing YAML parse
   already makes this feasible; `hasTopLevelPermissions` unmarshals into
   `map[string]any` and the values can be read from the same result.

---

### Gap 5 — `security.secret-scanning` and `security.push-protection` skip paid private repos

**Where:** `internal/check/check.go`, `securityToggle`

**The gap:** Both checks skip private repos unconditionally ("private repository
(paid feature)"), conflating:
- A private repo on a free plan where the feature is genuinely unavailable
- A private repo on a Pro/Team/Enterprise plan where the feature is available but
  off

**Proposed fix:** Skip only when `security_and_analysis` was not returned (which
already maps to `unknown` via `FieldSecurity`).  If the field IS present for a
private repo, evaluate it the same as a public repo and note in the remediation
that the feature requires a paid plan.

---

### Gap 6 — Reusable workflow callees are not inspected

**Where:** `internal/check/workflow.go`, `unpinnedUses` and
`hasTopLevelPermissions`

**The gap:** A workflow that calls `uses: acme/shared-workflows/...@main` is
checked for the SHA pin, but the callee's actions and permissions are not.  An
attacker who controls the callee can run arbitrary code with the caller's token
regardless of the caller's permissions block.

**Scope note:** Fixing this requires extra API calls and collection complexity.
Worth naming explicitly rather than discovering when the tool reports "all actions
pinned" on a workflow that calls an unpinned external callee.

**Proposed approach (longer term):** `workflow.reusable-callee-pinned` iterates
job-level `uses:` values, identifies external repos, and verifies the SHA pin.
The callee's internal actions are explicitly out of scope.

---

## Part B — Data model improvements

These are the structural investments that make the evidence model trustworthy at
scale.  They are orthogonal to the behavioural gaps above and should be delivered
as a separate, incremental sequence.

### B1 — `Observation[T]` replaces `*T + Errors map` and `Security map[string]string`

Two distinct patterns in the current model both have the nil-ambiguity problem:

**`*bool` fields** (`VulnReporting`, `SecurityPolicy`): nil accumulates multiple
meanings — not applicable, not collected, API error, plan limitation.  Checks
cannot distinguish them.

**`Security map[string]string`**: a missing key means the same thing as the `*bool`
nil case.  `Security["secret_scanning"]` being absent could mean the GitHub API
returned no `security_and_analysis` block (plan limitation), that the token
lacked the scope, or that the snapshot predates the field.  The map value
`"enabled"` / `"disabled"` is richer than a bool, but the absent-key case is
just as ambiguous.

Both patterns should be replaced with `Observation[T]`:

```go
type ObservationState string

const (
    ObservationAvailable   ObservationState = "available"
    ObservationUnavailable ObservationState = "unavailable" // plan or feature doesn't apply
    ObservationError       ObservationState = "error"       // token lacked permission or API failed
)

type Observation[T any] struct {
    State      ObservationState `json:"state"`
    Value      T                `json:"value,omitempty"`
    ReasonCode ReasonCode       `json:"reasonCode,omitempty"`
    Message    string           `json:"message,omitempty"`
}
```

The `Security` map becomes typed per feature:

```go
type FeatureState string

const (
    FeatureEnabled  FeatureState = "enabled"
    FeatureDisabled FeatureState = "disabled"
)

type RepositorySecurity struct {
    SecretScanning   Observation[FeatureState] `json:"secretScanning"`
    PushProtection   Observation[FeatureState] `json:"pushProtection"`
    DependabotAlerts Observation[FeatureState] `json:"dependabotAlerts"`
}
```

This eliminates the absent-key ambiguity and makes each feature's collection
state explicit and independently testable.

This change is breaking for the snapshot JSON schema, which makes B3
(`SchemaVersion`) a prerequisite.

---

### B2 — `ReasonCode` replaces message-string matching

Currently `planLimited()` does
`strings.HasPrefix(se.Message, "Upgrade to GitHub")` to identify plan-limited
403 responses.  GitHub rewording that message silently breaks the distinction
between "plan limit" and "forbidden".

```go
type ReasonCode string

const (
    ReasonPlanUnavailable ReasonCode = "plan_unavailable"
    ReasonForbidden       ReasonCode = "forbidden"
    ReasonNotFound        ReasonCode = "not_found"
    ReasonMissingScope    ReasonCode = "missing_scope"
    ReasonRateLimited     ReasonCode = "rate_limited"
    ReasonUnsupportedYAML ReasonCode = "unsupported_yaml"
)
```

The collector normalises GitHub errors into these codes at the boundary.  Checks
reason over codes, not messages.  The raw message remains available for
diagnostics.

---

### B3 — `SchemaVersion` and snapshot versioning

The snapshot is an offline artifact used for re-evaluation.  Without a version
field, schema additions are silent breaking changes.

```go
type Snapshot struct {
    SchemaVersion int       `json:"schemaVersion"`
    GeneratedAt   time.Time `json:"generatedAt"`
    // existing fields unchanged
}
```

Required behaviours once this is in place:
- Snapshots without `schemaVersion` are treated as version 0 (current)
- Snapshots with a future version fail explicitly rather than silently misreading
- The CHANGELOG records schema version bumps alongside tool version bumps

---

### B4 — Snapshot freshness

Offline evaluation may be deterministic while using evidence that is weeks old.
Surface `GeneratedAt` in the table header and add:

```
gh baseline --snapshot snap.json --max-snapshot-age 24h
```

This prevents an operator from accidentally treating a stale snapshot as a current
security audit.  The check is opt-in; CI pipelines that replay the same-day
snapshot can leave it unset.

---

### B5 — `WorkflowEvidence` struct

Today `internal/check/workflow.go` exports functions that checks call against raw
YAML strings.  The structural direction is to have the collector produce domain
facts and checks reason over those facts, not over YAML syntax.

```go
type WorkflowEvidence struct {
    Path        string
    Triggers    []string            // values from the on: block
    Permissions WorkflowPermissions // nil if not declared
    Actions     []ActionReference
    Secrets     []SecretReference   // includes inherited-secrets sentinel
}

type ActionReference struct {
    Kind  ActionReferenceKind // RemoteAction, ReusableWorkflow, LocalAction, DockerAction
    Ref   string
    Owner string
    Repo  string
}

type SecretReference struct {
    Name      string
    Inherited bool // true when secrets: inherit was used
}
```

This makes checks straightforward:

```
RemoteAction + RefIsFullSHA → pass
RemoteAction + RefIsTag     → fail
LocalAction                 → not applicable
UnableToInterpret           → unknown
```

It also makes Gaps 3 and 6 tractable: `Triggers` feeds the stale-secrets severity
adjustment; `ActionReference.Kind == ReusableWorkflow` feeds the callee-pinned
check.

This is a medium-sized change because it moves the YAML parsing from check time
into collection time and stores the structured evidence in the snapshot.  That
change has a user-visible benefit: `gh baseline --snapshot` can re-evaluate
trigger-aware stale-secrets without re-fetching the workflows.

---

### B6 — Separate baseline configuration from internal policy

The external review makes the right observation here.  The current `internal/baseline`
package does validation and normalization but exposes its parsed format directly to
checks.  A richer internal policy type would let the baseline JSON format evolve
without forcing changes through every check.  This is lower priority than B1–B5;
worth doing when check configuration becomes richer (e.g. per-check severity
overrides).

---

## Combined implementation sequence

### Immediate (one or two PRs, no data model changes)

| # | Work | Gap addressed |
|---|---|---|
| 1 | `--fail-on-unknown` flag + README update | Gap 1 |
| 2 | Parse `dependabot.yml` with `yaml.v3` | Gap 2 |
| 3 | Extend `secretRef` regex for bracket notation | Gap 3c |
| 4 | Detect `secrets: inherit` in `secretsUsed` | Gap 3b |

### Near-term (behavioural improvements, still pre-data-model)

| # | Work | Gap addressed |
|---|---|---|
| 5 | Parse `on:` block; adjust stale-secrets severity by trigger type | Gap 3a |
| 6 | Clarify `token-permissions` remediation message | Gap 4 |
| 7 | Fix `securityToggle` to evaluate private repos when field is present | Gap 5 |

### Prerequisites for step 9 (`Observation[T]`)

Step 9 is the root-cause fix for the nil-ambiguity problem.  Steps 1–7 mitigate
the symptoms (the audit is loud about unknown results) but don't eliminate the
ambiguity.  The gap between step 1 and step 9 requires:

**Step 8 must land first (non-negotiable):** `Observation[T]` changes the JSON
representation of `VulnReporting`, `SecurityPolicy`, and the `Security` map.
Any snapshot collected before the migration will have the old shape.  Without
`SchemaVersion`, the evaluator silently misreads old snapshots.  Add the version
field, write a compatibility shim for v0 snapshots (treat absent fields as
`ObservationError{ReasonCode: ReasonNotFound}` to be conservative), and update
the fixture files and round-trip tests before merging step 9.

**Go version check:** `Observation[T]` uses generics (Go 1.18+).  Confirm the
`go.mod` minimum version before writing the type.

**Collector migration scope:** Step 9 touches `internal/collect` and
`internal/snapshot` but should not change check semantics.  The collector
produces `Observation[T]` values; checks that currently read `*bool` or the
`Security` map need mechanical updates to read `.Value` and check `.State`, but
their pass/fail logic stays the same.  Write the migration as a pure refactor
with the existing check tests as the regression guard.

**Fixture updates:** `testdata/snapshot.json` and `testdata/real-world/snapshot.json`
will need to be regenerated or hand-migrated to the new schema.  The collect
tests in `internal/collect/collect_test.go` assert on `*bool` fields today and
will need updating.  Plan for one focused PR that updates both.

**What step 1 buys in the meantime:** `--fail-on-unknown` makes the audit
conservative — any nil that maps to `unknown` causes a non-zero exit — so the
ambiguity cannot silently produce a false pass.  The semantics improve (you know
*that* something is unknown) but not the precision (you don't know *why*).

### Medium-term (data model, incremental)

| # | Work | Notes |
|---|---|---|
| 8 | Add `SchemaVersion` to snapshot (B3) | Prerequisite for breaking schema changes |
| 9 | Introduce `Observation[T]` and `ReasonCode` (B1, B2); migrate `Security` map | Migrate collector and fixtures; check logic unchanged |
| 10 | Surface `GeneratedAt`; add `--max-snapshot-age` (B4) | Low effort once B3 is in |
| 11 | Introduce `WorkflowEvidence` struct in collector (B5) | Migrate checks to consume it |

### Longer-term (after data model stabilises)

| # | Work | Notes |
|---|---|---|
| 12 | `workflow.token-permissions-scope` check (Gap 4 stage 2) | Needs B5 for clean implementation |
| 13 | `workflow.reusable-callee-pinned` check (Gap 6) | Needs B5; extra API calls |
| 14 | Policy normalization layer (B6) | When configuration richness justifies it |

---

## Abstractions to avoid

The external review's warning is worth repeating: approximately 11 focused checks
do not justify a generic framework.  A function registry is sufficient.  The
useful abstractions are concrete:

```
Snapshot, Observation[T], ReasonCode, Policy, CheckID,
Finding, WorkflowEvidence, ActionReference
```

Do not introduce `Collector[T]`, `Rule[T]`, `Evaluator[T]`, or similar.
