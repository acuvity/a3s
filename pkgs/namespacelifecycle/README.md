# Namespace-owner lifecycle boundary

This package is **dormant, explicit source composition**, not runtime enablement or production qualification. Normal namespace processor construction/main configuration remains unchanged. The owner processor and participation command must be selected explicitly. Owner CRUD composition requires a request-bound native authority factory and rechecks the original user's current mutation right at the source boundary; participant authority cannot substitute. Legacy/direct writers and shared cleaners cannot be assumed to cooperate.

## Records and ownership

- Native namespace ID, canonical name and ordered ancestor IDs are immutable. A name is not an incarnation ID. Coordination records live at storage namespace `/`, outside ordinary descendant cleanup.
- Version 1 remains a low-level storage kernel. Version 2 retains one source Creation and one source Deletion operation in the same private record; no parallel journal or silent v1 upgrade is used.
- The native unique `zone,zHash` index hashes the immutable namespace name for this identity. Different-ID reuse conflicts with a retained name; collisions conservatively deny. There is no reopen, record deletion, TTL or automatic reset.
- Explicit quiescent root bootstrap requires exact native source evidence and its private bootstrap marker. Root `/` cannot be deleted. Missing/unqualified descendants are never adopted online.
- Metadata, digests, callbacks and snapshots are not grants. The outer native authorization and source/participant adapters establish authority and exact evidence.

## Creation

`PrepareOwnerNamespace` normalizes a detached, callback-free JSON body once; both the request digest and native BSON come from that owned body. The namespace-only adapter preserves the preallocated ID, native clock/hash and private creation marker instead of allowing ordinary manipulator creation to replace the ID.

An acknowledged creation claim grants one live invocation. It records ancestor attempts, acquires exact root-to-parent topology pins, verifies source incarnations, and claims one native insertion. Known zero-match pin contention may retry serially at most four times; unknown writes never retry. A cold reconstruction never initiates another insert or enrollment.

The Hanni recipient consumes a separate acknowledged `attempted → claimed` enrollment transition before initializing its registry. Source read-back does not renew that grant. Ready requires exact native marker evidence, all configured authenticated participant enrollments, and terminal/released ancestor pins. Current source/participant evidence is rechecked before readiness. Returned state is detached; neither the closure nor a token is persisted.

## Deletion

`BeginOwnedDeletion` records one immutable intent and denies new topology admission while preserving accepted pins. Its live owner acquires ancestor pins, seals the target, and checks the exact native source and leaf topology. Root, nonleaf and unqualified cases remain Held.

Participants must first fence their new registrations and prove every accepted writer terminal. Their exact retained proofs are recorded before the native-delete stage. A currently authorized subsequent DELETE may claim that **still-unattempted** stage through a fresh acknowledged `closing → attempted` CAS; reading an attempted state can never repeat native deletion. The separate `Reconcile` entry point never dispatches a native delete or prepares participants.

Only an acknowledged exact one-row native deletion permits the source result to become durable. Missing rows, a deadline or a lost acknowledgement are not deletion proof. Ancestor release follows terminal source evidence. Ambiguous or missing release evidence remains conservative Held rather than clearing another operation.

The deleted name stays tombstoned. The explicit owner processor emits cache invalidation using an Update notification, not a legacy destructive name-only deletion notification or NamespaceDeletionRecord. Terminal DELETE replays reissue this safe invalidation so a lost acknowledgement/notification cannot permanently skip it; delivery is not claimed exactly-once. This is **not resource cleanup or safe recreation**.

## Transport and authority

The explicit `/namespaceparticipations` processor inspects current owner state and consumes enrollment claims under native token verification, current ID/IAT revocation and uncached resource/IP/restriction permissions. InspectDeletion exposes only the exact retained source intent. No normal main route registration enables it.

The bounded Hanni adapters use trusted configured endpoints and token providers, refuse redirects/retries, and validate exact source/enrollment/drain bindings. Read-only inspection never initializes a missing gate. Enrollment proof and publication-only drain proof remain distinct. No caller-supplied Boolean or digest establishes writer/cleaner coverage.

## Bounds

- At most 64 topology pins, 32 namespace levels, 16 participants and 64 KiB canonical lifecycle JSON. Hanni's development registration profile is narrower: at most 16 ancestors and 128 lifetime registrations; unsupported inputs hold.
- Creation/deletion metadata bytes and remaining CAS revisions are reserved before admission. Reservation is not disk availability. Unknown work is never evicted for capacity.
- Each cooperative owner attempt is capped at 30 seconds; data/HTTP attempts use at most ten seconds. These are operation bounds, not leases, rollback or expiry of retained uncertainty.
- Namespace preparation is at most 32 KiB. Reads use bounded hinted results and strict BSON scalar/duplicate/shard checks. Exact deletion matches the immutable tuple independently of mutable body fields.
- No application-level native insert/delete retry, upsert or transaction is claimed. Driver retryable writes and concurrent privileged DDL require independent qualification; owned Mongo fixtures explicitly disable retryable writes.

## Verification and limits

```sh
GOTOOLCHAIN=go1.26.6 GOWORK=off GOFLAGS='-mod=readonly -p=4' GOMAXPROCS=4 \
  go test -vet=off -tags=integration -race ./pkgs/namespacelifecycle ./internal/processors -count=1 -timeout 3m
```

Fixtures create only owned temporary Mongo/HTTP processes. They cover immutable identity and body binding, single-use claims, paused/uncertain work, conditional native mutation, strict type/capacity checks, and denial/replay behavior. The opt-in two-process tracer additionally exercises real A3S/Hanni clients, processors, signed tokens and native permission retrieval. Test-only participant/qualification callbacks are not production writer coverage.

Generic cleanup/recreation, all native scheduling/threat/migration writers, shared cleaners, managed failover, mixed versions, rollback and runtime activation remain separate requirements. Do not infer full namespace safety or complete offline detection from a component or owned-fixture pass.
