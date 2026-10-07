# Namespace lifecycle storage boundary

This is a **dormant private storage kernel**, not a completed namespace deletion protocol. No ordinary processor, runtime option or participant endpoint uses it yet. The namespace owner and Hanni still require topology, registration, authenticated participant and cleanup composition.

## Invariants

- Native namespace ID plus canonical name and exact ordered ancestry are immutable. Names are not incarnation IDs. Records live at storage namespace `/`, outside ordinary descendant cleanup.
- Explicit trusted bootstrap/enrollment only. Missing records are never created by reads or mutations. Enrollment requires retained ancestor reservations; this store does not establish those reservations, namespace existence or authorization.
- The existing native unique `zone,zHash` index hashes the immutable namespace **name** for this identity. A different native ID cannot reopen a retained name. Hash collisions conservatively reject enrollment. There is no reopen, deletion, expiry or TTL for coordination.
- An acknowledged matching admission CAS grants one live invocation. Read-back, existing pins, ambiguous responses and retries do not restore authority. An outer durable operation record must prevent a completed operation from acquiring a new pin later.
- Seal competes on the same document as admission and preserves every pin. Root `/` cannot be sealed/deleted. Required participants are frozen in the intent.
- Exact terminal proof precedes release. Only after local pins settle may exact configured participant proofs be recorded. An acknowledged `closing → attempted` CAS permits one native deletion invocation. Reading `attempted` cannot dispatch another.
- Terminal/drain/deleted confirmation methods are trusted adapter boundaries. Their metadata/digests are **not** self-authenticating evidence. The adapter must independently verify the exact mutation or live no-dispatch authority, participant identity/fence, and deleted native incarnation. Missing data, a timeout, canceled context or process death proves none of these.
- `deleted` remains fenced. Cleanup/recreation is not authorized by this kernel, and generic name-only cleanup is not completion proof.

## Bounds and persistence

At most 64 retained topology/enrollment pins, 32 namespace levels, 16 participants and 64 KiB of canonical JSON; actual admission may be lower because it reserves worst-case terminal and deletion metadata bytes and enough CAS revisions for terminal/release/drain progress. Reservation is not disk availability. Unknown work is never evicted for capacity.

Each data attempt has a ten-second context, bounded index inspection, hinted two-row reads and at most one conditional write with primary/majority concerns. No application retry, upsert, multi-document transaction, rollback or lease is claimed. Native BSON types, duplicate fields, canonical JSON, immutable identity/shard fields and the full typed snapshot are checked before CAS. Concurrent privileged DDL and uncooperative writers remain outside the protocol.

## Focused proof

```sh
GOWORK=off GOFLAGS='-mod=readonly -p=4' GOMAXPROCS=4 \
  go test -vet=off -tags=integration -race ./pkgs/namespacelifecycle -count=1 -timeout 3m
```

Integration fixtures start only an owned ephemeral Mongo process. They cover retained admissions through deletion, admission/seal races, ambiguous acknowledgements and store reconstruction, no read-back redispatch, same-name replacement refusal, bounded terminal capacity and BSON numeric/CAS aliases. Store reconstruction is not Mongo failover/restart proof.

This does not qualify HTTP/auth composition, descendants/topology admission, every native writer/cleaner, managed Mongo, mixed versions, rollback, runtime activation or source ownership of supplied proofs.
