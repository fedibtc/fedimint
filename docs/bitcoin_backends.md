# Guardian Bitcoin backends

Configured Bitcoin RPC endpoints, including Esplora, are trusted inputs to a
guardian. Esplora is a trusted chain oracle: Fedimint does not independently
verify its chain selection, work, consensus rules, or freshness. Block payload
integrity checks and chain-identity comparisons are defense in depth against
inconsistent responses and misconfiguration, not the basis of this trust
model. Use operator-controlled or explicitly trusted services, with encrypted
transport across untrusted networks. A shared public provider can correlate
guardian activity and influence multiple guardians at once.

In hybrid mode (`FM_BITCOIND_URL` and `FM_ESPLORA_URL` together), available
endpoints must agree on the height-1 block hash at startup. If only one
responds, its trusted identity is remembered for the process lifetime; this
allows startup on Esplora while bitcoind is offline without another operator
option. An endpoint's successfully checked identity is invalidated after an
observed RPC failure, so recovery checks it again before use. These are not
per-request identity proofs. Restart the guardian when deliberately changing
chains.

Reads prefer bitcoind if it is not in initial block download and its reported
tip is at least Esplora's. Otherwise they use eligible Esplora. Health
snapshots last five seconds; probes run concurrently with a five-second
deadline and failed endpoints wait thirty seconds before another health
probe. This bounds latency from an unavailable secondary without spawning
overlapping blocking Core probes. Normal data requests retain their transport
timeouts. Any read error may be retried on another eligible backend. A
known-stale or IBD primary is not used as a read fallback. Neither endpoint
proves freshness when the other is unavailable.

Broadcast is deliberately bitcoind-first: Esplora receives the transaction
only if the primary attempt fails. A reachable, network-isolated bitcoind can
accept a transaction without propagating it. Fedimint relies on multiple
guardians rebroadcasting the same peg-out, assuming at least one broadcaster
has working Bitcoin connectivity. Successful local submission is not proof of
propagation, so the federation's normal rebroadcast and confirmation handling
remain necessary. Read-health failures do not suppress broadcast attempts;
backend identity checks still apply.

Esplora sees synchronization queries and, when used for broadcast fallback,
complete peg-out transactions and guardian-origin timing. Any primary
broadcast error, including policy rejection, may trigger this disclosure.
Only configure a fallback if these trust and privacy consequences are
acceptable.
