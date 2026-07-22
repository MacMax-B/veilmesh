// Package client is the UI-independent Propagare client core.
//
// Frontends should depend on this package (or generated bindings around it),
// never on node transports or cryptographic primitives directly. The Core
// owns replication, signed receipts, storage audits, fallback, fetch, and
// capability-based deletion.
//
// The direct node transport supports CA-PKI-free, identity-pinned hybrid TLS,
// but remains a direct reference/bootstrap transport. A production frontend must
// use an audited onion or mix provider before claiming metadata anonymity.
package client
