# Propagare v0.1.0-preview.1 – Security Preview

## Einstufung

Diese Veröffentlichung ist eine **Developer-/Security-Preview** und ausdrücklich
kein allgemeiner Produktiv-Release des Messengers. Sie darf nicht für echte
vertrauliche Kommunikation empfohlen und nicht als metadatenanonym, vollständig
forward-secret oder kompromittierungsresistent beworben werden.

Die verbindliche Begründung und sämtliche Gates stehen in
[`RELEASE-READINESS.md`](RELEASE-READINESS.md); die Sicherheitsgrenzen stehen in
[`../SECURITY.md`](../SECURITY.md).

## Enthalten

- plattformneutraler Go-Core und Referenz-Node für Linux, macOS und Windows,
- hybride ML-KEM/X25519-Versiegelung und Ed25519/ML-DSA-65-Signaturen,
- identitätsgepinntes TLS 1.3 mit hybridem Schlüsselaustausch,
- crashfeste verschlüsselte Client-Persistenz und gehärteter Node-Store,
- persistente Lösch-Tombstones, Reparatur- und Replay-Zustände,
- signiertes Node-Verzeichnis mit Lease, Challenge und Seed-Quorum,
- ENIG-Mix-v2-Command-/Scheduler-Core,
- sichere Full-Node-Routenzuweisung: drei Mixes, ein Courier und drei Replikate,
- direkte hybrid authentisierte 1:1-WebRTC-DTLS-SRTP-Bausteine.

## Bewusst nicht aktiviert

- kein konkreter unabhängig auditierter PQ-Ratchet-Adapter,
- keine produktive Sphinx-/SURB-/Courier-/Relay-Laufzeit,
- kein auditierter RFC-9420-MLS-Adapter,
- keine mobilen oder Desktop-Endnutzer-Frontends,
- keine produktiven OS-/Hardware-Vault-Adapter,
- keine öffentliche unabhängige Seed-/Relay-Infrastruktur.

Die fail-closed Produktionsschnittstellen werden ohne diese Komponenten nicht
geöffnet. Der direkte HTTPS-Pfad bleibt ein Entwicklungs-/Bootstrap-Pfad und
liefert keine Metadatenanonymität.

## Artefakte und Prüfung

Der Release-Builder erzeugt `propagare-node` für Linux amd64/arm64, macOS
amd64/arm64 und Windows amd64. `SHA256SUMS`, `BUILDINFO.txt` und
`THIRD_PARTY-MODULES.txt` gehören zu jedem Bundle. Die Binärdatei meldet Version
und Commit über `--version`.

Vor dem Tag wurden Formatierung, Modulprüfung, alle Tests, Race-Tests, `go vet`,
Schwachstellenprüfung, unterstützte Cross-Builds und reproduzierbare Builds
ausgeführt.
