# Propagare v0.1.0-preview.2 – Security Preview

## Einstufung

Diese Veröffentlichung ist eine **Developer-/Security-Preview** und kein
allgemeiner Produktiv-Release des Messengers. Sie darf nicht für echte
vertrauliche Kommunikation empfohlen und nicht als metadatenanonym,
forward-secret oder Sybil-resistent beworben werden.

Die verbindlichen Restpunkte stehen in [`RELEASE-READINESS.md`](RELEASE-READINESS.md).

## Änderungen gegenüber preview.1

- Sichere Windows-DACLs werden gegen die kanonische Windows-Darstellung aus
  getrennten effektiven und inherit-only ACEs validiert.
- Fremde SIDs, geerbte ACEs, doppelte Grants und unvollständige
  Vererbungsrechte werden weiterhin fail-closed abgewiesen.
- Windows-spezifische Negativtests prüfen DACL-Manipulation und unsichere
  Vererbungsflags.
- Client- und Node-Persistenztests berücksichtigen Windows-Dateisperren, ohne
  Sicherheitsprüfungen zu umgehen.
- Gleichzeitige In-Prozess-Provisionierung einer Node-Identität ist
  deterministisch serialisiert; die prozessübergreifende Exklusivität wird
  weiterhin durch Betriebssystem-Dateisperren erzwungen.

## Enthalten

- plattformneutraler Go-Core und Referenz-Node für Linux, macOS und Windows,
- hybride ML-KEM/X25519-Versiegelung und Ed25519/ML-DSA-65-Signaturen,
- identitätsgepinntes TLS 1.3 mit hybridem Schlüsselaustausch,
- crashfeste verschlüsselte Client-Persistenz und gehärteter Node-Store,
- signiertes Node-Verzeichnis mit Lease, Challenge und Seed-Quorum,
- ENIG-Mix-v2-Command-/Scheduler-Core und diverse Full-Node-Routenzuweisung.

## Bewusst nicht aktiviert

- kein unabhängig auditierter PQ-Ratchet-Adapter,
- keine produktive Sphinx-/SURB-/Courier-/Relay-Laufzeit,
- kein auditierter RFC-9420-MLS-Adapter,
- keine öffentliche Infrastruktur aus mindestens fünf organisatorisch und
  netztopologisch unabhängigen Seeds und Relays,
- keine produktiven OS-/Hardware-Vault-Adapter oder fertigen Endnutzer-Apps.

Ein einzelner Server kann Ein- und Ausgangsverkehr korrelieren. Der direkte
HTTPS-Pfad liefert daher ausdrücklich keine Metadatenanonymität.

## Artefakte und Prüfung

Der Release-Builder erzeugt `propagare-node` für Linux amd64/arm64, macOS
amd64/arm64 und Windows amd64. `SHA256SUMS`, `BUILDINFO.txt` und
`THIRD_PARTY-MODULES.txt` gehören zum Release. Vor dem Tag liefen Formatierung,
Modulprüfung, `go vet`, alle Tests, Race-Tests, die Prüfung bekannter
erreichbarer Schwachstellen, Cross-Builds und reproduzierbare Builds. Die
plattformgebundenen Persistenztests liefen zusätzlich auf macOS und Windows.
