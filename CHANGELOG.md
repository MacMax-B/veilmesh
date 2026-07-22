# Changelog

Alle wesentlichen Änderungen an Propagare werden in dieser Datei dokumentiert.

## Unreleased

- Keine Änderungen.

## 0.1.0-preview.1 – 2026-07-22

- Erste reproduzierbar paketierte Security Preview des Propagare-Cores und der
  Referenz-Node.
- Persistenter, begrenzter und crashfester Client- und Node-Zustand einschließlich
  Lösch-Tombstones, Store↔Identitätsbindung und exklusiver Laufzeitleases.
- Hybrid signierte, replaygeschützte Geräte-, Directory-, Nachrichten-, Gruppen-
  und Node-Operationen mit strikten Parser- und Größenlimits.
- Identitätsgepinntes TLS 1.3 mit hybridem X25519/ML-KEM-Schlüsselaustausch für
  produktive Direktlinks.
- Einheitliche Full-Node-Routenzuweisung mit drei Mix-Hops, einem Courier und drei
  Speicherreplikaten ohne Identitäts- oder grobe Netzpräfix-Wiederholung.
- Gehärtete CI mit Tests, Race-Tests, Vet, Schwachstellenprüfung, Cross-Builds und
  reproduzierbaren Node-Binaries.

Diese Version ist kein allgemeiner Produktiv-Release für vertrauliche
Endnutzerkommunikation. Die zwingenden Restpunkte stehen in
`docs/RELEASE-READINESS.md`.
