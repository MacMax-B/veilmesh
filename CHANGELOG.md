# Changelog

Alle wesentlichen Änderungen an Propagare werden in dieser Datei dokumentiert.

## Unreleased

- Expliziter Ein-Node-Direktbootstrap mit automatischer Hochstufung auf eine
  vollständige 3-Mix-/1-Courier-/3-Replikat-Route, sobald ein validierter
  Scheduler und sieben diverse Full Nodes verfügbar sind.
- Persistierbares `RequireFullMix`-Mindestniveau verhindert stille Downgrades
  bei kleinen, kollabierten oder manipulierten Directory-Sichten.
- Native macOS-SwiftUI-App auf dem separaten Client-Branch mit Liquid-Glass-
  Gestaltung, Netzwerk-Sicherheitsdashboard, deutscher/englischer
  Lokalisierung und fail-closed Core-Grenze.
- Monochromes macOS-Messenger-Design mit nativer linker Glass-Navigation,
  minimalistischem `#000000`/`#FFFFFF`-Chat und akzentfarbfreier
  Sicherheitskennzeichnung.

## 0.1.0-preview.2 – 2026-07-22

- Windows-DACL-Prüfung unterstützt die sichere kanonische Aufteilung von
  effektiven und vererbbaren Zugriffsrechten, ohne fremde, geerbte oder
  doppelte Grants zuzulassen.
- Neue Windows-Negativtests prüfen fremde SIDs und unsichere
  Vererbungsvarianten auf dem echten Windows-CI-Runner.
- Persistenz- und Schlüssel-Provisionierungstests verhalten sich unter den
  unterschiedlichen Datei-Locking-Modellen von Windows und Unix deterministisch.
- In-Prozess-Provisionierung einer neuen Node-Identität ist serialisiert;
  prozessübergreifende und lebenslange Exklusivität bleibt durch OS-Dateisperren
  geschützt.

Diese Version bleibt eine Developer-/Security-Preview. Insbesondere sind der
auditierte Onion-/SURB-Provider und eine unabhängige reale Mixnet-Infrastruktur
weiterhin nicht enthalten.

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
