# VeilMix v1

> **Außer Betrieb:** Dieses Hochlastprofil ist durch VeilMix v2 ersetzt. Der
> aktuelle Parser akzeptiert keine v1-Commands. Diese Datei bleibt ausschließlich
> als historische Versionsdokumentation erhalten; neue Integrationen müssen
> [`VEILMIX-V2.md`](VEILMIX-V2.md) verwenden.

## Status

VeilMix v1 ist das VeilMesh-eigene Orchestrierungsprotokoll für
metadatenresistentes, asynchrones Messaging. Es definiert Verkehrsform,
Anwendungsbefehle, Provider-Anforderungen und Fehlerverhalten. Es definiert
absichtlich weder eine neue kryptografische Primitive noch ein neues Onion-
Paketformat.

Der eingecheckte Stand enthält den größen- und zeitbegrenzten Command-Parser und
den konstant getakteten Scheduler. Ein unabhängig auditierter PQ-hybrider
Sphinx-/Mixnet-Paketprovider und eine reale Mix-Infrastruktur sind noch nicht
integriert. Deshalb darf dieser Stand nicht als produktiv anonym bezeichnet
werden.

## Sicherheitsziel und Angreifermodell

VeilMix soll gegenüber einem globalen passiven Netzbeobachter und teilweise
kompromittierten Relays verbergen:

- welcher Account eine gespeicherte Nachricht erzeugt oder abruft,
- welche zwei Accounts miteinander kommunizieren,
- wie viele echte Nachrichten ein dauerhaft verbundener Client sendet oder
  empfängt,
- ob ein einzelner fester Slot eine echte Nachricht, einen Poll oder Cover
  enthält.

Die Behauptung setzt voraus:

- beide Endgeräte und deren Zufallszahlengenerator sind nicht kompromittiert,
- der Client bleibt während des betrachteten Zeitraums online und hält das
  gewählte öffentliche Verkehrsprofil ein,
- mindestens ein Mix-Hop jedes Pfads ist ehrlich und nicht mit Entry und
  Zielservice kolludiert,
- Paketprovider, Ratchet, Secret Vault und Plattformadapter entsprechen ihrem
  Audit,
- genügend andere Clients benutzen dasselbe Paket-, Slot- und Pollprofil, damit
  eine relevante Anonymitätsmenge entsteht.

Nicht verhindert werden Endgeräte-Malware, absichtlich verratende Teilnehmer,
vollständige Relay-Kollusion, langfristige physische Beobachtung eines einzelnen
Geräts, Funk-/Betriebssystem-Seitenkanäle, Dienstverweigerung und Traffic-Lücken
während Suspend, Netzausfall oder Akkuabschaltung.

## Schichten

```text
signierte ENIG-Anwendungsnachricht
        │
        ▼
auditierter PQXDH-/Double-or-Triple-Ratchet
        │  pro Empfängergerät separater Ciphertext
        ▼
VeilMix Command v1 (maximal 20 KiB Payload)
        │
        ▼
auditierter PQ-hybrider Sphinx-/Onion-Provider
        │  feste 32-KiB-Pakete, SURB, Replay-Tag
        ▼
persistente PQ-hybrid geschützte Entry-Verbindung
        │
        ▼
mindestens drei unabhängige Mix-Schichten
        │
        ▼
Courier/Storage/Directory ── uniforme feste Antwort über SURB
```

Die Inhaltsverschlüsselung kennt die ENIG-Konten. Der Mix-Transport erhält nur
bereits verschlüsselte Commands und einmalige Capabilities. Die Entry-Verbindung
sieht feste Pakete, aber keine Route-Tags oder Kontakte. Ein Mix-Hop kennt nur
vorherigen und nächsten Hop. Storage und Directory kennen keinen Client-
Netzwerkstandort.

## Command v1

Ein Command bindet:

- Version `1`,
- zufällige 32-Byte-Request-ID in kanonischem Base64url,
- einen bekannten Operationstyp,
- millisekundengenormte Erstellungs- und Ablaufzeit,
- höchstens 20 KiB bereits verschlüsselte Payload.

Erlaubte Typen sind Store, Directory Lookup/Publish, Device Sync und Delete.
Unbekannte Typen/Felder, nachgestellte JSON-Werte, Lebenszeiten über 15 Minuten
und Encodings über 28 KiB werden vor Provider- oder Netzarbeit abgelehnt.

Poll liest ausschließlich und löscht niemals. Ein Delete-Command darf erst nach
erfolgreicher authentifizierter Rekonstruktion erzeugt werden und muss die
zufällige Lösch-Capability des höheren Speicherprotokolls enthalten. Retries
erzeugen eine neue Request-ID und ein neues Onion-Paket; das idempotente Item-ID
des Speicherprotokolls bleibt davon getrennt.

Große Nachrichten und Dateien benötigen eine separate authentifizierte
Fragmentierung oberhalb des Commands. Diese Fragmentierung ist in v1 noch nicht
implementiert; ein Provider darf die Größenprüfung nicht umgehen.

## Konstantes Slotprotokoll

VeilMix v1 besitzt genau ein zulässiges öffentliches Verkehrsprofil:

- exakt ein 32-KiB-Upstream-Paket pro Sekunde,
- exakt einen anonymen Poll in jedem fünften Slot,
- in jedem übrigen Slot genau ein vorbereitetes Real- oder Cover-Paket,
- uniforme feste Antworten für Real, Poll und Cover,
- maximal 1024 vorbereitete Commands, hart begrenzt auf 4096.

Vor jedem Slot erzeugt der Scheduler unabhängig von der Queue ein frisches
Cover-Paket. Variable Arbeit für echte Commands findet beim Enqueue und damit
außerhalb des Sendeslots statt. Poll-Slots sind positionsgebunden und unabhängig
von vorhandenen Nachrichten. Ein abgelaufener Command wird durch Cover ersetzt;
es entsteht kein leerer Slot.

Ein verpasster Slot, ein Zeitbudgetüberlauf, eine ungültige Paketgröße oder ein
Linkfehler beendet den sicheren Lauf. Der Client darf in diesem Zustand nicht
still auf direktes HTTP zurückfallen.

32 KiB pro Sekunde entsprechen ungefähr 2,6 GiB Upstream pro Tag und Client.
Das Referenzprofil priorisiert die Verkehrsform, ist aber für viele Mobilgeräte
praktisch zu teuer. Der v1-Konstruktor lehnt andere Paketgrößen, Slotintervalle
und Pollkadenzen ab, weil sie Clients fingerprintbar machen würden. Ein
langsameres Profil benötigt eine neue, quorum-signierte Protokollversion und eine
eigene ausreichend große Anonymitätsmenge; es darf niemals abhängig von einer
konkreten Unterhaltung umgeschaltet werden.

## Provider-Anforderungen

`mixtransport.NewScheduler` akzeptiert nur Adapter, die mindestens deklarieren:

- drei Mix-Hops aus unabhängigen Sicherheitsdomänen,
- feste Paketlänge und geschichtetes Mixing,
- Authentifizierung und Replay-Schutz pro Hop,
- uniforme Antworten/SURBs,
- PQ-hybriden Schutz des Onion-Pakets,
- regelmäßig gelöschte forward-secure Routing-Schlüssel,
- eine benannte unabhängige Prüfung,
- persistente, authentisierte Entry-Verbindung mit PQ-hybridem KEX,
- feste Link-Frames und deaktivierte Redirects.

Diese Eigenschaften im Interface sind nur Integrationssperren. Ein beliebiger
Adapter könnte lügen; Quellcode, Build, Konfiguration, Relays und Auditbericht
bleiben Teil der Trusted Computing Base.

Als Referenz für die Mix-Schicht dienen die öffentlich spezifizierten festen
Sphinx-Pakete, Replay-Caches, Schlüsselrotation und Layer-Topologie von
[Katzenpost](https://katzenpost.network/docs/specs/mixnet/). VeilMesh übernimmt
kein Paketformat ungeprüft. Ein Provider muss zusätzlich den PQ-hybriden
Onion-Schutz nachweisen. ML-KEM selbst ist in
[FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) standardisiert; hybride
HPKE- und TLS-Verwendungen befinden sich weiterhin in IETF-Standardisierung.

## Post-Quantum-Ebenen

- Account-/Geräteauthentisierung: Ed25519 plus ML-DSA-65; beide müssen gelten.
- Bootstrap-HPKE: ML-KEM-768 plus X25519.
- Nachrichten: auditierter hybrider PQXDH-/Ratchet-Provider mit Forward Secrecy,
  Post-Compromise Security und Löschung verbrauchter Schlüssel.
- Gruppen: RFC-9420-MLS-Provider; PQ-hybride Ciphersuites erst nach stabiler,
  auditierter Integration.
- Mix-Pakete: PQ-hybrider, auditierter Onion-Provider zwingend; noch offen.
- Link: PQ-hybrider TLS-/Noise-Provider zwingend; noch offen.
- Direkte Calls: derzeit nur klassische ECDHE-Forward-Secrecy, nicht PQ-sicher.

„Post-Quantum“ auf einer Ebene kompensiert keine klassische Schwäche auf einer
anderen Ebene. Insbesondere schützt PQ-Inhaltsverschlüsselung zwar den Klartext,
aber nicht rückwirkend die Route eines klassisch aufgezeichneten Onion-Pakets.

## Verifikation vor Aktivierung

Vor einem Produktivflag sind mindestens erforderlich:

1. reproduzierbare Interoperabilitätsvektoren des ausgewählten Paketproviders,
2. zwei unabhängige Kryptografie-/Protokollaudits,
3. NetFlow-/PCAP-Simulationen für Real-vs-Cover-Klassifikation,
4. Langzeittests gegen Intersection- und Statistical-Disclosure-Angriffe,
5. Sybil-/Relay-Kollusions- und PKI-Split-Simulationen,
6. Suspend/Resume-, Funkwechsel-, Clock-Jump- und Akku-Tests,
7. Nachweis, dass Courier-Replikation und Antworten festen Durchsatz behalten,
8. überprüfte Builds und signierte, quorumvalidierte Mix-PKI-Epochen.
