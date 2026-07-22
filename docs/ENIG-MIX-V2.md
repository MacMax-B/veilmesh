# ENIG-Mix v2

## Status

ENIG-Mix v2 ist das moderate Propagare-Orchestrierungsprotokoll für
metadatenresistentes asynchrones Messaging. Es definiert Command-Grenzen,
Verkehrsform, Provider-Anforderungen und Fehlerverhalten, aber absichtlich keine
neue kryptografische Primitive und kein eigenes Onion-Paketformat.

Implementiert sind Parser, Queue und Scheduler. Nicht enthalten sind ein
unabhängig auditierter PQ-hybrider Sphinx-/Onion-Provider, Courier, Mix-PKI,
uniforme Downlink-Infrastruktur und reale Relays. Direkter HTTP-Betrieb ist nicht
anonym; v2 allein begründet keine produktive Metadatenanonymität.

## Sicherheitsziel und Annahmen

Während eines ununterbrochenen aktiven Laufs sollen außen echte Commands,
anonyme Polls und Cover-Pakete nicht unterscheidbar sein. Zusammen mit einer
auditierten Mix-Schicht soll dies die Zuordnung von Accounts, Nachrichtenanzahl
und einzelnen Send-/Empfangsaktionen erschweren.

Das setzt mindestens voraus:

- ein ehrlicher, nicht kolludierender Hop je Pfad,
- ausreichend viele gleichzeitig gleich getaktete Clients,
- kompromisslose Einhaltung genau des öffentlichen v2-Profils,
- einen tatsächlich auditierten PQ-hybriden Paket- und Linkprovider,
- uniforme Antworten, korrekte SURBs, Replay-Schutz und Routing-Key-Löschung,
- nicht kompromittierte Endgeräte, Vaults und Zufallszahlengeneratoren.

Nicht verhindert werden vollständige Relay-Kollusion, Endgeräte-Malware,
absichtlich verratende Teilnehmer, Suspend-/Offline-Lücken, physische
Langzeitbeobachtung, Funk-/Betriebssystemseitenkanäle und Dienstverweigerung.
Das moderate Profil bietet weniger zeitliche Deckung und höhere Latenz als das
historische v1-Hochlastprofil.

## Schichten

```text
signierte ENIG-Anwendungsnachricht
        │
        ▼
auditierter PQXDH-/Double-or-Triple-Ratchet
        │  pro Empfängergerät separater Ciphertext
        ▼
ENIG-Mix Command v2 (maximal 2 KiB Payload)
        │
        ▼
auditierter PQ-hybrider Sphinx-/Onion-Provider
        │  feste 8-KiB-Pakete, SURB, Replay-Tag
        ▼
persistente PQ-hybrid geschützte Entry-Verbindung
        │
        ▼
mindestens drei unabhängige Mix-Schichten
        │
        ▼
Courier/Storage/Directory ── uniforme feste Antwort über SURB
```

Die Mix-Schicht erhält nur bereits verschlüsselte Commands und einmalige
Capabilities. Entry- und Zwischenhops dürfen weder Kontakte noch Route-Tags
protokollieren. Der direkte IP-Node-Verzeichnisabruf ist ein separater
Bootstrap-/Kontrollpfad und besitzt keine Metadatenanonymitätsgarantie.

## Command v2

Ein Command bindet:

- Version `2`,
- zufällige 32-Byte-Request-ID in kanonischem Base64url,
- Store, Directory Lookup/Publish, Device Sync oder Delete,
- millisekundengenormte Erstellungs- und Ablaufzeit,
- höchstens 2 KiB bereits verschlüsselte Payload.

Das JSON-Encoding ist auf 4 KiB begrenzt, die Lebenszeit auf 15 Minuten.
Unbekannte Felder/Typen, mehrere JSON-Werte, abgelaufene Commands und v1 werden
vor Provider- oder Netzarbeit abgelehnt. Größere Operationen brauchen eine
separate authentifizierte Fragmentierung oberhalb des Commands; sie ist noch
nicht implementiert und darf Grenzen nicht umgehen.

Poll ist strikt lesend. Löschen bleibt eine getrennte Operation mit zufälliger
Capability und darf erst nach erfolgreicher authentifizierter Rekonstruktion
ausgelöst werden. Ein Retry erhält eine neue Request-ID und ein neues
Onion-Paket.

## Moderates einheitliches Slotprofil

Es gibt genau ein zulässiges v2-Profil:

- exakt ein 8-KiB-Upstream-Paket alle 5 Sekunden,
- exakt einen anonymen Poll in jedem sechsten Slot, also alle 30 Sekunden,
- in jedem übrigen Slot ein vorbereitetes Real- oder frisches Cover-Paket,
- uniforme feste Antworten für Real, Poll und Cover,
- standardmäßig höchstens 1024, absolut höchstens 4096 vorbereitete Commands.

Bei Dauerbetrieb entstehen 141.557.760 Bytes beziehungsweise rund 135 MiB
Upstream pro Tag und Client, zuzüglich Link-/Netzwerk-Overhead und Downlink. Das
Profil darf nicht abhängig von Aktivität, Kontakt, Gerätetyp oder Akkustand
gewechselt werden. Eine spätere Änderung braucht eine neue Protokollversion und
eine ausreichend große gemeinsame Anonymitätsmenge.

Vor jedem Slot wird Cover vorbereitet. Variable Real-Command-Arbeit geschieht
beim Enqueue außerhalb des Sendemoments. Ein abgelaufener Command wird durch
Cover ersetzt. Verpasster Slot, Zeitbudgetüberlauf, falsche Paketgröße oder
Linkfehler beendet den sicheren Lauf; direkter HTTP-Fallback ist verboten.

## Zwingende Provider-Grenzen

`mixtransport.NewScheduler` verlangt deklarierte Eigenschaften:

- mindestens drei Mix-Hops aus unabhängigen Sicherheitsdomänen,
- feste Paketlänge, geschichtetes Mixing und Authentifizierung je Hop,
- Replay-Schutz und uniforme Antworten/SURBs,
- PQ-hybriden Onion-Schutz und forward-secure Routing-Key-Löschung,
- benannte unabhängige Prüfung,
- persistente authentisierte Entry-Verbindung mit PQ-hybridem KEX,
- feste Link-Frames und deaktivierte Redirects.

Die Felder sind Fail-Closed-Integrationssperren, kein Auditbeweis. Quellcode,
Build, Relaybetrieb, Konfiguration und Bericht bleiben Teil der Trusted Computing
Base. Als technische Referenz dienen feste Sphinx-Pakete, Replay-Caches,
Schlüsselrotation und Layer-Topologie der
[Katzenpost-Spezifikation](https://katzenpost.network/docs/specs/mixnet/).
Ein Provider muss die zusätzliche PQ-Hybridisierung eigenständig auditiert
nachweisen. ML-KEM ist in [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
standardisiert.

## Aktivierungskriterien

Vor einem Produktivflag sind mindestens nötig:

1. reproduzierbare Interoperabilitätsvektoren,
2. zwei unabhängige Kryptografie-/Protokollaudits,
3. PCAP-/NetFlow-Tests für Real-vs-Cover-Klassifikation,
4. Intersection-, Statistical-Disclosure- und Langzeittests,
5. Sybil-, Relay-Kollusions- und Mix-PKI-Split-Simulationen,
6. Suspend/Resume-, Funkwechsel-, Clock-Jump- und Akkutests,
7. fester Courier-/Downlink-Durchsatz,
8. überprüfte Builds und quorumvalidierte Mix-PKI-Epochen.
