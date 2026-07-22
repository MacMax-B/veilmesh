# ENIG-Mix v2

## Status

ENIG-Mix v2 ist das moderate Propagare-Orchestrierungsprotokoll für
metadatenresistentes asynchrones Messaging. Es definiert Command-Grenzen,
Verkehrsform, Provider-Anforderungen und Fehlerverhalten, aber absichtlich keine
neue kryptografische Primitive und kein eigenes Onion-Paketformat.

Implementiert sind Parser, Queue, Scheduler und die verifizierte zufällige
Full-Node-Routenzuweisung. Nicht enthalten sind ein unabhängig auditierter
PQ-hybrider Sphinx-/Onion-Provider, die Courier-/Relay-Laufzeit, Mix-PKI,
uniforme Downlink-Infrastruktur und reale Relays. Direkter HTTP-Betrieb ist nicht
anonym; v2 allein begründet keine produktive Metadatenanonymität.

## Bootstrap und automatische Hochstufung

Ein neues Netz kann mit einer verifizierten Node im direkten Bootstrapmodus
beginnen. Dieser Pfad überträgt weiterhin nur Ende-zu-Ende-verschlüsselte Daten
über identitätsgepinntes TLS, verbirgt aber weder Client-IP noch Zeitpunkt,
Häufigkeit oder Datenvolumen vor dieser Node. Er darf nur über das explizite
`AllowDirectBootstrap` gewählt und in der UI niemals als Mix angezeigt werden.

`mixtransport.SelectOperationalRoute` prüft immer den vollständigen
Directory-Kandidatensatz. Liegen ein aktuell validierter `Scheduler` und sieben
verschiedene Identitäten aus sieben unterschiedlichen groben Netzpräfixen vor,
bevorzugt die Funktion automatisch die Full-Route. Ohne diese Voraussetzungen
bleibt sie nur bei ausdrücklicher Erlaubnis im Direktmodus. `RequireFullMix`
scheitert stattdessen mit `ErrFullMixRequired`. Clientadapter müssen dieses
Mindestniveau geschützt persistieren, sobald der Nutzer es verlangt oder eine
Produktionsmigration den Bootstrapmodus beendet; so kann eine Eclipse-/Split-
View das Sicherheitsniveau nicht unbemerkt zurücksetzen.

Die automatische Auswahl erfindet kein Onion-Format. `MixReadiness` kann nur
von einem Scheduler mit weiterhin gültigen Provider-/Link-Assurances stammen;
diese Angaben bleiben dennoch eine Integrationssperre und kein Auditbeweis.

## Einheitliches Full-Node-Modell

Propagare verwendet keine dauerhaft verschiedenen Mix-, Courier- oder
Speicher-Node-Typen. Jede vollständig konforme Installation soll denselben
`propagare-node`-Code ausführen und jede dieser Aufgaben übernehmen können. Das
Directory veröffentlicht deshalb keine frei wählbaren Rollen; die Aufgabe wird
für jede Route neu vom Client vergeben.

`mixtransport.SelectFullRoute` wählt aus vollständig verifizierten
Directory-Records genau drei Mix-Hops, einen Courier und drei Speicherreplikate.
Eine Identität darf innerhalb derselben Route nur einmal vorkommen. Zusätzlich
müssen die sieben Nodes in unterschiedlichen IPv4-/24- beziehungsweise
IPv6-/48-Präfixen liegen. Diese Präfixregel erschwert triviale Korrelation durch
mehrere Adressen desselben Netzes, beweist aber keine Betreiberunabhängigkeit.
Eine spätere Betreiberattestierung darf deshalb nur ergänzend und nicht als
Ersatz für die bestehende Identitäts- und Netzdiversität verwendet werden.

Das Full-Node-Modell bedeutet gleiche Software und Fähigkeiten, nicht dass eine
einzelne Node mehrere Positionen desselben Pfades besetzen darf. Ein öffentlicher
Record darf erst als produktiv konform gelten, wenn die noch fehlenden
Relay-, Courier-, SURB- und Speicherschnittstellen gemeinsam aktiv und geprüft
sind. Der aktuelle Directory-Record beweist diese Laufzeitkonformität noch nicht.

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
mindestens drei für diese Route unterschiedliche Mix-Schichten
        │
        ▼
Courier/Storage/Directory ── uniforme feste Antwort über SURB
```

Jede Box in diesem Diagramm kann von derselben Full-Node-Software ausgeführt
werden, wird aber pro Route einer anderen Node-Identität zugewiesen. Die
Mix-Schicht erhält nur bereits verschlüsselte Commands und einmalige
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
