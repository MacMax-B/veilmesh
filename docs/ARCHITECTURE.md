# Architektur

## Zielbild

Propagare soll ein UI-unabhängiger Messenger-Core sein. Frontends besitzen keine
Netzwerk- oder Kryptografielogik. Der Core verwaltet Konten, Geräte,
Sitzungsschlüssel, Gruppen, Outbox, Replikation, Empfang, Dateien und Node-
Reputation.

Alle Netzteilnehmer verwenden dasselbe Full-Node-Programm. Mix-, Courier-,
Speicher-, Directory- und Bootstrap sind Fähigkeiten desselben Binaries, keine
unterschiedlichen proprietären Dienste. Der Client weist die Datenpfadrollen pro
Route neu an unterschiedliche Identitäten und grobe Netzpräfixe zu. Ein
allgemeiner Internet-Exit beziehungsweise VPN-Exit gehört ausdrücklich nicht zum
Messenger-Overlay.

```text
Frontend
   │ lokale, versionsgebundene Core-API
   ▼
Client-Core ── verschlüsselter lokaler Zustand
   │
   ├── Ratchet-/MLS-Provider
   ├── Direct-Call-Endpoint (signiertes SDP + DTLS-SRTP)
   ├── Mix-/Onion-Transport
   ├── Cover-Traffic-Scheduler
   └── Node-Registry und Reputation
            │
            ▼
     identische, pro Route unterschiedlich eingesetzte Full Nodes
```

## Nachrichtenfluss

1. Eine teilbare `ENIGC1…`-ID wird über den anonymen Fetch-Pfad in ein signiertes
   Account-Profil aufgelöst; ID-Bindung, Signatur und lokaler Revisions-Pin werden geprüft.
2. Der Sender erzeugt eine hybrid gerätesignierte Anwendungsnachricht.
3. Der auditierte Session-Provider erzeugt je Empfängergerät einen eigenen
   PQXDH-/Ratchet-Ciphertext und löscht verbrauchte Nachrichtenschlüssel.
4. Der Cover-Scheduler polstert und sendet reale und Dummy-Pakete im selben Takt.
5. Ein einmaliger Route-Tag und eine geheime Lösch-Capability werden erzeugt.
6. Der Mix-Transport entkoppelt Sender, Replikation und anonymen Abruf zeitlich.
7. Nur gültig hybrid signierte Node-Belege zählen zum Schreibquorum.
8. Fehlende Replikate werden auf Ersatz-Nodes geschrieben.
9. Spätere Stichproben prüfen zufällige Ciphertext-Bereiche.
10. Der Empfänger prüft Ratchet, Replay-Store, ENIG-Profil, Geräte-Zertifikat und
    Nachrichtensignatur, bevor Klartext an die App gelangt.
11. Optional erzeugt das Empfängergerät einen signierten Zustellbeleg, der selbst
    als Ratchet-Nachricht zurückgesendet wird.
12. Nach Empfang entscheidet die Client-Richtlinie über sofortige Löschung oder
    Aufbewahrung bis zum gewählten Ablaufdatum.

Die Schritte 1 bis 6 sind im Referenz-HTTP-Transport noch nicht produktiv
implementiert. `message.StrictPipeline` erzwingt die Provider-Verträge und bleibt
ohne konkrete auditierte Adapter geschlossen.

## Direkte Node-Link-Verschlüsselung

Client↔Node und Node↔Node verwenden im produktiven Direktpfad TLS 1.3 als
standardisierten Schlüsselaustausch und AEAD-Record-Layer, aber keine öffentliche
PKI. Die Node erzeugt einen selbstsignierten Zertifikatscontainer aus dem
Ed25519-Anteil ihres persistenten Node-Schlüssels. Die Gegenstelle erhält die
vollständige hybride Identität aus einem gepinnten Seed oder verifizierten
Directory-Record und vergleicht den präsentierten Ed25519-Schlüssel exakt.
Der Container wird vor Ablauf automatisch erneuert; der gepinnte Schlüssel
ändert sich dabei nicht.

Der TLS-Stack darf ausschließlich `X25519MLKEM768` aushandeln; TLS-Versionen,
Kurven/KEMs oder Zertifikatsschlüssel außerhalb dieses Profils führen zum
Abbruch. CA-, DNS- und SAN-Prüfung sind bewusst durch den bereits vorhandenen
Identitäts-Pin ersetzt. Redirects und benutzerdefinierte TLS-Dialer, die diese
Prüfung umgehen könnten, werden abgewiesen. Das ist Transportverschlüsselung,
keine Metadatenanonymität. Der Schlüsselaustausch ist PQ-hybrid; TLS-
`CertificateVerify` authentisiert aktuell klassisch mit Ed25519, während
Directory- und Node-Belege weiterhin beide Ed25519- und ML-DSA-65-Signaturen
verlangen.

## ENIG-Identitäten

- `ENIGC1…` bindet den langfristigen hybriden Account-Autorisierungsschlüssel.
- `ENIGD1…` bindet den hybriden Signaturschlüssel eines zertifizierten Geräts.
- `ENIGG1…` bindet Creator-Schlüssel, 32 zufällige Genesis-Bytes und die
  Genesis-Policy der Gruppe.

Ein Directory ist nur für Auffindbarkeit und Verfügbarkeit zuständig. Profile
werden vom Account signiert und lokal gegen die angefragte ID verifiziert. Der
Client pinnt die höchste gesehene Revision in seinem geschützten Store. Gegen
Rollback bei einem völlig neuen Client ist zusätzlich eine auditable Key-
Transparency-Struktur erforderlich.

## Aufbewahrung

Das Protokoll verwendet ein festes Speicherfenster von 60 Tagen als technische
Annäherung an zwei Monate. Jedes Item läuft exakt 60 Tage nach seiner
Erstellung ab; Nodes lehnen jedes andere Ablaufdatum ab und entfernen
abgelaufene Items regelmäßig. Früheres Entfernen ist ausschließlich über die
geheime Lösch-Capability möglich.

Das Fenster ist bewusst nicht wählbar: Eine absenderdefinierte Dauer würde ein
für Nodes sichtbares Unterscheidungsmerkmal in die Item-Metadaten einbetten.
Kürzere anwendungsseitige Ablaufzeiten gehören in die Ende-zu-Ende-
verschlüsselte Nachricht und bleiben für Nodes unsichtbar.

Ein Kalenderzeitraum von exakt zwei Monaten ist absichtlich nicht verwendet,
weil Nodes in verschiedenen Zeitzonen und ohne Kontoinformationen deterministisch
dasselbe Ablaufdatum berechnen müssen.

Der lokale `client.EncryptedDiskStore` hat standardmäßig und maximal 10 GiB
logisches Budget. Persistierte Dateigröße und konservativer Index-/Dateisystem-
Overhead zählen gegen dieses Budget. Der Store entfernt zuerst abgelaufene und
danach die ältesten ausdrücklich mit `PruneOldest` markierten Cache-/History-
Datensätze. Nicht abgelaufener Zustell-, Replay-, Outbox-, Gruppen- oder
Gerätezustand bleibt geschützt; kann das Limit sonst nicht eingehalten werden,
liefert der Core einen Platzfehler statt Sicherheitszustand zu verlieren. Eine
zusätzliche harte Datensatzgrenze verhindert Tiny-Record-Speicherverstärkung.

Jeder Datensatz wird mit AES-256-GCM, frischer Nonce und pfadgebundener AAD
authentisiert verschlüsselt sowie atomar als private Datei geschrieben. Der
Schlüssel gehört in `account.SecretVault` beziehungsweise einen OS-/Hardware-
Keystore und wird nie im Store-Verzeichnis abgelegt. Ein exklusiver
plattformgebundener Dateilock verhindert zwei gleichzeitige Store-Instanzen;
Crash-Temporaries werden beim nächsten Öffnen entfernt und fremde Dateien im
dedizierten Store-Verzeichnis führen zu einem geschlossenen Fehler. Der Startup-
Pfad validiert zuerst das vollständige Verzeichnis und löscht erst danach
Temporaries oder abgelaufene Records. Nach jedem Start wird das Verzeichnis
erneut synchronisiert, sodass ein sichtbarer Rename mit zuvor unbekanntem
`fsync`-Ergebnis keinen idempotenten Scheinerfolg erzeugt.

Vor dem ersten externen Speichereffekt persistiert der Core pro Item die
Lösch-Capability, vollständige hybride Identitäten und alle Nodes, die den
Ciphertext möglicherweise erhalten. Jeder verifizierte Beleg wird danach
inkrementell ergänzt. Audit, Reparatur und Löschung beginnen immer mit diesem
authentifizierten kanonischen Zustand, vereinigen nur gültige zusätzliche Belege
und bleiben über Directory-Mitgliedschaftswechsel hinweg auf die ursprünglichen
Identitäten gepinnt. `PendingDeliveries` macht diese Zustände nach Neustart
begrenzt paginierbar. Die transaktionale Einbindung aller weiteren Inbox-/
Outbox-/Ratchet-/MLS-Zustände bleibt Phase 1.

Der Referenz-Node ersetzt ein authentifiziert gelöschtes Item bis zu dessen
ursprünglichem Ablauf durch einen capability-gebundenen Tombstone. Store und
hybride Node-Identität sind dauerhaft durch einen signierten Binding-Record
verknüpft; ein fehlender Schlüssel für einen gebundenen Store wird niemals
automatisch ersetzt. Ein exklusiver Schlüssel-Lease verhindert, dass zwei
Prozesse dieselbe Node-Identität gleichzeitig betreiben.

## Metadatenverschleierung

Die Speicherschicht verwendet keine Account-ID:

- Einmalige oder kurzlebige Route-Tags werden aus Session-Geheimnissen abgeleitet.
- Nachrichten haben wenige feste Größenklassen.
- Dateiblöcke haben eine konstante verschlüsselte Größe.
- Löschung erfolgt über zufällige Capabilities.
- Nodes führen keine Anwendungs-Zugriffslogs.

Für das eigentliche Ziel „nicht erkennbar, wer mit wem wie oft schreibt“ reicht
das nicht. Der produktive Transport benötigt mindestens:

- drei oder mehr unabhängig ausgewählte verschlüsselte Hops,
- paketformatneutrale Onion- oder Sphinx-ähnliche Kapselung aus einer geprüften
  Bibliothek,
- Batching und zufällige Verzögerung,
- konstante Sendeintervalle,
- Dummy-/Cover-Nachrichten bei Inaktivität,
- Downloads über dieselben anonymen Pfade,
- zeitlich entkoppelte Replikation durch Relays statt direkte Mehrfach-Uploads.

Ohne Cover Traffic kann ein globaler Beobachter trotz Verschlüsselung Zeitpunkte
und Datenmengen korrelieren.

`mixtransport.Scheduler` implementiert dafür ENIG-Mix v2: Commands werden vorab
in feste Pakete gekapselt; pro Slot wird unabhängig von Aktivität ein frisches
Cover-Paket erzeugt und genau ein Real-, positionsgebundenes Poll- oder
Cover-Paket gesendet. Verpasste Slots führen zum Abbruch statt zu einem
unsicheren Fallback. Das Onion-Format selbst bleibt bei einem auditierten,
PQ-hybriden Provider. Die normative Spezifikation steht in
[`ENIG-MIX-V2.md`](ENIG-MIX-V2.md).

## Dateien und Bilder

`media.EncryptFile` erzeugt:

- einen zufälligen AES-256-Dateischlüssel,
- konstante, authentifiziert verschlüsselte Blöcke,
- einen Manifest-Hash je Block,
- einen individuellen Route-Tag und ein Lösch-Token je Block.

Das Manifest und `FileSecret` werden innerhalb der Ende-zu-Ende-verschlüsselten
Chatnachricht übertragen. Die Nodes sehen nur Blöcke. Nach vollständigem Download
werden alle Hashes und AEAD-Tags geprüft; erst dann kann der Core auf sämtlichen
Nodes löschen. Dateien, deren Blöcke nicht in eine einzelne begrenzte Fetch-
Antwort passen, werden automatisch in Byte- und Route-Tag-begrenzten Batches
abgerufen; kein Fetch löscht Daten.

## Direkte Audio-/Videoanrufe

Direkte 1:1-Calls laufen über `call.Endpoint`. Der Endpoint erzeugt für jeden
Call ein ephemeres WebRTC-DTLS-Zertifikat und hybrid-signiert das vollständige
SDP. Dadurch werden der SHA-256-Zertifikatsfingerprint, ICE-Kandidaten, Call-ID,
Geräterollen, Medienart und Ablaufzeit gemeinsam an die bekannte
Geräteidentität gebunden. Das Signal wird als normaler verschlüsselter
Nachrichteninhalt transportiert; Nodes treffen keine Call-Entscheidungen.

Pion ist auf ECDHE-ECDSA/AES-GCM für DTLS und AEAD-AES-GCM für SRTP beschränkt.
Ein TURN-Relay kann Pakete weiterleiten, aber keine Medien entschlüsseln. Die
Sitzung bietet klassische Forward Secrecy; ECDHE ist noch nicht PQ-sicher und
ein laufender Call besitzt keine Post-Compromise-Recovery.

Die Architektur erlaubt aktuell keinen SFU. Vor SFU-/Gruppencalls ist eine
auditierte RFC-9605-SFrame-Schicht mit MLS-basierter, bei Join/Leave rotierender
Schlüsselverwaltung erforderlich. SFrame-Schlüssel dürfen nie mehreren Sendern
zum Verschlüsseln zugewiesen werden.

## Mehrere eigene Geräte

Das Konto besitzt einen langfristigen hybriden Signaturschlüssel. Dieser
zertifiziert einzelne Geräte mit jeweils eigenen:

- hybriden HPKE-Schlüsseln,
- Signaturschlüsseln,
- aus dem Geräte-Signaturschlüssel abgeleiteten `ENIGD1…`-IDs.

Sync-Ereignisse werden separat für jedes aktive Gerät verschlüsselt. Ein
verlorenes Gerät wird durch eine signierte Kontoaktion widerrufen. Zusätzlich
signiert das Sendergerät das vollständige Sync-Ereignis einschließlich Konto,
exakter aktueller Profilrevision, Zeitgrenzen und Empfängerliste. Empfänger
verlangen das aktuelle Profil, ihren lokalen Mindest-Revisions-Pin und eine
atomare persistente Replay-Reservation, bevor sie Payload ausgeben. Danach
müssen 1:1-Sitzungen und MLS-Gruppen einen Key Update beziehungsweise Epoch
Commit durchführen.

## Gruppen

Die Gruppenadministration ist von der Gruppenverschlüsselung getrennt:

- Owner darf Admins ernennen, entfernen und Eigentum übertragen.
- Admins dürfen Mitglieder hinzufügen, entfernen und bannen.
- Optional dürfen Admins weitere Admins ernennen.
- Jede Änderung erhöht die Gruppenepoche und referenziert den vorherigen Hash.
- Jede Änderung ist hybrid signiert.

Produktiv wird die Aktion erst gültig, wenn derselbe Mitgliedschaftswechsel als
RFC-9420-MLS-Commit erfolgreich angewandt wurde. Entfernte Mitglieder erhalten
keine zukünftigen Epoch Secrets; neue Mitglieder erhalten keine früheren.

## Node-Auswahl und Sybil-Schutz

`nodedir` implementiert den ersten admission-kontrollierten Discovery-Layer:
Clients und Nodes starten mit derselben lokal gepinnten Seed-Liste aus hybrider
Identität und literalem IP-Endpunkt. Neue Nodes veröffentlichen eine kurzlebige,
hybrid signierte Lease. Gepinnte Seeds attestieren sie erst, wenn TCP-Quell-IP
und veröffentlichte IP übereinstimmen und die Node am veröffentlichten Port eine
frische signierte Challenge beantwortet. Erst das konfigurierte Seed-Quorum
macht den Eintrag aktiv.

Alle Seeds veröffentlichen hybrid signierte, eindeutig sortierte Snapshots der
aktiven Liste. Nodes gleichen diese Sichten regelmäßig ab; Clients vereinigen
mindestens die konfigurierte Zahl unabhängiger Seed-Antworten. Eine Lease läuft
spätestens nach zwei Stunden aus, wenn die Node sie nicht erneuert. Dieser Ablauf
ist kein öffentlicher Fehlverhaltensbeweis. Die Liste ist auf 512 Nodes begrenzt
und enthält keine Kontakte, Capabilities, Route-Tags oder Fetchlisten. Details
stehen in [`NODE-DIRECTORY-V1.md`](NODE-DIRECTORY-V1.md).

Für ein permissionless offenes Netzwerk ist zusätzlich folgendes Zielprotokoll
vorgesehen:

1. Eine Node synchronisiert den signierten Kontrollzustand vollständig.
2. Sie erzeugt ein Node-spezifisch kodiertes Speicherreplikat.
3. Sie veröffentlicht den Merkle-Root vor der Zufalls-Challenge.
4. Mehrere zufällige Auditoren fordern Blöcke mit kurzer Frist an.
5. Die Node bleibt 30 Tage im Probemodus.
6. Alle Probe-Nodes gemeinsam erhalten höchstens 5 % echter Aufgaben.
7. Eine Speichergruppe enthält höchstens eine Probe-Node und keine offensichtliche
   Netz-/Betreiberduplikation.
8. Erst langfristig korrekte Nodes erhalten mehr Einfluss.

Neue Schlüssel bleiben kostenlos, aber neue Schlüssel erhalten nicht sofort
Einfluss. Ressourcen- und Zeitkosten wachsen ungefähr linear mit der Anzahl
angreifender Nodes.
