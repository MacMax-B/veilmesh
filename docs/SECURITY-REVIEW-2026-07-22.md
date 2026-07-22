# Sicherheitsreview vom 22. Juli 2026

## Ergebnis

Der aktuelle Repository-Stand wurde intern codebasiert gehärtet und mit den
unten aufgeführten statischen, dynamischen, Race-, Plattform- und
Abhängigkeitsprüfungen verifiziert. Die dabei gefundenen implementierbaren
kritischen und hohen Fehler in den vorhandenen Komponenten wurden geschlossen
und durch Negativ- beziehungsweise Regressionstests abgesichert.

Das Ergebnis ist trotzdem **kein GO für einen allgemeinen Produktiv-Release als
Messenger**. Dem Repository fehlen weiterhin externe, unabhängig auditierte
Ratchet-, MLS-, Onion-/Mixnet- und Vault-Provider, reale Infrastruktur,
Endnutzer-Frontends und externe Sicherheitsprüfungen. Bis diese Gates erfüllt
sind, ist nur eine deutlich gekennzeichnete Developer-/Testnet-Preview zulässig.
Die verbindliche Entscheidung steht in
[`RELEASE-READINESS.md`](RELEASE-READINESS.md).

Es wurde kein fremdes oder öffentliches Ziel aktiv angegriffen. Es war kein
Produktionssystem im Scope; der Review betrifft den bereitgestellten Quellstand.

## Geschlossene Funde

| Schwere | Fund | Behebung |
|---|---|---|
| kritisch | Zustell-Capability und mögliche Speicherziele konnten bei Absturz oder verlorener Antwort vor dem ersten Beleg verloren gehen. | Der Core persistiert Lösch-Token, vollständige hybride Node-Identitäten und jeden möglichen Store-Versuch vor dem ersten externen Schreibeffekt. Belege werden einzeln verifiziert und inkrementell persistiert. |
| hoch | Audit, Repair und Delete konnten mit veraltetem oder unvollständigem Aufruferzustand arbeiten und bei Directory-Wechseln alte Replikate vergessen. | Jede Operation beginnt mit dem authentifizierten kanonischen lokalen Zustand, vereinigt nur gültige Belege, pinnt historische Identitäten und löscht auf allen jemals versuchten Zielen. Per-Item-Locks serialisieren konkurrierende Operationen. |
| hoch | Ein Delete-Retry nach verlorener Antwort oder Neustart konnte ein bereits gelöschtes Item nicht sicher unterscheiden und eine Wiederaufnahme zulassen. | Capability-gebundene, größenbegrenzte Tombstones ersetzen Items atomar bis zu deren ursprünglichem Ablauf. Identische Retries sind idempotent, falsche Tokens bleiben wie unbekannte Items behandelt. |
| hoch | Node-Daten konnten nach Schlüsselverlust versehentlich unter einer neuen Identität erscheinen; dieselbe Identität konnte parallel betrieben werden. | Jeder Store wird dauerhaft durch einen hybrid signierten Record an genau eine Node-Identität gebunden. Ein gebundener Store erzeugt nie automatisch einen Ersatzschlüssel; ein exklusiver Prozess-Lease hält den Schlüssel während der gesamten Laufzeit. |
| hoch | Ein sichtbarer Rename mit fehlgeschlagenem Verzeichnis-`fsync` konnte nach einem Neustart als dauerhaft behandelt werden. Teilweise Prune-/Sweep-Löschungen konnten den Durability-Status bei einer späteren Fehler- oder Cancel-Rückgabe verlieren. | Client- und Node-Store synchronisieren das Verzeichnis nach jedem vollständigen Startup-Scan. Jede Namespace-Mutation markiert den Store sofort als degradiert; Reads, idempotente Retries, weitere Mutationen und Close bleiben bis zu erfolgreicher Synchronisation geschlossen. |
| hoch | Startup-Bereinigung konnte vor der vollständigen Prüfung bereits gültige Datensätze verändern; Verzeichnis- und Temporärscans waren nicht überall ausreichend begrenzt. | Vollständige zweiphasige Startup-Prüfung vor Cleanup/Pruning, paginierte Scans, harte Record-/Temporary-/Dateigrößenlimits und descriptorgebundene Reads wurden ergänzt. |
| hoch | POSIX-Modusprüfungen wurden auf Windows als Schutzgrenze behandelt. Private Schlüssel-/Store-Dateien waren dort nicht durch eine explizit geprüfte DACL abgesichert. | Eine gemeinsame Plattformgrenze prüft auf Unix Typ, effektiven Besitzer und owner-only Modus. Windows verwendet geschützte, exakt validierte DACLs für Dienstnutzer, LocalSystem und Administratoren sowie `MoveFileEx(...WRITE_THROUGH)` für kritische Publikationen. Nicht unterstützte Plattformen scheitern geschlossen. |
| hoch | Produktive Directory-Verbindungen konnten durch eine private Policy auf HTTP herabgestuft werden; HTTPNode-Transport und Identität waren nach Konstruktion veränderbar. | Produktion akzeptiert nur öffentlich routbares HTTPS mit vollständigem Identitäts-Pinning. Private/Loopback-Verbindungen benötigen eine getrennte Development-API. Operative Node-Deskriptoren werden intern geklont und besitzen keine mutierbaren exportierten Transportfelder. |
| hoch | Ein einzelner budgetfüllender Fetch-Reply konnte andere Replikate verdrängen; lokale Cancels konnten die Node-Reputation beschädigen. | Antworten werden pro Node validiert und anschließend deterministisch in Node-ID-Reihenfolge round-robin innerhalb der globalen Grenzen vereinigt. Lokale Cancel-/Deadline-Fehler zählen nicht als Node-Fehler. |
| hoch | Geräte-Sync war nicht vollständig senderauthentisiert und nicht zwingend an den aktuellen Gerätebestand sowie persistenten Replay-Schutz gebunden. | Das Sendergerät signiert Event-ID, Konto, exakte Profilrevision, Zeitgrenzen und Payload. Nur aktuell aktive Sender/Empfänger werden akzeptiert; Profil- und Gerätezahl sind begrenzt und die Öffnung verlangt eine atomare persistente Replay-Reservation. |
| mittel | Allgemeine HTTP-Antwortlimits waren für kleine Receipt-/Proof-Endpunkte zu groß und Transportfehler konnten fremde Antwortinhalte in Diagnosezustände tragen. | Endpoint-spezifische Limits, strikte Ein-Wert-JSON-Decoder, Redirect-Verbot und sanitierte Fehlerklassen wurden eingeführt. Payloads, Capabilities und Fehlerkörper werden nicht protokolliert. |
| mittel | Ein später fehlerhafter Dateiblock konnte erst nach bereits begonnenem Upload erkannt werden; plattformabhängige Dateinamen waren möglich. | Manifest, Payload-Hash, Token und sämtliche Chunk-Metadaten werden vor dem ersten Netzwerkeffekt vollständig geprüft. Dateinamen sind UTF-8, separator- und control-character-frei. |
| mittel | Gleichzeitige Gruppenaktionen konnten einen Datenlauf verursachen und autorisierte Zustandsübergänge überschreiben; ein naiver Lock-Fix hätte wiederhergestellte JSON-Zustände unbenutzbar gemacht. | `group.State.Apply` serialisiert den vollständigen Verify-/Authorize-/Commit-Übergang über einen unveränderlichen Guard. Der begrenzte strikte JSON-Restore validiert den gesamten Zustand und initialisiert den Guard neu; Race- und Parser-Regressionstests decken beide Pfade ab. |
| mittel | Node-Hintergrundfehler konnten ignoriert werden; akzeptierte TLS-Verbindungen waren erst nach dem Handshake begrenzt. | Sweep- und Directory-Agent-Fehler beenden den Prozesspfad kontrolliert, Shutdown wartet begrenzt auf Worker, und die Verbindungsgrenze liegt vor dem TLS-Handshake. Interne HTTP-/TLS-Fehlerlogs werden verworfen. |
| mittel | Mehrere Parser-, Capability-, Identitäts-, Signaturdomänen- und Größenränder akzeptierten nichtkanonische oder zu große Werte. | Kanonische Base32/Base64url-/JSON-Prüfungen, harte Vorabgrenzen, Signaturdomänenlimits, Profil-/Padding-Limits und zugehörige Negativ- und Fuzz-Seeds wurden ergänzt. |

## Ausgeführte Abschlussprüfungen

Alle folgenden Prüfungen waren am 22. Juli 2026 erfolgreich:

- `gofmt` über alle Go-Dateien und `git diff --check`
- `go mod tidy -diff`
- `go mod verify`
- `go vet ./...`
- `go test -count=1 ./...`
- `go test -race -count=1 ./...`
- kurze aktive Fuzz-Läufe aller elf vorhandenen Fuzz-Harnesses für Profile,
  Nachrichten, Belege, SDP/Call-IDs, Client-/Node-JSON, Directory, Medien,
  Mix-Commands und Stored Items
- `govulncheck v1.1.4 -show verbose ./...`
- Linux/amd64-, macOS/arm64- und Windows/amd64-Cross-Build von `./...`
- Windows/amd64-Kompilierung der Client-, Node- und Node-CLI-Testbinaries
- zwei bereinigte Node-Builds mit `-trimpath`, ohne VCS-Metadaten und Build-ID;
  beide Binärdateien waren bytegleich

`govulncheck` meldete 0 betroffene Symbolschwachstellen und 0 Schwachstellen in
importierten Paketen. Der Modulgraph enthält weiterhin den Hinweis
`GO-2026-5932` für das nicht importierte, als unsicher designte
`golang.org/x/crypto/openpgp`; der aktuelle Code importiert oder erreicht dieses
Paket nicht. Dependabot und der gepinnte CI-Scan überwachen den Graphen weiter.

Die CI führt zusätzlich echte Client-/Node-Persistenztests auf aktuellen
macOS- und Windows-Runnern aus. Ein lokaler Cross-Build ersetzt diesen späteren
CI-Lauf nicht; ein Release darf nur aus einem Commit mit vollständig grüner
geschützter CI erzeugt werden.

## Verbleibende Produktions- und Deployment-Grenzen

- Direkte HTTPS-Verbindungen bieten Transportverschlüsselung, aber keine
  Metadatenanonymität. Ohne den auditierten Mix-/Onion-Provider darf das Produkt
  nicht als anonym beworben werden.
- `SendDirect` ist ein statisch versiegelter Bootstrap-Pfad ohne Ratchet,
  Forward Secrecy oder Post-Compromise Security. Produktion muss den
  fail-closed `message.StrictPipeline` mit einem auditierten Provider verwenden.
- Gruppenverwaltung ist keine Gruppenverschlüsselung. Ein auditierter RFC-9420-
  MLS-Provider und atomare Kopplung jedes Autorisierungswechsels an dessen MLS
  Commit fehlen.
- Store-Schlüssel benötigen reale OS-/Hardware-Vault-Adapter. Datei- und
  In-Memory-Vaults sind keine Produktionslösung.
- Der Referenz-Node-Store ist kein skalierbares Millionen-Item-Backend.
  Migration, Last-/Soak-Tests, Backup/Restore, Monitoring, Rollback und
  Incident-Prozesse fehlen.
- Unix-Deployments müssen erweiterte ACLs und ungeeignete Netzwerkdateisysteme
  ausschließen. Das Ziel-Dateisystem muss die erwarteten Rename-/`fsync`-
  Garantien tatsächlich liefern.
- Unabhängige Protokoll-, Implementierungs-, Plattform-, Infrastruktur- und
  Metadaten-Audits sowie ein externer Penetrationstest stehen aus.

Diese Grenzen sind Release-Gates und dürfen weder durch Konfiguration noch durch
Marketingtext abgeschwächt werden.
