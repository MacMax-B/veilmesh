# Sicherheitsreview vom 21. Juli 2026

## Ergebnis

Dieser Stand wurde vollständig codebasiert geprüft und lokal dynamisch getestet.
Er ist dadurch nicht „gegen alle Angriffe immun“ und ersetzt keinen externen
Pentest. Es existiert kein bereitgestelltes öffentliches Ziel, daher wurden
keine fremden Systeme oder produktiven Netze aktiv gescannt.

Der abschließende `govulncheck` mit Go 1.26.5 meldet keine erreichbare
Schwachstelle. Er nennt ein Advisory in einem transitiv benötigten Modul, dessen
verwundbare Symbole vom aktuellen Programm nicht aufgerufen werden. Diese
Abhängigkeit bleibt dennoch im regulären Update- und Scanprozess.

## Behobene Funde

| Schwere | Fund | Behebung |
|---|---|---|
| hoch | Ein einzelner Node konnte über extreme PoW-Parameter die Clientarbeit verstärken. | Parameter besitzen harte Grenzen; Epoch-Ausreißer werden gruppiert und die Schwierigkeit des Schreibquorums entscheidet. |
| hoch | Ein gültig signierter, aber inhaltlich falscher Speicherbeleg konnte als Replikat zählen. | Payload-Hash, Item-ID, Ablaufzeit, Node-ID und Zeitfenster werden gemeinsam geprüft. |
| hoch | Fetches konnten sehr große Antworten und viele Store-Items materialisieren. | Harte Byte-, Item-, Route- und globale Store-Grenzen; Überschreitung ist ein Fehler. |
| hoch | Maximale 64-MiB-Dateien überschritten die Grenzen eines einzelnen Fetches und waren nicht zuverlässig rekonstruierbar. | Der Client lädt Datei-Chunks in Route- und Byte-begrenzten Batches; Löschung bleibt hinter der vollständigen AEAD-Rekonstruktion. |
| hoch | Ein verkürzter, signierter Byte-Präfix konnte als vollständige Speicherstichprobe zählen; die letzte mögliche Stichprobenposition wurde nie gewählt. | Proofs müssen exakt die angeforderte Länge liefern und der Zufallsoffset schließt das letzte gültige Fenster ein. |
| hoch | Lokaler Replikations- und Löschzustand war nicht verschlüsselt persistent und hatte kein Client-Speicherbudget. | AES-256-GCM-ClientStore mit atomaren privaten Dateien, Neustart-Revalidierung, maximal 10 GiB, Datensatzgrenze und sicherheitsabhängigen Prune-Richtlinien ergänzt. |
| hoch | Öffentliche Plain-HTTP-Konfiguration konnte Route-Tags und Lösch-Capabilities offenlegen. | Produktions-Discovery und öffentliche Listener verlangen TLS; private Klartextentwicklung benötigt eine explizite API beziehungsweise Option. |
| hoch | Manuelle CA-/Zertifikatskonfiguration war ein Fehlkonfigurationsrisiko und Node↔Node-Verzeichnisaufrufe banden den TLS-Schlüssel nicht an die angekündigte Identität. | Der Node erzeugt den Zertifikatscontainer automatisch aus seinem Ed25519-Identitätsschlüssel. Client↔Node, Snapshot-Pull, Registrierung und Reachability-Rückruf pinnen diesen Schlüssel aus der vollständigen hybriden Identität und erzwingen TLS 1.3 mit `X25519MLKEM768`; CA, SAN, Hostname, Redirect und TLS-Dialer-Bypässe sind nicht nötig beziehungsweise werden abgewiesen. |
| hoch | Node-Speicherquoten zählten nur Payload-Bytes; Dateikodierung und Indexoverhead ermöglichten Speicherverstärkung. | Quoten rechnen persistierte Kodierung plus festen Overhead; Item-, Route- und Request-Anzahl bleiben hart begrenzt. |
| mittel | Ein lokal umbenannter Node-Datensatz konnte nach Löschen neu eingelesen werden; Deletes waren nicht direkt per Verzeichnis-`fsync` bestätigt. | Dateiname und Item-ID werden beim Start gebunden; Put, Delete, Sweep und Startbereinigung synchronisieren das private Verzeichnis. |
| hoch | Zwei Prozesse konnten dasselbe Client- oder Node-Datenverzeichnis gleichzeitig mit getrennten RAM-Indizes öffnen. | Plattformgebundene exklusive Dateilocks sperren die zweite Instanz fail-closed; Windows- und Linux-Builds sowie Konflikt-/Reopen-Tests decken die Grenze ab. |
| mittel | Unvertrauenswürdige HTTP-Fehlerkörper konnten geheime reflektierte Werte in Reputation oder Logs tragen. | Fehlerkörper werden verworfen; Fehler enthalten nur den HTTP-Status. Interne Serverfehler werden ebenfalls vereinheitlicht. |
| mittel | Nichtkanonische Base64url-Repräsentationen wurden für mehrere Capability-/Request-IDs akzeptiert. | Netzwerk-IDs verwenden Strict-Base64url und besitzen Negativtests für alternative Kodierungen. |
| hoch | Node-Redirects konnten sensible Requests beziehungsweise Capabilities an ein anderes Ziel umlenken. | Der Client folgt keinen Redirects. |
| hoch | Go 1.26.2 und `x/net v0.50.0` hatten erreichbare Advisories. | Toolchain auf Go 1.26.5 gepinnt und die Go-X-Abhängigkeiten aktualisiert. |
| hoch | Der Abschluss-Scan fand `GO-2026-5942`: ungültige DNS-SVCB/HTTPS-RRs konnten über den WebRTC-Pfad in `x/net v0.53.0` einen Panic auslösen. | `x/net` auf die gefixte Version v0.56.0 aktualisiert; dabei `x/crypto` auf v0.53.0 und `x/sys` auf v0.46.0 angehoben. |
| mittel | Netzwerk-JSON akzeptierte teilweise unbekannte Felder oder weitere Werte. | Strikte, größenbegrenzte Decoder auf Client und Server; Parser-Fuzz-Seeds ergänzt. |
| mittel | Proof- und Löschantworten banden Challenge-Offset beziehungsweise Zeit nicht vollständig. | Offset, Nonce, Samplegröße, Hash, Identität und Zeitfenster werden geprüft. |
| mittel | Routen, Dateien, Geräte und Gruppen hatten unvollständige Strukturgrenzen. | 32-Byte-Capabilities, Manifest-/Chunk-Konsistenz, verifizierte Gerätezertifikate, Rollen- und Mitgliedslimits. |
| mittel | Admins konnten andere Admins entfernen oder bannen. | Diese Aktionen sind Owner-restriktiert; fehlgeschlagene Übergänge mutieren den Zustand nicht. |
| mittel | Private Node-Dateien wurden nicht überall crashfest und mit überprüften Rechten geschrieben. | Private reguläre Dateien, Modus 0600, temporärer atomarer Write, `fsync` und strikte lokale JSON-Prüfung. |
| hoch | Teilbare Konten-/Gruppenadressen und ein kryptografisch prüfbares Directory-Profil fehlten. | Selbstzertifizierende `ENIGC1…`-/`ENIGD1…`-/`ENIGG1…`-IDs, hybrid signierte Profile, Geräte-Zertifikate und Genesis-Bindung ergänzt. |
| hoch | Der statische HPKE-Entwicklungspfad konnte irrtümlich als forward-secure Produktpfad verwendet werden. | `message.StrictPipeline` bleibt ohne auditierten PQ-Ratchet, Key-Löschung, Skip-Key-Grenze, Replay-Store und Mix-/Cover-Transport geschlossen; Legacy-API explizit markiert. |
| hoch | Es gab keine kryptografische Client-Bestätigung, dass ein Empfänger eine konkrete Nachricht authentifiziert hatte. | Hybrid gerätesignierte Nachrichten und Client-Zustellbelege binden beide Konten, Geräte, Profilrevision, Message-ID, Inhaltshash und Zeitgrenzen. |
| mittel | Ein früher zertifiziertes, inzwischen entferntes Gerät hätte allein über sein altes Zertifikat authentisch wirken können. | Nachricht und Beleg müssen zusätzlich im aktuell verifizierten, revisionsgepinnten Profil als aktives Gerät enthalten sein. |
| mittel | Wiederholte gültige Nachrichten konnten oberhalb eines schwachen Providers erneut ausgeliefert werden. | Der strikte Pfad verlangt einen persistenten atomaren Replay-Store zusätzlich zum Ratchet-Replayschutz. |
| hoch | Ein aktivitätsabhängiger Direkttransport würde Kommunikationshäufigkeit und Online-Aktionen offenlegen. | VeilMix v2 sendet pro aktivem 5-Sekunden-Slot genau ein festes 8-KiB-Real/Poll/Cover-Paket und stoppt bei Timing-/Linkfehlern. |
| hoch | Frei konfigurierbare Paketgrößen und Pollkadenzen hätten einzelne Clients fingerprintbar gemacht. | v2 akzeptiert ausschließlich das gemeinsame moderate Profil 8 KiB / 5 s / Poll in jedem 6. Slot; v1 und individuelle Abweichungen werden abgelehnt. |
| hoch | Eine vermeintlich eigene PQ-Onion-Konstruktion wäre unanalysierte Kryptografie gewesen. | Onion, SURB, Replay und Routing-Key-FS bleiben hinter einer zwingend auditierten PQ-hybriden Provider-Grenze; kein eigenes Paketformat wurde erfunden. |
| mittel | Queue-Überlauf, abgelaufene Commands oder falsche Provider-Paketgrößen konnten Traffic-Lücken beziehungsweise Ressourcenarbeit erzeugen. | Queue wird vor Providerarbeit reserviert; abgelaufene Commands werden durch Cover ersetzt; Paket-, Payload-, Lebenszeit- und Dispatch-Grenzen sind hart. |
| kritisch | Eine offene selbstgemeldete IP-Liste hätte beliebige Sybils, Eclipse-Sichten und Rückruf-SSRF ermöglicht. | Nur kanonische literale IPs; signierte Kurzzeit-Lease; TCP-Quell-IP-Bindung; Challenge ausschließlich an dieselbe IP; gepinntes Seed-Quorum; keine Redirects. |
| hoch | Eine einzelne Node-Antwort hätte einem Client eine erfundene oder unvollständige Netzsicht geben können. | Jeder Snapshot ist hybrid signiert, eindeutig sortiert und begrenzt; Clients vereinigen eine konfigurierte Mindestzahl gepinnter Seed-Sichten und prüfen jeden Eintrag separat. |
| mittel | Tote Nodes konnten unbegrenzt in Discovery-Listen bleiben oder durch eine einzelne Fehlmessung öffentlich beschuldigt werden. | Leases gelten höchstens zwei Stunden und laufen ohne Erneuerung lokal aus; fehlende Verfügbarkeit wird nicht als globaler Fehlverhaltensbeweis behandelt. |

## ENIG-, Messaging- und Zero-Trust-Prüfungen

- Typverwechslung, falsche Länge/Kodierung und Public-Key-/ID-Substitution
- manipulierte und übergroße Profile, unbekannte Felder und Directory-Rollback
- vertauschte Account-, Geräte- und HPKE-Private-Keys im lokalen Vault-Datensatz
- fehlgeschlagene Vault-Persistenz: Registrierung liefert keine Identität zurück
- Gruppen-Genesis-Nonce und -Policy gegen die `ENIGG1…`-ID gebunden
- Nachrichteninhalt, Geräte-Zertifikat, Empfänger und Ablaufzeit manipuliert
- Client-Beleg mit verändertem Message-Digest oder nicht aktivem Gerät
- Ratchet ohne Key-Löschung, Transport ohne Cover Traffic und fehlender
  Replay-Store werden bereits beim Aufbau abgelehnt
- wiederverwendete Route-Capability, zu großer Ratchet-Plaintext/Ciphertext und
  Nachrichten-Replay werden vor Auslieferung abgelehnt

Nicht enthalten sind ein konkreter auditierter PQ-Ratchet, ein produktives
Mixnet, Key Transparency oder OS-spezifische Secret-Vault-Adapter. Die neuen
Provider-Grenzen verhindern unsicheren Produktbetrieb, sie implementieren diese
externen Systeme nicht selbst.

Der VeilMix-v2-Command-Layer und moderate Cover-Scheduler sind implementiert.
Weiterhin nicht enthalten sind der konkrete auditierte PQ-hybride Onion-
Provider, uniforme Downlink-/SURB-Implementierung, Courier, Mix-PKI und reale
Relays. Daher bleibt die Produktbehauptung „metadatenanonym“ gesperrt.

Das IP-Node-Verzeichnis wurde mit Signatur-/Quorum-Manipulation, Sequenz-
Rollback, Lease-Ablauf, falscher Quellen-IP, Challenge-Fälschung, Redirect,
unsortiertem Snapshot, unbekannten Feldern und Größenlimits negativ getestet.
Der CA-PKI-freie Link wurde zusätzlich mit selbstsigniertem Zertifikat, richtigem
und falschem Identity-Pin sowie abgewiesenen benutzerdefinierten Transport-/TLS-
Dialern getestet. Der TLS-Schlüsselaustausch ist PQ-hybrid; die Zertifikats-
Authentisierung ist bis zur Unterstützung einer standardisierten hybriden
TLS-Signaturmethode weiterhin Ed25519.
Nicht gelöst sind kolludierende Seed-Quoren, nachweisbare globale Vollständigkeit,
Betreiberdiversität und permissionless Ressourcennachweise.

## Call-spezifische Prüfungen

- manipuliertes SDP, falsche hybride Signatur und falsche Gerätezuteilung
- abgelaufene Signale, Call-ID-Replay und aktive Call-Grenze
- SDP-, ICE-Kandidaten-, ICE-Server- und Mediensektionsgrenzen
- SHA-256-DTLS-Fingerprintbindung
- ausschließlich ECDHE-ECDSA/AES-GCM für DTLS
- ausschließlich AEAD-AES-GCM für SRTP sowie DTLS/SRTP/SRTCP-Replayfenster
- echter lokaler Offer/Answer-Handshake und authentisierter Opus/RTP-Empfang
- automatische maximale Call-Dauer und neues ephemeres Zertifikat pro Call

Nicht getestet oder nicht implementiert sind SFU-/Gruppencalls, SFrame/MLS,
plattformreale Kamera-/Mikrofonadapter, mobile Suspend/Resume-Szenarien, große
NAT-/TURN-Matrizen und eine Live-Kompromittierung des Endgeräts.

## Ausgeführte Prüfklassen

- manuelles Review aller Go- und Sicherheits-/Architekturdateien
- positive und negative Unit-/Integrationstests
- aktive Fuzz-Kurzläufe für SDP, Netzwerk-JSON, Profile, Nachrichten,
  Client-Zustellbelege, VeilMix-Commands, Direct-Ciphertext, Stored Items sowie
  kanonische Call-/Datei-IDs
- `go test -count=1 ./...`
- `go test -race -count=1 ./...`
- `go vet ./...`
- `go mod verify`
- Windows- und Linux-Cross-Build der Client-/Node-Dateilocks
- `govulncheck ./...`: 0 erreichbare Schwachstellen, 0 in importierten Paketen;
  ein Advisory liegt nur in einem benötigten Modul, dessen betroffene Symbole
  nicht aufgerufen werden
- Formatierung mit `gofmt`

Ein erneuter `gosec`-Lauf wurde von der verwalteten Ausführungsrichtlinie wegen
des extern geladenen Scanner-Binaries abgelehnt und wird deshalb nicht als
Abschlussprüfung behauptet. Der vorherige Stand war ohne gosec-Fund; alle neuen
Pfade wurden zusätzlich durch `go vet`, manuelles Review, Negativtests, Race-
Tests und die oben genannten plattformübergreifenden Builds geprüft.

Die exakten Abschlussläufe stehen nicht als Sicherheitszertifikat. Für einen
Produktivstart bleiben unabhängige Protokoll-, Implementierungs-, Mobilplattform-
und Infrastruktur-Pentests Pflicht.
