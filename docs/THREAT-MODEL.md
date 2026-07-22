# Bedrohungsmodell

## Geltungsbereich

Dieses Modell beschreibt den aktuellen Propagare-Prototyp. Es ist keine Aussage,
dass das System gegen „alle Angriffe immun“ sei. Sicherheitsbehauptungen gelten
nur für den eingecheckten, getesteten Code, die festgelegten Abhängigkeiten und
die unten genannten Annahmen.

## Geschützte Werte

- Nachrichten-, Datei-, Audio- und Videoklartext
- langfristige Konto-, Geräte- und Node-Schlüssel
- ephemere Call- und zukünftige Ratchet-/MLS-Geheimnisse
- Route-Tags, Lösch-Capabilities, Fetch-Listen und Dateischlüssel
- Integrität von Gruppenrollen, Speicherbelegen und Löschbestätigungen
- Bindung teilbarer ENIG-IDs an Account-, Geräte- und Gruppen-Genesis-Schlüssel
- Integrität signierter Anwendungsnachrichten und Client-Zustellbelege
- Vertraulichkeit und Integrität lokaler Replikations-, Lösch- und zukünftiger
  Inbox-/Outbox-/Replay-Zustände

## Angreifer

Berücksichtigt werden bösartige Speicher-Nodes, Signaling-/TURN-Dienste,
Netzwerkangreifer, Replay- und Parserangriffe, manipulierte Protokollantworten,
Ressourcenerschöpfung sowie Teilnehmer, die unberechtigt Gruppenrechte erlangen
wollen. Ein globaler passiver Beobachter wird für Metadatenanalyse angenommen.

Nicht durch das Netzwerkprotokoll lösbar sind vollständig kompromittierte
Endgeräte, absichtlich aufzeichnende Gesprächspartner, Schwachstellen in
Betriebssystem, Kamera-/Mikrofontreibern oder nicht auditierten Frontend-
Adaptern sowie physischer Zugriff auf entsperrte Geräte.

## Vertrauensgrenzen

```text
Frontend/Medienadapter
        │ keine Schlüssel- oder Signaling-Entscheidungen
        ▼
Client-Core und Call-Endpoint ── lokaler sicherer Schlüsselspeicher
        │ signierte, E2E-verschlüsselte Signale
        ├──────────────► Speicher-Nodes
        │ DTLS-SRTP (direkt oder über TURN)
        └──────────────► Gesprächsgerät
```

Directory, Speicher-Nodes und TURN-Relays sind nicht für Vertraulichkeit oder Integrität
vertrauenswürdig. Die bekannte Geräteidentität des Gesprächspartners, der lokale
Core, Secret-Vault-, Ratchet-, Replay- und Mixnet-Adapter, der Zufallszahlengenerator,
Go-Kryptografie, CIRCL und Pion liegen in der Trusted Computing Base. Deklarierte
Provider-Assurances sind kein Ersatz für Code- und Deployment-Audits. Der direkte
HTTP(S)-Transport ist nicht anonym. Produktive Direktverbindungen sind
fail-closed auf CA-PKI-freies, identitätsgepinntes TLS 1.3 mit ausschließlich
`X25519MLKEM768` beschränkt; explizites privates Plain HTTP ist nur ein
Entwicklungsmodus. CA, Hostname und SAN sind keine Vertrauensanker. Der
Ed25519-Zertifikatsschlüssel wird aus dem hybriden Seed-/Directory-Record
gepinnt. Der Schlüsselaustausch ist PQ-hybrid, die TLS-`CertificateVerify`-
Authentisierung derzeit jedoch klassisch; Anwendungs- und Directory-Belege
verlangen weiterhin beide Signaturen.

## Identität und Nachrichten

Eine bekannte `ENIGC1…`-ID verhindert unbemerkte Directory-Schlüsselsubstitution,
weil der Client den Fingerprint neu berechnet und alle Profile/Geräte-Zertifikate
hybrid prüft. Ein Directory kann Verfügbarkeit verhindern, Kontaktabfragen
beobachten oder alte signierte Profile wiedergeben. Lokal gepinnte Revisionen
begrenzen Rollback; Key Transparency für Erstinstallationen fehlt.

Der strikte Pfad gibt Klartext erst nach Ratchet-Entschlüsselung, Größenprüfung,
Profil-/Gerätesignaturprüfung und atomarer Replay-Ablehnung frei. Signierte
Client-Belege sind übertragbare Authentizitätsnachweise und reduzieren Deniability.

## ENIG-Mix

Der ENIG-Mix-v2-Scheduler schützt die Verkehrsform nur während eines
ununterbrochenen Laufs: ein festes Paket je Slot, feste Pollpositionen und Cover
ohne Aktivitätsabhängigkeit. Ein Slotfehler beendet den Lauf und damit die
Behauptung für den betroffenen Zeitraum. Suspend, Offline-Zeit und unterschiedliche
Nutzerprofile können Anonymitätsmengen aufteilen.

Sender-/Empfänger-Unverknüpfbarkeit setzt mindestens einen ehrlichen Mix-Hop,
nicht vollständig kolludierende Entry-/Service-Betreiber, ausreichend gleich
getaktete Nutzer und einen tatsächlich auditierten PQ-hybriden Paketprovider
voraus. Gegen vollständige Relay-Kollusion oder kompromittierte Endpunkte besteht
keine Protokollgarantie.

## IP-Node-Verzeichnis

Die standardmäßig ausgelieferte Seed-Liste ist eine lokale Vertrauenswurzel:
Sie pinnt vollständige hybride Node-Identitäten und literale IP-Endpunkte. Neue
Node-Leases brauchen das konfigurierte Quorum dieser Seeds. Ein einzelner
unvertrauenswürdiger Node kann deshalb weder eine beliebige Dritt-IP anmelden
noch Clients allein eine neue Vertrauenswurzel unterschieben.

Seed-Quorum und Rückruf-Challenge begrenzen Sybil-, Eclipse- und SSRF-Angriffe,
beseitigen sie aber nicht. Ein kolludierendes Quorum kann Nodes zulassen oder
gültige Nodes aus seiner Sicht verschweigen. Gemeinsame NATs beweisen keine
unabhängigen Betreiber. Der direkte Abruf offenbart dem Seed die Client-IP und
den Abrufzeitpunkt. Clients bilden deshalb eine verifizierte Union mehrerer
Seed-Sichten; globale Vollständigkeit ist trotzdem nicht beweisbar.

Offline-Zustand wird nicht als Schuldbehauptung signiert. Ohne rechtzeitige
Erneuerung läuft eine Lease spätestens nach zwei Stunden aus und wird in jeder
lokalen Sicht entfernt. Vorübergehend unterschiedliche Listen sind im
eventual-consistenten Modell erwartet.

## Direkte Calls

Das hybrid signierte SDP bindet Call-ID, Rollen, Medienart, Ablaufzeit,
ICE-Kandidaten und den SHA-256-DTLS-Fingerprint. Signaturen werden vor der
SDP-Verarbeitung geprüft. Pion vergleicht anschließend das präsentierte
self-signed DTLS-Zertifikat mit diesem Fingerprint.

Erlaubt sind höchstens je eine Audio- und Videosektion, 64 ICE-Kandidaten,
64 KiB SDP und kurzlebige Signale. Ein bounded Replay-Cache und ein Limit aktiver
Calls schützen vor Wiederholung und Zustandserschöpfung. DTLS ist auf
ECDHE-ECDSA mit AES-GCM, SRTP auf AEAD-AES-GCM beschränkt. Ein ephemeres
Zertifikat wird pro Call erzeugt und Calls werden spätestens nach der
konfigurierten Höchstdauer geschlossen.

Die daraus folgende Forward Secrecy ist klassisch und sitzungsbezogen, nicht
post-quantenresistent und kein Schutz nach einer Live-Kompromittierung. Direkte
Calls verwenden keinen SFU. SFU-/Gruppencalls bleiben blockiert, bis SFrame und
MLS aus auditierten Providern atomar integriert sind.

## Verfügbarkeits- und Parsergrenzen

- Node-, Request-, Item-, Fetch-, Datei-, Retention-, PoW- und Call-Grenzen
  werden vor teurer Arbeit geprüft.
- Client-Speicher ist auf höchstens 10 GiB und eine feste Datensatzanzahl
  begrenzt. Nur abgelaufener oder ausdrücklich prunebarer Zustand wird entfernt;
  andernfalls schlägt der Schreibvorgang geschlossen fehl.
- Ein einzelner PoW-Ausreißer bestimmt nicht mehr die Arbeit des Schreibquorums.
- Fetches sind pro Node und über alle Replikate gemeinsam begrenzt; Items pro
  Route, Node-Speicher, Node-Requests und lokale Client-Datensätze ebenfalls.
- JSON-Netzwerkparser lehnen unbekannte Felder und nachgestellte Werte ab.
- Capability-/Request-IDs müssen eine kanonische Base64url-Darstellung besitzen.
- Redirects von Nodes werden nicht verfolgt, damit Capabilities nicht an ein
  umgeleitetes Ziel gesendet werden.
- Speicher-, Proof- und Löschbelege müssen Identität, Payload, Item, Zeit und
  Challenge vollständig binden. Ein Speicherbeweis zählt nur mit dem gesamten
  angeforderten Bytefenster.

## Verbleibende hohe Risiken

- kein konkreter produktiver Double-/Triple-Ratchet-Adapter für Textnachrichten
- kein MLS-Provider für Gruppeninhalte
- kein konkreter anonymer Transport-/Cover-Traffic-Adapter
- keine reale ENIG-Mix-Relay-/Courier-/PKI-Infrastruktur und kein auditierter
  PQ-hybrider Onion-Paketprovider; nur Command-Layer und Scheduler sind vorhanden
- keine Key-Transparency-Struktur und keine plattformspezifischen Secret-Vault-Adapter
- keine permissionless Sybil-Abwehr, transparente Checkpoint-Logstruktur oder
  garantierte Betreiber-/Netzdiversität trotz signiertem Seed-Quorum-Verzeichnis
- Node-JSON- und Client-Dateistores sind nicht für sehr große Installationen
  oder Mehrdatensatz-Transaktionen einer Datenbankklasse ausgelegt
- keine unabhängige Sicherheitsprüfung dieses Stands

Jede Änderung an diesen Annahmen oder Garantien muss `SECURITY.md`, dieses
Dokument und die Negativ-/Fuzztests gemeinsam aktualisieren.
