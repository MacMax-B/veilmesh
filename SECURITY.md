# Sicherheitsstatus

## Was der aktuelle Code schützt

- Nodes erhalten ausschließlich Ciphertext und zufällige Capabilities.
- Direkte versiegelte Nachrichten verwenden einen hybriden klassischen und
  post-quantenresistenten KEM.
- Node-Belege und Adminaktionen sind gleichzeitig klassisch und mit ML-DSA-65
  signiert. Beide Signaturen müssen gültig sein.
- Dateien werden vor dem Upload mit AES-256-GCM verschlüsselt und in konstante
  Blockgrößen gepolstert.
- Route-Tags, Lösch-Tokens und Dateischlüssel werden kryptografisch zufällig
  erzeugt.
- Eine Node kann ohne geheime Lösch-Capability keine Nachricht löschen.
- Abholung löscht nicht automatisch. Erst ein vollständig authentifizierter
  Dateidownload löst optional die Löschung aus.
- Feste Größen-, Zeit-, Request- und Quotenlimits werden vor Speicherung geprüft.
- Fetch-Antworten sind pro Node und über alle Replikate gemeinsam auf Itemzahl
  und Bytes begrenzt. Große Dateien werden in begrenzten Fetch-Batches geladen.
- Produktive Client↔Node- und Node↔Node-Verbindungen verwenden ausschließlich
  TLS 1.3 mit dem hybriden `X25519MLKEM768`-Schlüsselaustausch. Die Node erzeugt
  den selbstsignierten Zertifikatscontainer automatisch aus ihrem persistenten
  Ed25519-Identitätsschlüssel; Clients und Nodes pinnen diesen Schlüssel aus der
  vollständig hybrid signierten Directory-Identität. Öffentliche CA, DNS-
  Validierung, SAN und manuell verwaltete TLS-Dateien sind nicht erforderlich.
  Der Container wird vor Ablauf automatisch mit demselben gepinnten Schlüssel
  erneuert.
  Plain HTTP ist nur über die ausdrücklich benannte Entwicklungs-API für
  literale Loopback- oder private IPs möglich; Redirects bleiben gesperrt.
- Der verschlüsselte lokale Client-Store besitzt standardmäßig und maximal
  10 GiB logisches Budget sowie eine harte Datensatzgrenze. Abgelaufene Daten
  werden zuerst, danach nur ausdrücklich als Cache/History markierte Daten
  oldest-first entfernt. Nicht abgelaufener Replay-, Outbox-, Gruppen- oder
  Löschzustand wird bei Platzmangel nicht still gelöscht; der Schreibvorgang
  schlägt stattdessen geschlossen fehl.
- Lokale Client-Datensätze werden als private, atomar geschriebene AES-256-GCM-
  Einheiten gespeichert. Metadaten und Nutzdaten sind authentisiert; Dateinamen
  enthalten nur einen domänenseparierten Hash der Datensatz-ID. Der
  Verschlüsselungsschlüssel wird nicht neben dem Store gespeichert. Ein
  plattformgebundener exklusiver Dateilock verhindert parallele Store-Instanzen;
  abgebrochene temporäre Writes werden beim Neustart entfernt.
- Node-Quoten rechnen die persistierte Kodierung plus festen Dateisystem-/Index-
  Overhead, nicht nur Ciphertext-Nutzbytes. Die globale gleichzeitige
  Request-Arbeit ist hart begrenzt; auch ein Node-Datenverzeichnis besitzt
  exklusiven Prozessbesitz.
- Der Node-Server schreibt absichtlich keine HTTP-Zugriffslogs.
- Direkte 1:1-Audio-/Videoanrufe verwenden WebRTC DTLS-SRTP mit ausschließlich
  ECDHE/AES-GCM und AEAD-SRTP. Das vollständige SDP einschließlich des
  ephemeren DTLS-Fingerprints ist hybrid an beide Geräteidentitäten gebunden.
- Call-Signale sind kurzlebig, größenbegrenzt und replaygeschützt. Pro Anruf
  wird ein neues DTLS-Zertifikat erzeugt; die maximale Sitzungsdauer ist
  begrenzt.
- Account-, Geräte- und Gruppenadressen beginnen mit `ENIG` und sind
  domänenseparierte SHA-256-Fingerprints der autorisierenden öffentlichen
  Schlüssel; Gruppen binden zusätzlich Creator, zufälligen Genesis-Nonce und
  Genesis-Policy.
- Öffentliche Account-Profile und jedes Geräte-Zertifikat sind hybrid signiert.
  Ein fremder Directory-Schlüssel kann deshalb nicht unter einer bekannten
  `ENIGC1…`-ID substituiert werden.
- Anwendungsnachrichten und Client-Zustellbelege sind mit zertifizierten
  Geräteschlüsseln hybrid signiert und binden Sender, Empfänger, Message-ID,
  Zeitgrenzen und Inhalt beziehungsweise Nachrichten-Hash.
- `message.StrictPipeline` verweigert den Start ohne Ratchet-Key-Löschung,
  begrenzte Skip-Keys, persistenten Replay-Speicher und einen deklariert
  auditierten Mix-/Cover-Transport.
- `mixtransport.Scheduler` sendet in jedem aktiven Slot genau ein fest großes
  Real-, Poll- oder Cover-Paket. Ein abgelaufener Command wird durch Cover
  ersetzt; Größenfehler, verpasste Slots und Linkfehler stoppen den sicheren Lauf.
- Das Node-Verzeichnis akzeptiert ausschließlich kanonische literale IPs,
  hybrid signierte Kurzzeit-Leases und ein Quorum lokal gepinnter Seed-
  Attestierungen. Ein Seed prüft Quellen-IP und einen signierten Rückruf-Challenge,
  bevor es attestiert. Snapshots sind vollständig signiert, sortiert und auf 512
  aktive Nodes begrenzt; abgelaufene Leases werden lokal entfernt.

## Kritische noch offene Grenzen

### Metadaten

Der direkte Referenztransport verbirgt nicht:

- IP-Adresse des Clients gegenüber der ersten Node,
- Zeitpunkt und Datenmenge einer Übertragung,
- Korrelation mehrerer gleichzeitiger Replikate,
- ungefähre Dateigröße anhand der Blockanzahl.

Rotierende Route-Tags und Padding verhindern dauerhafte Kontokennungen auf der
Speicherschicht, aber sie besiegen keinen global beobachtenden Gegner. Dafür sind
ein geprüftes Mixnet, feste Sendeintervalle, Dummy-Nachrichten, Batching und
Verzögerungen notwendig.

Auch das Auflösen einer `ENIGC1…`-ID verrät dem Directory ein Kontaktinteresse,
wenn die Anfrage direkt erfolgt. Profile müssen deshalb über denselben anonymen,
konstant getakteten Fetch-Pfad geladen werden. Der bestehende HTTP-Core darf
keine Metadaten-Privacy-Eigenschaft deklarieren und wird von
`message.NewStrictPipeline` nicht als privater Transport akzeptiert.

VeilMix v2 implementiert die eigene moderate konstante Verkehrslogik, aber noch keine
produktive Anonymität: Der auditierte PQ-hybride Onion-Provider, uniforme
Downlink-/SURB-Antworten, Courier-Replikation, Mix-PKI und reale Relays fehlen.
Die Assurance-Felder der Provider sind nur Integrationssperren und kein
kryptografischer Auditbeweis. Details und das genaue Angreifermodell stehen in
[`docs/VEILMIX-V2.md`](docs/VEILMIX-V2.md).

Das Referenzprofil mit 8 KiB alle 5 Sekunden verbraucht bei ununterbrochenem
Betrieb ungefähr 135 MiB Upstream pro Tag. Ein anderes Profil muss für eine
gesamte Anonymitätsmenge einheitlich sein; aktivitätsabhängiges Umschalten würde
neue Metadaten erzeugen. Das moderate Profil reduziert Kosten, schwächt aber
Latenz und statistische Deckung gegenüber dem früheren v1-Hochlastprofil.

### Node-Verzeichnis

Node-IP-Adressen sind absichtlich öffentlich. Registrierung und Abruf über den
direkten Verzeichnis-HTTP-Pfad verbergen weder Client-/Node-IP noch Zeitpunkt.
Produktiv sind CA-PKI-freies, identitätsgepinntes TLS 1.3, mehrere organisatorisch
und netztopologisch unabhängige gepinnte Seeds sowie mindestens ein
Mehrheitsquorum erforderlich. Der TLS-Handschlag bricht ab, wenn nicht exakt
`X25519MLKEM768`, TLS 1.3 und der Ed25519-Schlüssel der erwarteten hybriden
Node-Identität präsentiert werden. Plain HTTP und private IPs sind ausschließlich
hinter dem expliziten lokalen Entwicklungsmodus erlaubt.

Die Directory- und Node-Protokollobjekte werden weiterhin mit Ed25519 und
ML-DSA-65 signiert und verlangen beide gültigen Signaturen. Die
`CertificateVerify`-Authentisierung des Go-TLS-Stacks verwendet dagegen den
gepinnten Ed25519-Anteil; der Schlüsselaustausch ist hybrid, die
Transportauthentisierung selbst aber nicht post-quantenresistent. Das darf nicht
als vollständig PQ-authentisierter Kanal dokumentiert werden. Eine spätere
Migration muss eine standardisierte, in Go unterstützte hybride TLS-
Signaturmethode verwenden und darf kein eigenes Handshake-Protokoll erfinden.

Das Verzeichnis ist eventual-consistent: Nodes und Clients vereinigen signierte
Seed-Sichten, aber kein Protokollteil kann beweisen, dass ein böswilliges Seed
keinen gültigen Eintrag verschweigt. Kolludiert das konfigurierte Seed-Quorum,
sind Sybil- und Eclipse-Angriffe weiter möglich. Quellen-IP plus Rückruf-Challenge
verhindern beliebige Dritt-IP-Einträge, lösen aber keine gemeinsame-NAT- oder
Betreiberidentität. Leases entfernen offline gegangene Nodes erst nach Ablauf;
Nichterreichbarkeit allein wird bewusst nicht als öffentlich beweisbares
Fehlverhalten behandelt. Details: [`docs/NODE-DIRECTORY-V1.md`](docs/NODE-DIRECTORY-V1.md).

### 1:1-Kryptografie

`pqcrypto.Seal` ist eine echte hybride ML-KEM-768/X25519-HPKE-Versiegelung. Ein
statischer Empfängerschlüssel allein bietet jedoch keine vollständige Forward
Secrecy bei späterem Verlust dieses Schlüssels. Er darf produktiv nur für
Prekeys, Gerätezertifikate oder als Baustein eines auditierten Ratchet-Protokolls
verwendet werden.

Produktionsziel: geprüftes PQXDH plus Double/Triple Ratchet oder ein äquivalentes
standardisiertes Protokoll. Keine eigene Ratchet-Konstruktion entwickeln.

Die neue Provider-Grenze ist kein Ratchet und ihre Assurance-Struktur kein
Auditnachweis. Der konkrete Adapter, dessen Zustandsdatenbank und die angegebene
Audit-Referenz bleiben Teil der Trusted Computing Base und müssen vor Integration
unabhängig geprüft werden.

### Identität und Zustellbelege

`ENIGC1…` ist ein Fingerprint des hybriden Account-Signaturschlüssels, nicht der
private Schlüssel und kein alleinstehender Verschlüsselungsschlüssel. Ein
unvertrauenswürdiges Directory liefert dazu das hybrid signierte öffentliche
Profil mit zertifizierten Geräteschlüsseln. Bekannte Revisionsnummern müssen
lokal geschützt gepinnt werden; ohne Key Transparency kann eine Erstinstallation
einen alten, aber korrekt signierten Profilstand nicht als Rollback erkennen.

Der Account-Schlüssel zertifiziert Geräte. Nachrichten und Zustellbelege werden
vom jeweiligen Gerät signiert und erst danach innerhalb des Ratchets
verschlüsselt. Das liefert starke Authentizität und übertragbare Belege, reduziert
aber kryptografische Deniability. Eine Client-Zustellquittung beweist Annahme und
Authentifizierung durch ein Empfängergerät, nicht menschliches Lesen. Eine
Node-Speicherquittung beweist nur die signierte Speicherbehauptung einer Node.

`account.Register` gibt erst Erfolg zurück, nachdem der private Account- und
Gerätezustand über `SecretVault.Store` geschrieben wurde. Das Repository enthält
keinen plattformspezifischen Vault-Adapter; dessen atomare, hardware-/OS-gestützte
Implementierung ist eine offene Produktionsanforderung.

### Direkte Anrufe

`call.Endpoint` ermöglicht direkte 1:1-WebRTC-Anrufe. Der Medienkanal besitzt
klassische Forward Secrecy auf Sitzungsebene, weil Pion ausschließlich
ECDHE-DTLS-Ciphersuites verwendet. Ein späterer Verlust der langfristigen
Geräte-Signaturschlüssel entschlüsselt keine aufgezeichnete, abgeschlossene
DTLS-SRTP-Sitzung. Das gilt nur unter der Annahme, dass ephemere
Sitzungsgeheimnisse nicht während des Calls kompromittiert wurden und die
verwendeten Bibliotheken sowie Endgeräte korrekt arbeiten.

Bewusste Grenzen:

- Der ECDHE-Schlüsselaustausch ist nicht post-quantenresistent. Die hybride
  Ed25519/ML-DSA-Signatur authentisiert das SDP, macht ECDHE aber nicht PQ-sicher.
- Ein laufender Call hat keinen eigenen Double Ratchet und keine
  Post-Compromise-Recovery. Darum erzwingt der Core eine maximale Call-Dauer;
  ein neuer Call erzeugt eine neue Sitzung.
- Direkte ICE-Kandidaten legen dem Gesprächspartner IP-Adressen offen. Mit der
  ICE-Richtlinie `relay` sieht der Gesprächspartner nur den TURN-Relay, dafür
  kennt der TURN-Betreiber Verbindungsmetadaten. TURN erhält keinen
  Medienklartext.
- STUN, TURN und ein Netzbeobachter sehen Timing, Datenmenge und Dauer. E2EE ist
  keine Metadatenanonymität.
- SFU- und Gruppenanrufe sind nicht implementiert. Sie dürfen erst mit einer
  auditierten RFC-9605-SFrame-Implementierung und einem auditierten
  forward-secure Key-Manager, typischerweise RFC 9420 MLS, freigeschaltet werden.
- SFrame allein löst weder Schlüsselverwaltung noch Replay- oder eindeutige
  Senderauthentisierung. Diese Eigenschaften müssen der Key-Manager und die
  Anwendung liefern.
- Kompromittierte Endgeräte, Mikrofon-/Kamera-Malware und ein böswilliger
  Gesprächsteilnehmer können Klartext erfassen. Das Protokoll kann das nicht
  verhindern.

Der Call-Code und die Pion-Abhängigkeit wurden in diesem Repository getestet,
aber nicht unabhängig auditiert. Vor Produktion bleiben zwei unabhängige Audits
und ein Audit der Plattform-Medienadapter Pflicht.

### Gruppen

`group.State` autorisiert Add, Remove, Ban, Admin-Delegation und Owner-Transfer.
Es verschlüsselt keine Gruppeninhalte. Jede erfolgreiche Zustandsänderung muss
atomar mit einem MLS-Proposal und MLS-Commit verbunden werden.

Der Owner-Schlüssel ist ein Administrations-Signaturschlüssel, kein universeller
Entschlüsselungsschlüssel. Ein Master-Entschlüsselungsschlüssel würde Forward
Secrecy und den Schutz gebannter Mitglieder zerstören.

### Böse Nodes

Der Client verlangt signierte Speicherbelege und führt Stichproben durch. Drei
aufeinanderfolgende Fehler schließen eine Node lokal für 24 Stunden aus.

Nicht implementiert ist ein netzwerkweiter Ausschluss. Ausbleibende Antworten
sind allein nicht kryptografisch beweisbar. Für einen globalen Ausschluss braucht
es mehrere zufällig gewählte Auditoren, Merkle-Proofs über gespeicherte Blöcke,
signierte widersprüchliche Aussagen und eine Registry-Quorumsentscheidung.

### Sybil-Schutz

Node-Schlüssel sind weiterhin kostenlos. Das Seed-Quorum begrenzt ungeprüfte
Aufnahmen, ist aber keine permissionless Sybil-Abwehr. Vor einem offenen Netzwerk
sind zusätzlich nötig:

- organisatorisch unabhängige Seed-/Maintainer-Quoren und transparente,
  überprüfbare signierte Checkpoints,
- Node-spezifischer Proof of Replication/Space-Time,
- unvorhersehbare Herausforderungen,
- Probezeit von beispielsweise 30 Tagen,
- global begrenzter Anteil neuer Nodes,
- zufällige Gruppen mit Netz- und Betreiberdiversität.

### Speicherung und Löschung

Der Prototyp verwendet eine JSON-Datei pro Item und hält den Index im RAM. Das
ist leicht prüfbar, aber nicht für Millionen Nachrichten geeignet.

Der Client besitzt nun einen verschlüsselten, crashfest atomar geschriebenen
Dateistore mit einem maximalen 10-GiB-Budget. Er ersetzt weder einen
plattformgebundenen OS-/Hardware-Vault für den Store-Schlüssel noch eine
transaktionale Datenbank für alle zukünftigen Inbox-, Outbox-, Ratchet-, MLS-
und Replay-Operationen. Im aktuellen Core werden Lösch-Capability,
Replikationsbelege und Reparaturzustand persistiert und nach einem Neustart
erneut authentifiziert. Weitere Zustandsarten müssen über dieselbe Schnittstelle
mit expliziter Prune-Richtlinie integriert werden.

Eine signierte Löschbestätigung beweist nur, dass die Node behauptet zu löschen.
Sie kann nicht beweisen, dass keine heimliche Kopie existiert. Ende-zu-Ende-
Verschlüsselung und zeitnahe Schlüsselvernichtung bleiben deshalb entscheidend.

## Schlüsselregeln

- Private Schlüssel niemals in Logs, Crashreports oder Cloud-Backups schreiben.
- Geräteschlüssel mit OS-Keychain beziehungsweise Hardware-Backed Keystore sichern.
- Account-Root, Ratchet-Zustand, Profilrevisionen und Replay-IDs ebenfalls im
  geschützten lokalen Store halten. Der Dateistore verschlüsselt Daten, aber sein
  32-Byte-Schlüssel muss aus einer produktiven OS-/Hardware-Vault-Implementierung
  stammen; ein einfacher Datei-/Memory-Vault ist nicht produktionsgeeignet.
- Keine geheimen Werte in Go-Strings halten, wenn Bytes verwendet werden können.
- Beim Abmelden Schlüsselmaterial bestmöglich überschreiben und Datenspeicher löschen.
- Node-Identitäten nur über eine signierte Registry vertrauen, nicht über TOFU.
- Jede Netzwerkantwort begrenzen, authentifizieren und auf Replay prüfen.
- Vor einem Produktivstart mindestens zwei unabhängige Sicherheitsaudits durchführen.

Das explizite Angreifer- und Vertrauensmodell steht in
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).
Der letzte interne Prüfbericht steht in
[`docs/SECURITY-REVIEW-2026-07-21.md`](docs/SECURITY-REVIEW-2026-07-21.md).
