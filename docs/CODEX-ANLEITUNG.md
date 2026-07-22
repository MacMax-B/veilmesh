# Anleitung für Codex: VeilMesh sicher weiterbauen

Diese Datei ist die Arbeitsreihenfolge für weitere Codex-Sitzungen. Vor jeder
Änderung zuerst `AGENTS.md`, `SECURITY.md`, `docs/ARCHITECTURE.md` und diese Datei
vollständig lesen.

## Leitprinzip

VeilMesh darf nie Sicherheit behaupten, die nur geplant ist. Implementierte,
getestete Eigenschaften und offene Forschungs-/Auditpunkte bleiben in der
Dokumentation getrennt.

## Phase 1: stabiler Client-Core

Aktueller Stand: `client.EncryptedDiskStore` und `ClientStore` sind vorhanden,
authentisiert verschlüsselt, atomar geschrieben, auf maximal 10 GiB und eine
feste Datensatzanzahl begrenzt. Replikationsbelege und Lösch-Capabilities werden
persistiert und beim Neustart erneut geprüft. Der Schlüssel muss weiterhin aus
einem OS-/Hardware-Vault geliefert werden.

1. Den vorhandenen verschlüsselten `ClientStore` beibehalten und alle neuen
   Datensätze mit einer expliziten, sicher begründeten Prune-Richtlinie versehen.
2. Outbox, Inbox, Replikationsstatus, Lösch-Capabilities, Geräteereignisse und
   Node-Reputation transaktional speichern.
3. Die vorhandene `account.SecretVault`-Grenze mit OS-Keychain-/Secure-Enclave-
   Adaptern verbinden; Dateischlüssel nie ungeschützt in einer allgemeinen
   Datenbank speichern.
4. Ereignis-API für Frontends ergänzen:
   `MessageReceived`, `DeliveryChanged`, `NodeExcluded`, `GroupChanged`.
5. FFI-freundliche DTOs versionieren und anschließend Android/iOS-Bindings mit
   `gomobile bind` sowie eine lokale Desktop-IPC-Schicht erzeugen.

Abnahmekriterien:

- Neustart verliert keine ausstehenden Reparaturen.
- Zwei Frontends erzeugen identische Core-Zustände.
- Kein Frontend importiert `node`, `pqcrypto` oder rohe Transportpakete.

## Phase 2: produktives 1:1-Protokoll

1. Keine eigene Ratchet-Kryptografie programmieren.
2. Die vorhandene `message.RatchetProvider`-Grenze um Prekey-Veröffentlichung und
   Sitzungsaufbau ergänzen; Encrypt, Decrypt, Skip-Key-Limits und Key Deletion
   bleiben gekapselt.
3. Eine auditierte PQXDH- plus Ratchet-Implementierung integrieren. Lizenz und
   Plattform-Support vorher dokumentieren.
4. `pqcrypto.Seal` nur noch für Gerätezertifikate, Prekey-Bundles oder Recovery-
   Kapseln verwenden.
5. Replay-, Out-of-order- und Milliarden-Skip-Angriffe testen.

Abnahmekriterien:

- Forward Secrecy nach Löschung alter Ratchet-Schlüssel.
- Post-Compromise Recovery nach einem Key Update.
- Hybrid klassisch/PQ beim Sitzungsaufbau.
- reproduzierbare Interoperabilitäts-Testvektoren.

## Phase 3: MLS/TreeKEM-Gruppen

1. `group.MLSProvider` mit einer gepflegten RFC-9420-Implementierung verbinden,
   bevorzugt OpenMLS über eine kleine Rust-FFI-Grenze.
2. Jede `group.Action` atomar mit Proposal und Commit anwenden.
3. Gruppenhandshakes als `PrivateMessage` transportieren, soweit RFC 9420 dies
   erlaubt.
4. Owner-Transfer und Admin-Delegation ändern nur Autorisierung, niemals einen
   universellen Entschlüsselungsschlüssel.
5. Gebannte Geräte und Mitglieder müssen nach dem Commit keine neuen Inhalte
   entschlüsseln können.
6. Hybride PQ-MLS-Ciphersuites erst aktivieren, wenn Spezifikation und Provider
   stabil und auditiert sind; bis dahin die Provider-Grenze beibehalten.

Abnahmekriterien:

- Add/Remove/Ban mit mindestens 100 simulierten Mitgliedern.
- konkurrierende Commits und Fork-Recovery getestet.
- alte Mitglieder lesen keine Zukunft; neue Mitglieder lesen keine Vergangenheit.

## Phase 2b: Calls über die direkte Referenz hinaus

Direkte 1:1-Calls sind über signiertes WebRTC-DTLS-SRTP vorhanden. Für jede
Erweiterung gelten zusätzlich:

1. Keine eigene SFrame- oder Call-Ratchet-Kryptografie implementieren.
2. SFU-/Gruppencalls nur mit auditierter RFC-9605-SFrame-Bibliothek und
   auditiertem MLS-Key-Manager aktivieren.
3. Bei jedem Join/Leave Schlüssel rotieren; ein SFrame-Sendeschlüssel gehört
   genau einem Sender.
4. Replay, KID-/CTR-Überlauf, Key-Reuse, simulcast/SVC und verspätete
   Keyframes negativ testen.
5. Medienadapter auf allen Zielplattformen getrennt prüfen; keine SDP-, ICE- oder
   Schlüsselwerte loggen.

Abnahmekriterien:

- SFU sieht keinen Medienklartext.
- Entfernte Teilnehmer entschlüsseln keine neue Epoche.
- Neue Teilnehmer erhalten keine alten Medienkeys.
- Join/Leave und maximale Call-Dauer erzwingen einen Key-Wechsel.
- Interoperabilitätsvektoren für SFrame und MLS sind reproduzierbar.

## Phase 4: Metadatenresistenter Transport

1. Den vorhandenen `mixtransport.Scheduler` und VeilMix v2 niemals mit dem
   direkten HTTP-Transport als „anonym“ verdrahten.
   Produktive Node-Links müssen über `transportauth` laufen: TLS 1.3,
   `X25519MLKEM768` und exaktes Pinning des Ed25519-Anteils der vollständig
   verifizierten hybriden Node-Identität. Keine CA-/SAN-Abhängigkeit ergänzen und
   keine eigene Handshake-Kryptografie bauen.
2. `Transport` in direkte HTTP-, Onion- und Mix-Implementierungen aufteilen.
3. Ein geprüftes PQ-hybrides Paketformat verwenden; keine eigene Onion-Kryptografie.
4. Client wählt Hops, nicht die Entry-Node.
5. Ein Hop darf nie gleichzeitig Sender und finalen Speichertag kennen.
6. Replikation zeitlich durch Relays entkoppeln.
7. Den vorhandenen festen Real-/Poll-/Cover-Scheduler mit öffentlich einheitlichen
   Mobilprofilen und uniformen Downlink-Antworten integrieren.
8. Simulationswerkzeug für Zeitkorrelationsangriffe bauen.

Abnahmekriterien:

- Paketmitschnitt kann Route-Tags nicht über Hops verbinden.
- Nachricht und Dummy-Paket sind außerhalb des Clients nicht unterscheidbar.
- Hintergrundprofil hält definierte Akku- und Datenbudgets ein.

## Phase 5: Node-Registry und Ressourcennachweis

1. Das vorhandene `nodedir`-Lease-/Seed-Quorum nicht in eine offene
   Selbstregistrierung oder DNS-basierte Discovery aufweichen.
2. Produktion mit mindestens 3-von-5 unabhängigen, im Client gepinnten Seeds
   betreiben; Seed-Updates wie sicherheitskritische Client-Updates behandeln.
3. Kontrollzustand zusätzlich mit transparenten signierten Checkpoints
   synchronisieren und Split-Views erkennbar machen.
4. Geprüfte Proof-of-Replication-/Proof-of-Space-Time-Bibliothek auswählen.
5. Commitment vor Zufalls-Challenge erzwingen.
6. Herausforderungen aus einem gemeinsamen, nicht von der Node kontrollierten
   Random Beacon ableiten.
7. 30-tägige Probephase und globales 5-%-Limit für Probe-Nodes implementieren.
8. Speichergruppen deterministisch zufällig und divers zusammenstellen.
9. Netzwerkweiten Ausschluss nur bei beweisbarer Falschaussage oder Quorum
   unabhängiger Verfügbarkeitsprüfer erlauben.

Abnahmekriterien:

- 100.000 Fake-Schlüssel erhöhen den Einfluss nicht ohne lineare Ressourcen.
- Eine einzelne Registry-Stelle kann keine Node aufnehmen oder entfernen.
- Eclipse- und Registry-Split-Simulationen vorhanden.

## Phase 6: skalierbarer Node-Speicher

1. `DiskStore` hinter ein `Store`-Interface verschieben.
2. Atomaren Log-/LSM- oder geeigneten Datenbank-Backend implementieren.
3. Merkle-Root pro verschlüsseltem Blob und Stichprobenpfade ergänzen.
4. Quoten, Garbage Collection und Reparaturen unter Last testen.
5. Keine sekundären Indizes über Identitäten, Kontakte oder Absender anlegen.

Abnahmekriterien:

- Millionen Items ohne vollständigen RAM-Index.
- Crash während Put/Delete beschädigt keine übrigen Items.
- Ablaufbereinigung hat begrenzte I/O-Spitzen.

## Pflichtprüfungen nach jeder Änderung

```bash
gofmt -w ./account ./client ./cmd ./group ./media ./node ./pqcrypto ./protocol
go test ./...
go test -race ./...
go vet ./...
```

Bei Protokoll-, Kryptografie-, Gruppen- oder Metadatenänderungen zusätzlich:

- Threat Model aktualisieren,
- neue Negativtests und Fuzztests hinzufügen,
- Protokollversion prüfen,
- keine Sicherheitsbehauptung ohne Test oder externe Analyse ergänzen.
