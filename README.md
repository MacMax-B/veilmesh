# VeilMesh

VeilMesh ist ein ausführbares Grundprojekt für einen anonymitätsorientierten,
dezentralen Messenger. Es trennt den plattformneutralen Client-Core strikt von
Frontends und Node-Servern. Android-, iOS-, Desktop-, CLI- und Web-Oberflächen
können später dieselbe Core-API verwenden.

Das Repository ist ein **Security-Prototyp und kein produktionsfertiger
Messenger**. Die bereits implementierten Bausteine sind real und getestet; die
noch fehlenden Sicherheitsgrenzen sind in `SECURITY.md` und `docs/ARCHITECTURE.md`
explizit aufgeführt.

## Bereits implementiert

- Client-Core als öffentliches Go-Paket ohne Benutzeroberfläche
- Node-Server mit persistenter, automatisch ablaufender Speicherung
- festes Speicherfenster: jedes Item läuft exakt 60 Tage nach Erstellung ab;
  ein anderes Ablaufdatum wird abgelehnt, früheres Entfernen geht nur über die
  geheime Lösch-Capability
- Rechenporto (Proof of Work), das bei hoher Speicherauslastung steigt
- hybride ML-KEM-768/X25519-HPKE-Verschlüsselung für versiegelte Nachrichten
- hybride Ed25519- und ML-DSA-65-Signaturen für Node-Belege und Administration
- ein Schlüssel oder eine Signatur gilt nur, wenn beide Verfahren gültig sind
- gepolsterte Textnachrichten und konstant große verschlüsselte Dateiblöcke
- konfigurierbare Dateigrößenbegrenzung
- Lösch-Capabilities statt Benutzeridentitäten auf Nodes
- Löschen von Dateien erst nach vollständigem Download und Authentifizierung
- Replikationsquorum, signierte Speicherbelege und automatische Ersatz-Nodes
- zufällige Speicherprüfungen und lokaler Ausschluss unzuverlässiger Nodes
- authentisiert verschlüsselter lokaler Client-Store mit standardmäßig und
  maximal 10 GiB, oldest-first Cache-Pruning und Schutz nicht abgelaufener
  Sicherheitszustände sowie exklusivem Prozess-Lock
- verschlüsselter Sync zu allen durch das Konto signierten eigenen Geräten
- selbstzertifizierende, typisierte `ENIGC1…`-Konten, `ENIGD1…`-Geräte und
  `ENIGG1…`-Gruppen; Directory-Antworten werden lokal neu gebunden und signiert
- Registrierung hinter einer verpflichtenden OS-Keychain-/Hardware-Vault-Grenze
- hybrid gerätesignierte Nachrichten und gerätesignierte Client-Zustellbelege
- strikt geschlossener Nachrichtenpfad, der ohne auditierten PQ-Ratchet,
  persistenten Replay-Speicher und Mix-/Cover-Transport nicht startet
- `VeilMix v2`: moderater, größenbegrenzter Command-Layer und konstant
  getakteter Real-/Poll-/Cover-Scheduler mit festen Paketen und hartem
  Fail-Closed-Verhalten
- IP-basiertes Node-Verzeichnis mit ausgelieferter Seed-Pin-Liste, hybrid
  signierten Kurzzeit-Leases, Rückruf-Challenge, Seed-Quorum, Ablaufbereinigung
  und signierten vollständigen Snapshots für Nodes und Clients
- CA-PKI-freie Client↔Node- und Node↔Node-Kanäle: automatisch aus der Node-
  Identität erzeugter Zertifikatscontainer, exaktes Schlüssel-Pinning und
  erzwungener TLS-1.3-Schlüsselaustausch mit `X25519MLKEM768`
- Gruppenrollen, Ban, Admin-Delegation und Eigentümerübertragung
- Provider-Schnittstelle für RFC-9420-MLS/TreeKEM
- direkte 1:1-Audio-/Videoanrufe über authentisiertes WebRTC DTLS-SRTP
- pro Call ephemerer DTLS-Fingerprint, hybrid signiertes SDP, Replay- und
  Ressourcenlimits sowie klassische Forward Secrecy auf Sitzungsebene

## Bewusst noch nicht als „gelöst“ bezeichnet

- Der Referenztransport ist direktes, identitätsgepinntes HTTPS ohne öffentliche
  PKI (Plain HTTP nur explizit für lokale Entwicklung). Er verbirgt IP-Adressen und
  Zeitkorrelationen nicht. Produktiv braucht er ein geprüftes Onion-/Mixnet-
  Transportmodul, Cover Traffic, Batching und TLS/QUIC innerhalb der Hops.
- Der VeilMix-Scheduler und seine PQ-/Audit-Provider-Grenzen sind implementiert;
  ein konkreter auditierter PQ-hybrider Sphinx-/Mixnet-Provider, Courier und
  reale Relay-Infrastruktur sind noch nicht enthalten.
- Die versiegelte HPKE-Nachricht ist ein sicherer PQ-hybrider Baustein, aber noch
  kein vollständiges PQXDH-/Double-Ratchet-Protokoll mit Forward Secrecy und
  Post-Compromise Security. `message.StrictPipeline` definiert und erzwingt die
  Provider-Grenze; ein konkreter auditierter Provider ist noch nicht enthalten.
- Die Secret-Vault-Schnittstelle ist implementiert, nicht jedoch die
  plattformspezifischen Keychain-/Secure-Enclave-Adapter.
- ENIG-IDs verhindern unbemerkten Schlüssel-Austausch. Ein Verzeichnis kann
  Profile weiterhin vorenthalten und bei einer frischen Installation einen alten,
  noch gültig signierten Stand wiedergeben; dafür fehlen Key Transparency und
  ein gesicherter lokaler Revisions-Pin.
- Direkte 1:1-Calls sind E2EE und klassisch forward-secret. Der DTLS-ECDHE-
  Schlüsselaustausch ist noch nicht post-quantenresistent und besitzt während
  eines laufenden Calls keine Post-Compromise-Recovery. SFU-/Gruppencalls
  benötigen eine auditierte SFrame+MLS-Integration und sind nicht aktiviert.
- Gruppen-Administration ist implementiert; die eigentliche Gruppenverschlüsselung
  muss über einen auditierten MLS-Provider erfolgen. Die hybriden PQ-MLS-
  Ciphersuites sind im Juli 2026 noch IETF-Entwürfe.
- Das signierte Node-Verzeichnis verhindert ungeprüfte Einzelanmeldungen, ist
  aber noch keine permissionless Sybil-Lösung: Seed-Quorum, Betreiberdiversität,
  Probezeit und Ressourcennachweis bleiben eine Produktionsanforderung.
- Ein lokaler Client kann böse Nodes ausschließen. Netzwerkweit beweisbarer
  Ausschluss benötigt Merkle-Speichernachweise und mehrere unabhängige Auditoren.

## Projektstruktur

```text
account/       Konten, Geräte-Zertifikate und verschlüsselter Geräte-Sync
identity/      selbstzertifizierende ENIG-Konto-, Geräte- und Gruppen-IDs
message/       signierte Nachrichten/Client-Belege und strikte Provider-Grenzen
mixtransport/  VeilMix-v2-Commands und moderater Real/Poll/Cover-Scheduler
nodedir/       signierte IP-Leases, Seed-Quorum und Snapshot-Reconciliation
client/        UI-unabhängiger Client-Core, Replikation, Audit und Failover
cmd/veilnode/  ausführbarer Referenz-Node
group/         Admin-/Ban-Zustandsmaschine und MLS-Provider-Grenze
call/          direkte, hybrid authentisierte WebRTC-DTLS-SRTP-Calls
media/         gepolsterte, verschlüsselte Datei- und Bildblöcke
node/          Node-HTTP-API und persistenter Speicher
pqcrypto/      Hybrid-HPKE, Hybrid-Signaturen und Padding
transportauth/ CA-PKI-freies Node-Key-Pinning und hybrides TLS-1.3-Profil
protocol/      versionsgebundene Transportobjekte und Proof of Work
docs/          Architektur, Protokoll und Codex-Weiterbauanleitung
```

## Voraussetzungen

- Go 1.26.5 oder neuer; `go.mod` pinnt den minimal gehärteten Toolchain
- ein Betriebssystem, das von Go unterstützt wird

Go 1.26 wird wegen dessen standardisierter ML-KEM- und hybrider
HPKE-Unterstützung benötigt. Patchlevel 1.26.5 ist das Minimum, weil ältere
1.26-Patchstände erreichbare Standardbibliotheks-Advisories enthalten.

## Testen

```bash
go mod download
go test ./...
go test -race ./...
```

Die Integrationstests starten lokale kurzlebige Nodes und prüfen Verschlüsselung,
Replikation, Ausfallersatz, Speicher-Audit und Löschen.

## Entwicklungs-Node starten

```bash
go run ./cmd/veilnode \
  -listen 127.0.0.1:8787 \
  -data ./local/node-1-data \
  -key ./local/node-1-key.json \
  -difficulty 16
```

Für ein Quorum sollten mindestens fünf unabhängige Nodes laufen. Der
Referenzserver sollte nicht direkt ins öffentliche Internet gestellt werden.

Der optionale Verzeichnisbetrieb verlangt eine mit Client-Releases gemeinsam
ausgelieferte `veilmesh-seeds.json`. Sie pinnt vollständige hybride
Seed-Identitäten und literale IP-Endpunkte. Eine öffentliche Node wird zum
Beispiel mit `-advertise-ip`, `-advertise-port`, `-node-seeds` und
`-node-quorum` gestartet. Der Server erzeugt seinen Zertifikatscontainer
automatisch aus dem persistenten Node-Schlüssel; `-tls-cert`, `-tls-key`, eine
CA und IP-SANs sind nicht erforderlich. Reale Seed-IP-Adressen und -Schlüssel
sind absichtlich nicht erfunden oder im Prototyp vorgegeben. Der
Zertifikatscontainer wird vor Ablauf automatisch erneuert, ohne den gepinnten
Node-Schlüssel zu ändern.

## Direkttransport verwenden

```go
nodeA, _ := client.ConnectPinnedHTTPNode(ctx, "https://127.0.0.1:8787", pinnedIdentityA, nil)
nodeB, _ := client.ConnectPinnedHTTPNode(ctx, "https://127.0.0.1:8788", pinnedIdentityB, nil)
nodeC, _ := client.ConnectPinnedHTTPNode(ctx, "https://127.0.0.1:8789", pinnedIdentityC, nil)

// storeKey muss produktiv aus OS-Keychain/Secure Enclave kommen.
store, _ := client.NewEncryptedDiskStore(client.DiskClientStoreConfig{
    Directory: "./local/client-state",
    Key:       storeKey,
    // 0 verwendet das sichere Standard- und Maximallimit von 10 GiB.
    MaxBytes: 0,
}, time.Now())

core, _ := client.New(client.Config{
    Nodes:       []*client.HTTPNode{nodeA, nodeB, nodeC},
    Replicas:    3,
    WriteQuorum: 2,
    Store:       store,
})

recipient, _ := pqcrypto.GenerateHybridKEMKeyPair()
routeTag, _ := client.RandomCapability()
// Jedes Item wird exakt für das feste 60-Tage-Protokollfenster gespeichert.
delivery, err := core.SendDirect(
    ctx,
    recipient.PublicKey,
    routeTag,
    []byte("Hallo"),
)
```

Die `pinnedIdentity*`-Werte müssen aus der ausgelieferten Seed-Liste oder einem
vollständig verifizierten Directory-Record stammen; sie dürfen nicht vom gerade
kontaktierten Netzpfad übernommen werden. Der ausführbare Node lauscht immer mit
diesem CA-PKI-freien verschlüsselten Transport. Plain HTTP bleibt ausschließlich
für eingebettete private Entwicklungstests über
`DiscoverHTTPNodeForDevelopment` verfügbar.

`Core.SendDirect` ist nur der direkte Entwicklungs-/Bootstrap-Pfad und erfüllt
weder Forward Secrecy noch Metadatenanonymität. Eine produktive App registriert
zuerst mit `account.Register(ctx, secretVault)`, teilt die resultierende
`ENIGC1…`-ID und verwendet ausschließlich `message.NewStrictPipeline` mit
auditiertem Ratchet-, Replay- und Mixnet-Adapter.

Frontends sollen weder eigene Kryptografie implementieren noch direkt mit Nodes
sprechen. Sie rufen ausschließlich den Client-Core auf und erhalten daraus
Ereignisse, Nachrichtenmodelle und Zustandsänderungen.

Die geplante stabile Oberfläche für Apps und alternative Frontends steht in
[`docs/FRONTEND-API.md`](docs/FRONTEND-API.md).
Das eigene Metadatenprotokoll ist in
[`docs/VEILMIX-V2.md`](docs/VEILMIX-V2.md) spezifiziert. Das Node-Verzeichnis ist
in [`docs/NODE-DIRECTORY-V1.md`](docs/NODE-DIRECTORY-V1.md) beschrieben.

## Direkten 1:1-Call aushandeln

```go
caller, _ := call.NewEndpoint(call.Config{Signer: callerDeviceSigner})
callee, _ := call.NewEndpoint(call.Config{Signer: calleeDeviceSigner})

outgoing, offer, _ := caller.Start(ctx, callee.Identity(), call.Media{Audio: true})
// offer als Inhalt einer bestehenden E2E-verschlüsselten Nachricht senden.

incoming, answer, _ := callee.Accept(ctx, caller.Identity(), offer)
// answer auf demselben E2E-Kanal zurücksenden.
_ = outgoing.ApplyAnswer(answer)

// Plattformadapter hängen danach Pion-Audio-/Videotracks an die Sessions.
defer outgoing.Close()
defer incoming.Close()
```

Das vollständige SDP darf nicht durch ein Frontend oder einen Signaling-Server
verändert werden. Direkte Kandidaten legen dem Gesprächspartner IP-Adressen
offen; `ICETransportPolicyRelay` erzwingt TURN, schützt aber nicht vor Timing-
und Volumenmetadaten beim Relay.

## Kryptografische Grundlagen

- [NIST FIPS 203 – ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 – ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [RFC 9420 – Messaging Layer Security](https://www.rfc-editor.org/rfc/rfc9420)
- [RFC 9605 – Secure Frame](https://www.rfc-editor.org/rfc/rfc9605)
- [Signal PQXDH](https://signal.org/docs/specifications/pqxdh/)
- [IETF-Entwurf zu PQ-MLS-Ciphersuites](https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/)

Vor einem realen Einsatz sind unabhängige Protokoll-, Kryptografie-,
Metadaten- und Implementierungs-Audits zwingend.

## Lizenz

Dieses Projekt steht unter der [GNU Affero General Public License v3.0](LICENSE)
(AGPL-3.0). Wer VeilMesh verändert und als Netzwerkdienst betreibt, muss den
Quelltext der veränderten Version den Nutzern dieses Dienstes zugänglich machen.
