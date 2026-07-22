# Frontend-API

Frontends sind austauschbare Darstellungen. Sie dürfen weder kryptografische
Schlüssel ableiten noch Node-Quoren, Lösch-Tokens oder Route-Tags verwalten.

## Aktuelle öffentliche Core-Funktionen

- `client.New`: Core mit vertrauenswürdig bezogenen Node-Deskriptoren erstellen.
- `client.ConnectPinnedHTTPNode`: produktiven CA-PKI-freien TLS-1.3-Kanal gegen eine
  bereits vertrauenswürdig bezogene vollständige Node-Identität aufbauen;
  `DiscoverHTTPNode` bleibt für konventionell CA-validiertes HTTPS und
  `DiscoverHTTPNodeForDevelopment` erlaubt Plain HTTP nur explizit für literale
  Loopback-/private IPs.
- `client.NewEncryptedDiskStore`: lokalen authentisiert verschlüsselten Store
  mit standardmäßig und maximal 10 GiB aufbauen. Der 32-Byte-Schlüssel muss aus
  einem OS-/Hardware-Vault kommen und darf nicht an die UI gelangen.
- `client.FetchNodeDirectory`: mehrere gepinnte Seed-Snapshots prüfen und die
  vollständige aktive Union der hybrid attestierten IP-Leases liefern.
- `client.ConnectDirectoryRecords`: eine hart begrenzte Auswahl aufbauen und
  jede präsentierte Node-Identität nochmals gegen den Directory-Record prüfen.
- `Core.SendDirect`: gepolsterte, hybrid PQ-verschlüsselte Nachricht replizieren.
- `Core.Fetch`: Ciphertext über kurzlebige Route-Tags abrufen und deduplizieren.
- `client.OpenDirectItem`: versiegelte Nachricht lokal öffnen.
- `Core.Audit`: bestätigte Replikate durch zufällige Byte-Challenges prüfen.
- `Core.AuditAndRepair`: fehlerhafte Replikate auf Ersatz-Nodes schreiben.
- `Core.Delete`: bekannte Replikate capability-basiert löschen.
- `Core.LoadDelivery`: Replikations-, Reparatur- und Löschzustand nach Neustart
  laden und alle Node-Belege erneut hybrid prüfen.
- `Core.ClientStorageUsage`, `Core.SetClientStorageLimit`,
  `Core.PruneClientStorage`: Belegung anzeigen, ein kleineres Limit setzen und
  nur gemäß expliziter Prune-Richtlinie bereinigen.
- `Core.Reputation`: lokalen Node-Status für Diagnose darstellen.
- `media.EncryptFile`, `media.Store`, `media.Retrieve`: Bilder und Dateien.
- `account.SignDevice`, `account.SealSyncEvent`: eigene Geräte verbinden.
- `account.Register`, `account.Load`: `ENIGC1…`-Konto ausschließlich hinter
  einer geschützten `SecretVault`-Implementierung erzeugen beziehungsweise laden.
- `account.ResolveVerified`: unvertrauenswürdige Directory-Profile gegen ID,
  Signatur und lokal gepinnte Mindest-Revision prüfen.
- `message.NewStrictPipeline`: produktiven Nachrichtenpfad nur mit auditiertem
  Ratchet, persistentem Replay-Store und Mix-/Cover-Transport erzeugen.
- `StrictPipeline.SendDirect`, `StrictPipeline.OpenDirect`: pro Gerät ratcheten,
  ENIG-/Signaturprüfung und Replay-Schutz ausführen.
- `message.NewDeliveryReceipt`, `message.VerifyDeliveryReceipt`: signierte
  Geräte-Zustellbelege erstellen und prüfen.
- `mixtransport.NewCommand`, `mixtransport.Scheduler.Enqueue`: opaque Operationen
  außerhalb des Sendeslots vorbereiten; der Scheduler selbst läuft ausschließlich
  im Core und darf von der UI weder pausiert noch aktivitätsabhängig umgestellt werden.
- `group.State.Apply`: signierte Rollen- und Mitgliedschaftsänderungen.
- `call.NewEndpoint`, `Endpoint.Start`, `Endpoint.Accept`,
  `Session.ApplyAnswer`: authentisierte direkte 1:1-Calls.
- `Session.ReplaceAudioTrack`, `Session.ReplaceVideoTrack`, `Session.OnTrack`:
  schmale Plattform-Mediengrenze ohne Zugriff auf Call-Schlüssel.

## Geplante stabile FFI-Oberfläche

Die nächste Core-Schicht soll nur plattformneutrale IDs, Byte-Arrays und
versionierte JSON/CBOR-DTOs exportieren:

```text
CreateAccount
LinkDevice
SendMessage
SendFile
PollEvents
MarkRead
RetryDelivery
CreateGroup
AddGroupMember
BanGroupMember
GrantGroupAdmin
TransferGroupOwnership
SetRetention
GetClientStorageUsage
SetClientStorageLimit
PruneClientStorage
GetNodeHealth
StartDirectCall
AcceptDirectCall
EndDirectCall
```

`SetRetention` betrifft ausschließlich die anwendungsseitige, Ende-zu-Ende-
verschlüsselte Anzeige- und Löschrichtlinie. Das Speicherfenster auf Nodes ist
protokollweit fest (60 Tage) und für Frontends nicht konfigurierbar.

Call-Signale werden ausschließlich innerhalb des verschlüsselten
Nachrichtenkanals übertragen. Ein Frontend darf SDP weder verändern noch selbst
signieren. Plattformcode liefert nur Audio-/Videotracks und empfängt Remote-
Tracks. TURN-Zugangsdaten und ICE-Richtlinien gehören in den Core-Adapter, nicht
in frei loggende UI-Zustände.

UI-Frameworks abonnieren ausschließlich Core-Ereignisse. Dadurch können Flutter,
React Native, SwiftUI, Jetpack Compose, Desktop- und CLI-Frontends nebeneinander
existieren, ohne das Sicherheitsprotokoll zu duplizieren.

## Bindings

- Android/iOS: nach Stabilisierung der DTOs mit `gomobile bind`.
- Desktop: Go direkt oder lokaler Core-Prozess über geschützten Unix Socket/
  Named Pipe.
- Web: erst nach separater Browser-Bedrohungsanalyse; Schlüsselmaterial in einer
  normalen Webseite ist deutlich schwerer zu schützen.

Die FFI-Grenze darf keine privaten Schlüssel, Lösch-Tokens oder ungefilterten
Netzwerkantworten an ein Frontend zurückgeben.

`client.Core.SendDirect` und `client.OpenDirectItem` bleiben ausdrücklich
Entwicklungs-/Bootstrap-APIs. Frontends dürfen daraus weder Forward Secrecy noch
Metadatenanonymität ableiten.
