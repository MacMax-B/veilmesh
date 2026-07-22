# Referenzprotokoll v1

## Node-Endpunkte

| Methode | Pfad | Zweck |
|---|---|---|
| `GET` | `/v1/health` | knapper Verfügbarkeitscheck |
| `GET` | `/v1/identity` | hybride öffentliche Node-Identität |
| `GET` | `/v1/parameters` | Größen-, PoW- und Kapazitätsgrenzen |
| `GET` | `/v1/nodes` | hybrid signierter Snapshot aller aktiven Node-Leases |
| `POST` | `/v1/nodes/register` | signierte Lease beim gepinnten Seed attestieren lassen |
| `POST` | `/v1/nodes/challenge` | frische Rückruf-Challenge hybrid signieren |
| `POST` | `/v1/items` | Ciphertext speichern und Beleg erhalten |
| `POST` | `/v1/fetch` | mehrere Route-Tags abfragen |
| `POST` | `/v1/proof` | zufällige gespeicherte Bytes beweisen |
| `POST` | `/v1/delete` | mit geheimer Capability löschen |

Sensible Tags werden in Request-Bodies übertragen, nicht in URL-Pfaden. Das
ersetzt keinen anonymen Transport, reduziert aber versehentliche Proxy-Logs.

Produktive direkte Links verwenden TLS 1.3 als standardisierten Handshake und
AEAD-Record-Layer, jedoch ohne öffentliche PKI: Der selbstsignierte
Zertifikatscontainer trägt den Ed25519-Schlüssel der bereits bekannten hybriden
Node-Identität. Die Gegenstelle pinnt diesen Schlüssel und erzwingt
`X25519MLKEM768`; CA-, DNS- und SAN-Prüfungen sind nicht Teil des Trust-Modells.
Die Anwendung erfindet keinen eigenen Key Exchange. Directory-Objekte,
Speicherbelege, Proofs und Löschbelege verlangen unabhängig davon weiterhin
gültige Ed25519- und ML-DSA-65-Signaturen.

Route-Tags sind exakt 32 zufällige Bytes in ungepaddetem Base64url. Fetches sind
auf 256 unterschiedliche Tags sowie 512 Items beziehungsweise 8 MiB
Ciphertext begrenzt. Eine Überschreitung liefert einen Fehler statt einer still
abgeschnittenen Antwort.

## ENIG-Identitäten und öffentliche Profile

Alle teilbaren Adressen verwenden ungepaddeltes, kanonisches Base32 über einen
domänenseparierten SHA-256-Digest:

- Account: `ENIGC1` plus 52 Zeichen, gebunden an Ed25519- und ML-DSA-65-Key.
- Gerät: `ENIGD1` plus 52 Zeichen, gebunden an dessen Signatur-Keypair.
- Gruppe: `ENIGG1` plus 52 Zeichen, gebunden an Creator, Genesis-Nonce und
  kanonische Genesis-Policy.

Ein Account-Profil enthält Account-ID/-Public-Key, monotone Revision,
Aktualisierungszeit und höchstens 32 sortierte, account-signierte
Gerätezertifikate. Das gesamte Profil ist nochmals vom Account hybrid signiert.
Parser lehnen unbekannte Felder, nachgestellte JSON-Werte, falsche Typ-Präfixe,
unsortierte/duplizierte Geräte und Profile über 256 KiB ab.

## Signierte Nachrichten und Client-Belege

Eine direkte Nachricht bindet Version, Typ, zufällige 32-Byte-Message-ID,
`ENIGC1…`-Sender und -Empfänger, das Account-zertifizierte Sendergerät,
Erstellungs-/Ablaufzeit und maximal 192 KiB Body. Das Gerät signiert alle Felder
gleichzeitig mit Ed25519 und ML-DSA-65. Dieses Objekt wird vollständig innerhalb
des Session-Ratchets verschlüsselt.

Ein Client-Zustellbeleg bindet Message-ID, SHA-256 des vollständigen signierten
Nachrichtenobjekts, beide Konten, Empfängergerät und Empfangszeit. Er wird vom
Empfängergerät hybrid signiert und ebenfalls nur im Ratchet transportiert. Er
ist nicht mit einem Node-Speicherbeleg gleichzusetzen und behauptet kein Lesen.

## VeilMix v2

VeilMix-Commands verwenden eine unabhängige Version `2`, eine zufällige
32-Byte-Request-ID, einen bekannten Operationstyp, Erstellungs-/Ablaufzeit und
maximal 2 KiB opaque Payload. Encodings sind auf 4 KiB begrenzt. v2 legt exakt
8 KiB, fünf Sekunden Slotintervall und einen Poll in jedem sechsten Slot fest.
Abweichende Netzwerkprofile und v1 werden als fingerprintbar beziehungsweise
inkompatibel abgelehnt.

In jedem aktiven Slot wird exakt ein festes Paket versendet. Poll-Slots hängen
nur von der öffentlichen Slotnummer ab. In allen anderen Slots ersetzt Cover
eine leere Queue, einen abgelaufenen Command oder fehlende Anwendungsaktivität.
Das normative Ablauf- und Angreifermodell steht in
[`VEILMIX-V2.md`](VEILMIX-V2.md).

## Node-Verzeichnis v1

Eine Node-Lease bindet Protokollversion, vollständige hybride Node-Identität,
kanonischen literal-IP-Endpunkt, monotone Sequenz sowie Ausgabe-/Ablaufzeit. Die
Node signiert alle Felder gleichzeitig. Leases gelten 10 Minuten bis höchstens
2 Stunden. Ein nicht gepinnter Eintrag benötigt unterschiedliche gültige
Attestierungen des lokal gepinnten Seed-Quorums über den Hash der vollständigen
Lease einschließlich ihrer Signatur.

Produktiv sind nur CA-PKI-frei identitätsgepinnte `https`-Endpunkte mit öffentlich
routbarer IP zulässig. TLS 1.3 und `X25519MLKEM768` sind zwingend; ein
CA-Zertifikat oder IP-SAN wird nicht benötigt.
Private IPs und `http` sind nur im expliziten Entwicklungsmodus erlaubt. DNS-
Namen, Redirects, doppelte Attestierer, Rollbacks derselben Node-ID, unsortierte
Snapshots, unbekannte Felder und übergroße Antworten werden abgewiesen. Die
vollständige Spezifikation steht in
[`NODE-DIRECTORY-V1.md`](NODE-DIRECTORY-V1.md).

TLS-Handschlag und Record-Layer folgen
[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html). Das externe
Public-Key-Pinning ohne Zertifizierungsstelle entspricht dem Trust-Modell der
Raw-Public-Key-Anwendungsfälle aus
[RFC 7250](https://www.rfc-editor.org/rfc/rfc7250.html); wegen der Go-API wird
der gepinnte Schlüssel hier in einem selbstsignierten X.509-Container
transportiert, nicht über die RFC-7250-Erweiterung.

## Item-ID

Die Item-ID bindet:

- Protokollversion,
- Route-Tag,
- Erstellungs- und Ablaufzeit,
- Hash der Lösch-Capability,
- SHA-256-Hash des Ciphertexts.

Der PoW-Nonce ist nicht Bestandteil der Item-ID, sodass derselbe Ciphertext auf
mehreren Nodes und in späteren Epochen repariert werden kann.

## Festes Ablauffenster

Jedes Item läuft exakt 60 Tage nach seiner Erstellungszeit ab. Nodes erzwingen
`expires_at == created_at + 60 Tage`; jedes andere Ablaufdatum wird als
ungültig abgelehnt. Früheres Entfernen ist nur über die geheime
Lösch-Capability möglich. Die Aufbewahrung ist eine Protokollkonstante und
deshalb bewusst kein Feld in `/v1/parameters`.

## Rechenporto

```text
SHA-256(
  "veilmesh/postage/v1"
  || epoch
  || item_id
  || nonce
)
```

Der Hash benötigt die von der Node veröffentlichte Anzahl führender Null-Bits.
Bei 80 % Speicherbelegung steigt die Schwierigkeit um ein Bit, bei 95 % um zwei.
Ein zusätzliches Bit verdoppelt ungefähr die Arbeit.

Schwierigkeit und Epochenlänge besitzen harte Obergrenzen. Der Client wählt die
Arbeit des Schreibquorums und lässt einen einzelnen höheren Ausreißer nicht die
PoW-Kosten aller Replikate bestimmen.

Das ist eine erste Spam-Bremse, keine alleinige Sybil-Abwehr. Produktiv sollten
anonyme blind signierte Portotickets die Arbeit über mehrere Nachrichten
amortisieren.

## Löschung

Der Client sendet nur `SHA-256(delete_token)` mit dem Item. Das zufällige Token
bleibt im Ende-zu-Ende-verschlüsselten Clientzustand. Eine Löschanfrage enthält
das Token; die Node vergleicht den Hash in konstanter Zeit.

`GET` beziehungsweise Fetch löscht niemals automatisch. Sonst könnte ein
Angreifer fremde Nachrichten allein durch Abrufen vernichten.

Eine Fetch-Anfrage enthält höchstens 256 eindeutige, kanonisch kodierte
Route-Capabilities. Antworten sind auf höchstens 512 Items und 8 MiB
Ciphertext-Nutzdaten begrenzt. Der Client erzwingt dieselben Grenzen zusätzlich
über die zusammengeführte Sicht aller Replikate. Dateien mit mehr Blöcken oder
Bytes werden in mehreren unabhängigen, begrenzten Fetches rekonstruiert; erst
die vollständig erfolgreiche Hash- und AEAD-Prüfung kann eine separate
Löschrunde auslösen.

## Speicherbelege

Ein Beleg enthält Node-ID, Item-ID, Payload-Hash, Speicherzeit und Ablaufzeit.
Er wird gleichzeitig mit Ed25519 und ML-DSA-65 signiert. Der Client zählt ihn nur,
wenn beide Signaturen gültig sind.

Der Client prüft zusätzlich, dass Payload-Hash und Ablaufzeit exakt zum
gesendeten Item passen, die Speicherzeit nicht nach der Ablaufzeit liegt und
Belegzeiten in einem engen Uhrtoleranzfenster liegen.

Der aktuelle Stichprobenbeweis ist für lokale Reparatur geeignet. Für
netzwerkweit beweisbaren Ausschluss muss v2 den Payload-Hash durch einen Merkle-
Root ersetzen und Merkle-Pfade im Proof liefern.

Eine Stichprobe bindet Nonce, Item-ID, Offset, angeforderte Länge,
Payload-Hash und Zeit. Die Node muss genau das vollständige angeforderte
Bytefenster liefern; ein verkürzter Präfix ist kein gültiger Speicherbeweis.

## Versionsregeln

- Unbekannte Felder und unbekannte Protokollversionen werden abgelehnt.
- Limits werden vor Datenbank- oder Kryptografiearbeit geprüft.
- Kryptografische Domänen sind protokoll- und zweckgebunden.
- Jede inkompatible Änderung erhöht die Protokollversion.
- Frontends sehen keine rohen Node-Protokollobjekte; sie verwenden den Core.
