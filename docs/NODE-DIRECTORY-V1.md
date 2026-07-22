# IP-Node-Verzeichnis v1

## Ziel und Status

Das Verzeichnis verteilt die aktive IP-Liste eventual-consistent an alle Nodes
und Clients. Jeder Release beziehungsweise Betreiberverbund liefert dieselbe
kleine Standard-Seed-Liste aus. Ein Client muss zunächst nur diese gepinnten
Einträge kennen und kann anschließend den vollständigen aktiven Stand abrufen.

Der Code implementiert signierte Leases, Seed-Attestierungen, Rückruf-Challenges,
Snapshots, Reconciliation und Ablaufbereinigung. Konkrete öffentliche Seed-IPs,
Schlüssel sind Deploymentdaten und wurden mangels realer
Betreiber absichtlich nicht erfunden. Das Verzeichnis ist keine Anonymitätsschicht
und noch keine permissionless Sybil-Abwehr.

Das Zielnetz besitzt nur einen Node-Softwaretyp: Jeder gültige Record soll eine
Full Node beschreiben, die Mix-, Courier-, Speicher-, Directory- und
Bootstrap-Aufgaben ausführen kann. Rollen sind daher keine selbstdeklarierte
Eigenschaft im Record, sondern eine kurzlebige Zuweisung des Clients pro Route.
Der aktuelle v1-Rückruf beweist Erreichbarkeit und Identitätsbesitz, aber noch
nicht die Konformität aller fehlenden Full-Node-Dienste. Bis ein standardisierter
Conformance-Probe-Pfad vorhanden ist, darf die Aufnahme nicht als solcher Beweis
beworben werden.

## Vertrauensanker

Ein `PinnedNode` enthält:

- die vollständige hybride Ed25519-/ML-DSA-65-Identität einschließlich Node-ID,
- genau einen kanonischen Endpoint aus Schema, literalem IPv4-/IPv6-Wert und
  Port.

Diese Liste wird lokal mit Client und Node ausgeliefert. Sie darf nicht aus
einer beliebigen Netzwerkantwort überschrieben werden. Neue Seeds oder neue
Seed-IP-Adressen benötigen ein sicherheitskritisches, signiertes Software-/
Konfigurationsupdate. Produktion sollte mindestens fünf organisatorisch und
netztopologisch unabhängige Seeds und ein 3-von-5-Quorum verwenden.

`https` und eine öffentlich routbare IP sind produktiv verpflichtend. Eine Node
erzeugt ihren selbstsignierten TLS-Zertifikatscontainer automatisch aus dem
Ed25519-Anteil ihrer persistenten hybriden Identität. Gegenstellen vertrauen
weder CA noch Hostname oder SAN, sondern pinnen exakt diesen Schlüssel aus dem
lokal ausgelieferten Seed beziehungsweise dem verifizierten Directory-Record.
TLS 1.3 und `X25519MLKEM768` sind zwingend; ein Downgrade oder anderer
Schlüsselaustausch wird abgewiesen. Der kurzlebigere X.509-Container wird vor
Ablauf automatisch mit demselben gepinnten Node-Schlüssel erneuert. `http`,
Loopback und private Netze werden nur
mit dem expliziten Entwicklungsschalter akzeptiert. DNS-Namen, URL-Userinfo,
Redirects, Ports 0, Multicast-, Link-Local- und unspezifizierte Adressen sind
nicht Teil des Verzeichnisprotokolls.

## Aufnahme einer neuen Node

1. Die Node erzeugt beziehungsweise lädt ihre persistente hybride
   Node-Identität.
2. Sie signiert eine Lease über Identität, IP-Endpunkt, monotone Sequenz,
   Ausgabezeit und Ablaufzeit.
3. Sie sendet die Lease nacheinander direkt an die gepinnten Seeds.
4. Ein Seed akzeptiert den Request nur, wenn die TCP-Quell-IP exakt der
   veröffentlichten IP entspricht. Proxy-Header werden ignoriert.
5. Der Seed sendet eine zufällige 32-Byte-Challenge ausschließlich an dieselbe
   IP und den veröffentlichten Port. Redirects sind verboten.
6. Die Node signiert Nonce, Node-ID und Zeit. Der Seed prüft beide Signaturen und
   attestiert danach den Hash der vollständigen Lease einschließlich ihrer
   Node-Signatur.
7. Die Node sammelt unterschiedliche Attestierungen. Erst das lokal konfigurierte
   Seed-Quorum macht den Record aktiv. Beim nächsten Abgleich erhalten auch die
   bereits besuchten Seeds den vollständigen Quorum-Record.

Registrierung, Rückruf und Snapshot-Abruf laufen jeweils über den auf die
angekündigte vollständige Identität gepinnten Kanal. Der selbstsignierte
Zertifikatscontainer ist kein zusätzlicher Vertrauensanker und benötigt keine
öffentliche PKI. Directory-Signaturen bleiben hybrid; die TLS-
`CertificateVerify`-Signatur ist derzeit Ed25519, während der TLS-
Schlüsselaustausch X25519 und ML-KEM-768 kombiniert.

Die Rückruf-Challenge verhindert, dass ein beliebiger Absender fremde Internet-
IPs als Node einträgt. Sie beweist nicht, dass zwei Nodes hinter derselben NAT
verschiedene Betreiber sind. Rückrufe sind auf dieselbe Quellen-IP, einen festen
Pfad, einen Request, kurze Zeit, feste Antwortgröße, keine Redirects und eine
begrenzte Parallelität beschränkt. Damit wird die Registrierung nicht zu einem
allgemeinen SSRF- oder Portscan-Proxy.

## Lease und Offline-Entfernung

Eine Lease gilt mindestens 10 Minuten und höchstens 2 Stunden. Die Referenznode
verwendet 1 Stunde und erneuert nach ungefähr der halben Laufzeit. Eine höhere
Sequenz ersetzt den bisherigen Record; niedrigere Sequenzen und Konflikte bei
derselben Sequenz werden abgewiesen.

Nodes entfernen abgelaufene Records lokal. Ausfall, Paketverlust oder eine
einzelne fehlgeschlagene Probe erzeugen ausdrücklich keinen signierten
Fehlverhaltensbeweis. Deshalb kann eine offline gegangene Node bis zum Ablauf
ihrer letzten Lease sichtbar bleiben. Unterschiedliche Listen während der
Propagation sind normal; „alle Nodes“ bedeutet alle derzeit gültig aufgenommenen
Records in der zusammengeführten Sicht, nicht mathematisch beweisbare globale
Vollständigkeit.

## Verteilung an Nodes und Clients

`GET /v1/nodes` liefert einen Snapshot mit Publisheridentität,
Erstellungszeitpunkt, eindeutig nach Node-ID sortierten Records und hybrider
Publisher-Signatur. Jeder Record wird zusätzlich vollständig selbst- und
quorumverifiziert. Die Grenzen sind:

- höchstens 512 aktive Records,
- höchstens 16 Attestierungen je Record,
- höchstens 16 MiB Snapshot-Encoding,
- höchstens 256 KiB Registrierung,
- höchstens 5 Minuten Uhrabweichung.

Nodes ziehen regelmäßig die Snapshots aller gepinnten Seeds, vereinigen gültige
Records und entfernen abgelaufene Leases. Dadurch erreicht eine neue Node nach
spätestens einigen Synchronisationsintervallen alle ehrlichen Nodes. Clients
verwenden `client.FetchNodeDirectory`, verlangen eine konfigurierte Mindestzahl
erfolgreicher Seed-Sichten und bilden deren verifizierte Union. Die vollständige
Liste kann lokal gehalten werden; `client.ConnectDirectoryRecords` begrenzt die
gleichzeitig kontaktierten Speicher-Nodes separat auf 64 und akzeptiert
produktiv ausschließlich öffentlich routbares `https`. Die getrennte API
`client.ConnectDirectoryRecordsForDevelopment` erlaubt private/Loopback-
Endpunkte nur nach ausdrücklichem Entwicklungs-Opt-in; der Produktionspfad
downgradet niemals anhand einer privaten Directory-Policy auf `http`.

Snapshots enthalten ausschließlich öffentliche Node-Identitäten und
IP-Endpunkte. Kontakte, Account-/Geräte-IDs, Route-Tags, Capabilities, Payloads
und Fetch-Listen sind verboten und werden von diesem Datentyp nicht dargestellt.
Für ENIG-Mix-Routen prüft `mixtransport.SelectFullRoute` jeden Record erneut und
weist sieben unterschiedliche Identitäten aus sieben unterschiedlichen groben
IP-Präfixen drei Mix-, einer Courier- und drei Replikataufgaben zu. Das Directory
veröffentlicht dabei weiterhin keine dauerhafte Rolle.

## Nicht gelöste Angriffe

- Ein kolludierendes Seed-Quorum kann Sybils zulassen.
- Seeds können gültige Nodes aus ihren Antworten auslassen; die Union mehrerer
  Sichten reduziert, beweist aber keine Vollständigkeit.
- Eine dominierte Standard-Seed-Liste ermöglicht Eclipse-Angriffe.
- IP-Adressen beweisen weder Betreiber- noch Netzdiversität.
- Direkte Registrierung und Abfrage zeigen Seeds Client-/Node-IP und Timing.
- DDoS, Partitionen und Clock-Fehlkonfiguration bleiben Verfügbarkeitsrisiken.
- Es fehlen transparente Checkpoint-Logs, Gossip-Split-Erkennung, Probezeit,
  Ressourcennachweis und ein globales Limit neuer Betreiber.

Keine dieser Grenzen darf als „gegen alle Angriffe immun“ dokumentiert werden.
