# Release-Reife

Stand: 22. Juli 2026

## Entscheidung

**NO-GO für einen allgemeinen Produktiv-Release als Messenger.**

Der Quellstand kann nach erfolgreichen Abschlussprüfungen als klar
gekennzeichnete Entwickler-/Security-Preview veröffentlicht werden. Er darf
nicht als metadatenanonymer, vollständig forward-secreter oder für Endnutzer
fertiger Messenger beworben werden. Diese Grenze ist technisch und
organisatorisch, nicht durch ein weiteres Versionslabel lösbar.

## Im Repository abgesicherte Release-Gates

- Der öffentliche Go-Modulpfad entspricht dem Repository.
- Die CI arbeitet mit minimalen Berechtigungen und auf vollständige Commit-SHAs
  gepinnten Actions. Sie prüft Formatierung, Moduldateien, `go vet`, Unit-/
  Integrationstests, Race-Tests, bekannte erreichbare Schwachstellen,
  Cross-Builds und reproduzierbare Node-Binaries.
- Produktive Client-Cores verlangen verschlüsselte Persistenz; ein flüchtiger
  Core ist nur über eine ausdrücklich als Entwicklung markierte API verfügbar.
- Lösch-Capability, vollständige Node-Identitäten und mögliche Store-Ziele werden
  vor dem ersten externen Schreibeffekt persistiert. Audit, Repair und Delete
  verwenden nach Neustart den erneut authentifizierten kanonischen Zustand.
- Produktive Node-Verbindungen sind identitätsgepinnt und nach der Erzeugung
  nicht durch exportierte Transportfelder veränderbar.
- Node-Start, Schlüssel-Erststart, Speicherlimits, persistente Lösch-Tombstones,
  Store↔Identitätsbindung, Lösch-Retry und Shutdown verhalten sich fail-closed
  und crashfest. Ein Prozess hält die Node-Identität exklusiv für seine gesamte
  Laufzeit.
- Geräte-Sync ist gerätesigniert, exakt an eine lokal gepinnte Profilrevision
  gebunden und verlangt atomaren persistenten Replay-Schutz.
- Parser-, Capability-, Signatur-, Autorisierungs- und Größenänderungen besitzen
  Negativtests.
- Ein kleines Netz kann ausdrücklich im nicht anonymen Direkt-Bootstrapmodus
  beginnen. Die automatische Full-Route wird nur bei validiertem Scheduler und
  sieben diversen Nodes gewählt; `RequireFullMix` verhindert stilles
  Downgrade. Diese Trennung ist getestet und dokumentiert.

## Zwingende externe und noch fehlende Gates

Vor einem Produktiv-Release für Endnutzer müssen mindestens alle folgenden
Punkte abgeschlossen und nachweisbar sein:

1. Ein unabhängig auditierter PQ-hybrider Ratchet-Provider mit Forward Secrecy,
   Post-Compromise Security, sicherer Key-Löschung und persistenter Replay-
   Transaktion.
2. Ein unabhängig auditierter ENIG-Mix-v2-Onion-/SURB-Provider sowie reale,
   organisatorisch und netztopologisch unabhängige Relay-, Courier-, Seed- und
   Verzeichnis-Infrastruktur. Direkte HTTPS-Verbindungen liefern keine
   Metadatenanonymität. Das einheitliche Full-Node-Binary muss alle Rollen
   tatsächlich ausführen und seine Konformität beweisen; die bereits
   implementierte sichere Routenzuweisung allein erfüllt dieses Gate nicht.
3. Ein auditierter RFC-9420-MLS-Provider für Gruppen. Jede Autorisierungsänderung
   muss atomar mit dem zugehörigen MLS Commit werden.
4. Produktive OS-/Hardware-Vault-Adapter für alle Zielplattformen. Datei- oder
   In-Memory-Vaults sind dafür nicht ausreichend.
5. Fertige, sicher getestete Endnutzer-Frontends und Plattformadapter für
   Android, iOS und Desktop einschließlich Upgrade-, Backup-, Restore-,
   Suspend-/Resume- und Barrierefreiheitstests. Der native macOS-Branch enthält
   bereits eine ausführbare, safety-locked SwiftUI-Oberfläche, aber noch keinen
   produktiven Core-Service-/FFI-Adapter, keine Vault-Integration und keine
   signierte/notarisierte Distributions-App.
6. Skalierbarer Node-Speicher, Migrationspfad, Kapazitätsplanung, Last-/Soak-
   Tests, Monitoring ohne sensible Metadaten sowie dokumentierte Notfall- und
   Wiederherstellungsverfahren. Der Referenzstore „eine JSON-Datei pro Item plus
   RAM-Index“ ist kein Millionen-Item-Backend. Ziel-Dateisysteme müssen ihre
   Rename-/Durability-Garantien erfüllen; Unix-Deployments müssen zusätzlich
   unerwartete erweiterte ACLs ausschließen.
7. Mindestens zwei unabhängige Protokoll-/Implementierungs-Audits sowie separate
   Infrastruktur-, Mobilplattform-, Metadaten- und Penetrationstests; alle
   kritischen und hohen Funde müssen geschlossen und nachgetestet sein.
8. Datenschutz-/Rechtsprüfung, Missbrauchs- und Incident-Response-Prozess,
   Support-/Update-Verantwortung und ein privater Meldekanal für
   Sicherheitslücken.
9. Signierte Release-Tags, Checksummen, SBOM, vollständige Drittanbieter-
   Lizenzhinweise, Build-Provenienz, signierte Artefakte und ein getesteter
   Rollback-/Widerrufsprozess.
10. Geschützte Hauptbranch-Regeln, verpflichtende CI und Review-Freigaben im
    Hosting-Repository. Die Workflow-Datei allein aktiviert diese externen
    Repository-Regeln nicht.

## Zulässige nächste Veröffentlichung

Bis diese Gates erfüllt sind, ist höchstens eine **Developer Preview / Testnet
Preview** zulässig. Sie muss den NO-GO-Status aus diesem Dokument und aus
`SECURITY.md` sichtbar verlinken, darf keine echten vertraulichen
Kommunikationsdaten empfehlen und darf keine Anonymitätsgarantie behaupten.
