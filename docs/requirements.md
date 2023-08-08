# BSI SYS.1.6
In supply Chain pruefbar = Zumindest TEILE sind pruefbar und zu beruecksichtigen. Heisst nicht, dass alle Anforderungen erfuellt sind!
In Anforderung zu Supply Chain steht immer nur ein EXTRAKT der eigentlichen Anforderung
|Nummer|Anforderung|Relevanz|Anforderung zu Supply-Chain|Hinreichend umgesetzt|
|---|---|---|---|---|
|SYS.1.6.A1|Planung des Container-Einsatzes|Nein|Keine Vorgaben fuer Supply Chain|
|SYS.1.6.A2|Planung der Verwaltung von Containern|Nein|Keine Vorgaben fuer Supply Chain|
|SYS.1.6.A3|Sicherer Einsatz containerisierter IT-Systeme|In Supply-Chain pruefbar|Im laufenden Betrieb SOLLTEN die Performance und der Zustand der containerisierten IT-Systeme überwacht werden (sogenannte Health Checks).|
|SYS.1.6.A4|Planung der Bereitstellung und Verteilung von Images|Ja|Der Prozess zur Bereitstellung und Verteilung von Images MUSS geplant und angemessen dokumentiert werden.|
|SYS.1.6.A5|Separierung der Administrations- und Zugangsnetze bei Containern|In Supply-Chain pruefbar|Es SOLLTEN nur die für den Betrieb notwendigen Kommunikationsbeziehungen erlaubt werden.|
|SYS.1.6.A6|Verwendung sicherer Images|Ja|Es MUSS sichergestellt sein, dass sämtliche verwendeten Images nur aus vertrauenswürdigen Quellen stammen. Der Ersteller der Images MUSS eindeutig identifizierbar sein. Die Quelle MUSS danach ausgewählt werden, dass der Ersteller des Images die enthaltene Software regelmäßig auf Sicherheitsprobleme prüft, diese behebt und dokumentiert sowie dies seinen Kunden zusichert. Die verwendete Version von Basis-Images DARF NICHT abgekündigt („deprecated") sein. Es MÜSSEN eindeutige Versionsnummern angegeben sein. Wenn ein Image mit einer neueren Versionsnummer verfügbar ist, MUSS im Rahmen des Patch- und Änderungsmanagement geprüft werden, ob und wie dieses ausgerollt werden kann.|
|SYS.1.6.A7|Persistenz von Protokollierungsdaten der Container|In Supply-Chain pruefbar|Die Speicherung der Protokollierungsdaten der Container MUSS außerhalb des Containers, mindestens auf dem Container-Host, erfolgen.|
|SYS.1.6.A8|Sichere Speicherung von Zugangsdaten bei Containern|In Supply-Chain pruefbar|Zugangsdaten MÜSSEN so gespeichert und verwaltet werden, dass nur berechtigte Personen und Container darauf zugreifen können. Insbesondere MUSS sichergestellt sein, dass Zugangsdaten nur an besonders geschützten Orten und nicht in den Images liegen. Die von der Verwaltungssoftware des Containerdienstes bereitgestellten Verwaltungsmechanismen für Zugangsdaten SOLLTEN eingesetzt werden. Mindestens die folgenden Zugangsdaten MÜSSEN sicher gespeichert werden: <br><br> * Passwörter jeglicher Accounts, <br> * API-Keys für von der Anwendung genutzte Dienste, <br> * Schlüssel für symmetrische Verschlüsselungen sowie <br> * private Schlüssel bei Public-Key-Authentisierung.|
|SYS.1.6.A9|Eignung für Container-Betrieb|Nein|Die Ergebnisse der Prüfung nach SYS.1.6.A3 Sicherer Einsatz containerisierter IT-Systeme SOLLTE nachvollziehbar dokumentiert werden.|
|SYS.1.6.A10|Richtlinie für Images und Container-Betrieb|Summe der Checks/Whitepaper Softwarelieferanten|Es SOLLTE eine Richtlinie erstellt und angewendet werden, die die Anforderungen an den Betrieb der Container und die erlaubten Images festlegt. Die Richtlinie SOLLTE auch Anforderungen an den Betrieb und die Bereitstellung der Images enthalten.|
|SYS.1.6.A11|Nur ein Dienst pro Container|In Supply Chain Pruefbar|Keine Vorgaben fuer Supply Chain|
|SYS.1.6.A12|Verteilung sicherer Images|Ja|Es SOLLTE angemessen dokumentiert werden, welche Quellen für Images als vertrauenswürdig klassifiziert wurden und warum. Zusätzlich SOLLTE der Prozess angemessen dokumentiert werden, wie Images bzw. die im Image enthaltenen Softwarebestandteile aus vertrauenswürdigen Quellen bezogen und schließlich für den produktiven Betrieb bereitgestellt werden. Die verwendeten Images SOLLTEN über Metadaten verfügen, die die Funktion und die Historie des Images nachvollziehbar machen. Digitale Signaturen SOLLTEN jedes Image gegen Veränderung absichern. |
|SYS.1.6.A13|Freigabe von Images|Ja|Alle Images für den produktiven Betrieb SOLLTEN wie Softwareprodukte einen Test- und Freigabeprozess gemäß des Bausteins OPS.1.1.6 Software-Test und Freigaben durchlaufen.|
|SYS.1.6.A14|Aktualisierung von Images|Ja|Bei der Erstellung des Konzeptes für das Patch- und Änderungsmanagement gemäß OPS.1.1.3 Patch- und Änderungsmanagement SOLLTE entschieden werden, wann und wie die Updates der Images oder der betriebenen Software bzw. des betriebenen Dienstes ausgerollt werden.|
|SYS.1.6.A15|Limitierung der Ressourcen pro Container|In Supply Chain Pruefbar|Für jeden Container SOLLTEN Ressourcen auf dem Host-System, wie CPU, flüchtiger und persistenter Speicher sowie Netzbandbreite, angemessen reserviert und limitiert werden.
|SYS.1.6.A16|Administrativer Fernzugriff auf Container|In Supply Chain Pruefbar|Applikations-Container SOLLTEN keine Fernwartungszugänge enthalten.|
|SYS.1.6.A17|Ausführung von Containern ohne Privilegien|In Supply Chain Pruefbar|Die Container-Runtime und alle instanziierten Container SOLLTEN nur von einem nicht-privilegierten System-Account ausgeführt werden, der keine erweiterten Rechte für den Container-Dienst bzw. das Betriebssystem des Host-Systems verfügt oder diese Rechte erlangen kann.|
|SYS.1.6.A18|Accounts der Anwendungsdienste|Nein|Keine Vorgaben fuer Supply Chain|
|SYS.1.6.A19|Einbinden von Datenspeichern in Container|In Supply Chain Pruefbar|Keine Vorgaben fuer Supply Chain|
|SYS.1.6.A20|Absicherung von Konfigurationsdaten|Ja|Die Beschreibung der Container-Konfigurationsdaten SOLLTE versioniert erfolgen. Änderungen SOLLTEN nachvollziehbar dokumentiert sein.|
|SYS.1.6.A21|Erweiterte Sicherheitsrichtlinien|Ja|Erweiterte Richtlinien SOLLTEN die Berechtigungen der Container einschränken. Mandatory Access Control (MAC) oder eine vergleichbare Technik SOLLTE diese Richtlinien erzwingen. Die Richtlinien SOLLTEN mindestens folgende Zugriffe einschränken: <br> * eingehende und ausgehende Netzverbindungen, <br> * Dateisystem-Zugriffe und <br> * Kernel-Anfragen (Syscalls). <br> Die Runtime SOLLTE die Container so starten, dass der Kernel des Host-Systems alle nicht von der Richtlinie erlaubten Aktivitäten der Container verhindert (z. B. durch die Einrichtung lokaler Paketfilter oder durch Entzug von Berechtigungen) oder zumindest Verstöße geeignet meldet.|
|SYS.1.6.A22|Vorsorge für Untersuchungen|Nein|Keine Vorgaben fuer Supply Chain|
|SYS.1.6.A23|Unveränderlichkeit der Container|In Supply Chain pruefbar|Dateisysteme SOLLTEN nicht mit Schreibrechten eingebunden sein.|
|SYS.1.6.A24|Hostbasierte Angriffserkennung|Nein|Keine Vorgaben fuer Supply Chain|
|SYS.1.6.A25|Hochverfügbarkeit von containerisierten Anwendungen|In Supply Chain Pruefbar|Bei hohen Verfügbarkeitsanforderungen der containerisierten Anwendungen SOLLTE entschieden werden, auf welcher Ebene die Verfügbarkeit realisiert werden soll (z. B. redundant auf der Ebene des Hosts).|
|SYS.1.6.A26|Weitergehende Isolation und Kapselung von Containern|In Supply Chain pruefbar|Wird eine weitergehende Isolation und Kapselung von Containern benötigt, dann SOLLTEN folgende Maßnahmen nach steigender Wirksamkeit geprüft werden: <br> * feste Zuordnung von Containern zu Container-Hosts, <br> * Ausführung der einzelnen Container und/oder des Container-Hosts mit Hypervisoren, <br> * feste Zuordnung eines einzelnen Containers zu einem einzelnen Container-Host.|

# APP.4.4
|Nummer|Anforderung|Relevanz|Anforderung zu Supply-Chain|Hinreichend umgesetzt|
|---|---|---|---|---|
|APP.4.4.A1|Planung der Separierung der Anwendungen (B)|Ja|Anwendungen SOLLTEN jeweils in einem eigenen Kubernetes-Namespace laufen, der alle Programme der Anwendung umfasst. Nur Anwendungen mit ähnlichem Schutzbedarf und ähnlichen möglichen Angriffsvektoren SOLLTEN einen Kubernetes-Cluster teilen.|
|APP.4.4.A2|Planung der Automatisierung mit CI-CD (B)|Ja|Wenn eine Automatisierung des Betriebs von Anwendungen in Kubernetes mithilfe von CI/CD stattfindet, DARF diese NUR nach einer geeigneten Planung erfolgen. Die Planung MUSS den gesamten Lebenszyklus von Inbetrieb- bis Außerbetriebnahme inklusive Entwicklung, Tests, Betrieb, Überwachung und Updates umfassen. Das Rollen- und Rechtekonzept sowie die Absicherung von Kubernetes Secrets MÜSSEN Teil der Planung sein.|Nein, wird nicht erfuellt, da nur Demo|
|APP.4.4.A3|Identitäts- und Berechtigungsmanagement bei Kubernetes (B)|Ja|Jeder Benutzer DARF NUR die unbedingt notwendigen Rechte erhalten.|
|APP.4.4.A4|Separierung von Pods (B)|In Supply Chain pruefbar|Der Betriebssystem-Kernel der Nodes MUSS über Isolationsmechanismen zur Beschränkung von Sichtbarkeit und Ressourcennutzung der Pods untereinander verfügen (vgl. Linux Namespaces und cgroups). Die Trennung MUSS dabei mindestens Prozess-IDs, Inter-Prozess-Kommunikation, Benutzer-IDs, Dateisystem und Netz inklusive Hostname umfassen.|
|APP.4.4.A5|Datensicherung im Cluster (B)|Nein|Keine Vorgaben fuer Supply Chain|
|APP.4.4.A6|Initialisierung von Pods (S)|Nein|Keine Vorgaben fuer Supply Chain|
|APP.4.4.A7|Separierung der Netze bei Kubernetes (S)| In Supply Chain pruefbar | Bei mehreren Anwendungen auf einem Kubernetes-Cluster SOLLTEN zunächst alle Netzverbindungen zwischen den Kubernetes-Namespaces untersagt und nur benötigte Netzverbindungen gestattet sein (Whitelisting).|
|APP.4.4.A8|Absicherung von Konfigurationsdateien bei Kubernetes (S)|Ja|Die Konfigurationsdateien des Kubernetes-Cluster, inklusive aller Erweiterungen und Anwendungen SOLLTEN versioniert und annotiert werden. Zugangsrechte auf die Verwaltungssoftware der Konfigurationsdateien SOLLTEN minimal vergeben werden. Zugriffsrechte für lesenden und schreibenden Zugriff auf die Konfigurationsdateien der Control Plane SOLLTEN besonders sorgfältig vergeben und eingeschränkt sein.|
|APP.4.4.A9|Nutzung von Kubernetes Service-Accounts (S)|In Supply Chain Pruefbar|Pods SOLLTEN NICHT den "default"-Service-Account nutzen. Dem "default"-Service-Account SOLLTEN keine Rechte eingeräumt werden. Pods für unterschiedliche Anwendungen SOLLTEN jeweils unter eigenen Service-Accounts laufen. Berechtigungen für die Service-Accounts der Pods der Anwendungen SOLLTEN auf die unbedingt notwendigen Rechte beschränkt werden. Pods, die keinen Service-Account benötigen, SOLLTEN diesen nicht einsehen können und keinen Zugriff auf entsprechende Token haben. Nur Pods der Control Plane und Pods, die diese unbedingt benötigen, SOLLTEN privilegierte Service-Accounts nutzen. Programme der Automatisierung SOLLTEN jeweils eigene Token erhalten, auch wenn sie aufgrund ähnlicher Aufgaben einen gemeinsamen Service-Account nutzen.|
|APP.4.4.A10|Absicherung von Prozessen der Automatisierung (S)|Ja|Alle Prozesse der Automatisierungssoftware, wie CI/CD und deren Pipelines, SOLLTEN nur mit unbedingt notwendigen Rechten arbeiten. Wenn unterschiedliche Benutzergruppen über die Automatisierungssoftware die Konfiguration verändern oder Pods starten können, SOLLTE dies für jede Gruppe durch eigene Prozesse durchgeführt werden, die nur die für die jeweilige Benutzergruppe notwendigen Rechte besitzen.|
|APP.4.4.A11|Überwachung der Container (S)|In Supply Chain Pruefbar|In Pods SOLLTE jeder Container einen Health Check für den Start und den Betrieb („readiness“ und „liveness“) definieren. Diese Checks SOLLTEN Auskunft über die Verfügbarkeit der im Pod ausgeführten Software geben. Die Checks SOLLTEN fehlschlagen, wenn die überwachte Software ihre Aufgaben nicht ordnungsgemäß wahrnehmen kann. Für jede dieser Kontrollen SOLLTE eine dem im Pod betriebenen Dienst angemessene Zeitspanne definieren. Auf Basis dieser Checks SOLLTE Kubernetes die Pods löschen oder neu starten.|
|APP.4.4.A12|Absicherung der Infrastruktur-Anwendungen (S)|Ja|Sofern eine eigene Registry für Images oder eine Software zur Automatisierung, zur Verwaltung des Festspeichers, zur Speicherung von Konfigurationsdateien oder ähnliches im Einsatz ist, SOLLTE deren Absicherung mindestens betrachten: <br> <br> Verwendung von personenbezogenen und Service-Accounts für den Zugang, <br> verschlüsselte Kommunikation auf allen Netzports, <br> minimale Vergabe der Berechtigungen an Benutzer und Service Accounts, <br> Protokollierung der Veränderungen und <br> regelmäßige Datensicherung.|
|APP.4.4.A13|Automatisierte Auditierung der Konfiguration (H)|teilweise|Es SOLLTE ein automatisches Audit der Einstellungen der Nodes, von Kubernetes und der Pods der Anwendungen gegen eine definierte Liste der erlaubten Einstellungen und gegen standardisierte Benchmarks erfolgen.|
|APP.4.4.A14|Verwendung dedizierter Nodes (H)|Ja|In einem Kubernetes-Cluster SOLLTEN die Nodes dedizierte Aufgaben zugewiesen bekommen und jeweils nur Pods betreiben, welche der jeweiligen Aufgabe zugeordnet sind.|nicht umgesetzt, weil Demo|
|APP.4.4.A15|Trennung von Anwendungen auf Node- und Cluster-Ebene (H)|Nein|Keine Vorgaben fuer Supply Chain|
|APP.4.4.A16|Verwendung von Operatoren (H)|Ja|Die Automatisierung von Betriebsaufgaben in Operatoren SOLLTE bei besonders kritischen Anwendungen und den Programmen der Control Plane zum Einsatz kommen.|
|APP.4.4.A17|Attestierung von Nodes (H)|Nein|Keine Vorgaben fuer Supply Chain|
|APP.4.4.A18|Verwendung von Mikro-Segmentierung (H)|In Supply Chain pruefbar|Die Pods SOLLTEN auch innerhalb eines Kubernetes-Namespace nur über die notwendigen Netzports miteinander kommunizieren können. Es SOLLTEN Regeln innerhalb des CNI existieren, die alle bis auf die für den Betrieb notwendigen Netzverbindungen innerhalb des Kubernetes-Namespace unterbinden. Diese Regeln SOLLTEN Quelle und Ziel der Verbindungen genau definieren und dafür mindestens eines der folgenden Kriterien nutzen: Service-Name, Metadaten („Labels"), die Kubernetes Service Accounts oder zertifikatsbasierte Authentifizierung.|
|APP.4.4.A19|Hochverfügbarkeit von Kubernetes (H)|Ja|Der Betrieb SOLLTE so aufgebaut sein, dass bei Ausfall eines Standortes die Cluster und damit die Anwendungen in den Pods entweder ohne Unterbrechung weiterlaufen oder in kurzer Zeit an einem anderen Standort neu anlaufen können. Für den Wiederanlauf SOLLTEN alle notwendigen Konfigurationsdateien, Images, Nutzdaten, Netzverbindungen und sonstige für den Betrieb benötigten Ressourcen inklusive der zum Betrieb nötigen Hardware bereits an diesem Standort verfügbar sein.Für den unterbrechungsfreien Betrieb des Clusters SOLLTEN die Control Plane von Kubernetes, die Infrastruktur-Anwendungen der Cluster sowie die Pods der Anwendungen anhand von Standort-Daten der Nodes über mehrere Brandabschnitte so verteilt werden, dass der Ausfall eines Brandabschnitts nicht zum Ausfall der Anwendung führt.|Nicht in Demo beruecksichtigt
|APP.4.4.A20|Verschlüsselte Datenhaltung bei Pods (H)|Nein| Keine Vorgaben fuer Supply Chain|
|APP.4.4.A21|Regelmäßiger Restart von Pods (H)|Nein|Keine Vorgaben fuer Supply Chain|

Organisatorisch (Teilweise Whitepaper IG BvC Softwarelieferanten):
- [ ] Prozess/Prueftabelle fuer neue Quellen (SYS.1.6.A6) (Regelmaessiger Re-Check, ggf. OldImage Check)
  - [ ] Die Quelle MUSS danach ausgewählt werden, dass der Ersteller des Images die enthaltene Software regelmäßig auf Sicherheitsprobleme prüft, diese behebt und dokumentiert sowie dies seinen Kunden zusichert
  - [ ] Die verwendete Version von Basis-Images DARF NICHT abgekündigt („deprecated") sein.
  - [ ] Es MÜSSEN eindeutige Versionsnummern angegeben sein.
- [ ] Prueftabelle fuer SYS.1.6.A3
  - [ ] Anforderung an Isolations und Kapselung wird erfuellt
  - [ ] Anforderung an Verfuegbarkeit ist erfuellt
  - [ ] Anforderung an Datendurchsatz ist erfuellt
- [ ] Prueftabelle fuer SYS.1.6.A9 (Eignung fuer Container Betrieb)
  - [ ] Software ist fuer Containereinsatz geeignet
  - [ ] Software kann unvorhergesehen beendet werden
- [ ] Pruefung fuer SYS.1.6.A11
  - [ ] Nur ein Dienst pro Container
- [ ] Pruefung fuer SYS.1.6.A25
  - [ ] Verfuegbarkeitserwartungen / Pod Affinity/Anti-Affinity


Image/Dockerfile-Kontrolle:
- [ ] Health-Checks (SYS.1.6.A3, APP.4.4.A11)
- [ ] Pruefung Base Image (SYS.1.6.A3)
- [ ] Image Label Pruefung nach Maintainer (SYS.1.6.A6) (Der Ersteller der Images MUSS eindeutig identifizierbar sein)
- [ ] Pruefung auf SemVer (aenderbar) (SYS.1.6.A6) (Es MÜSSEN eindeutige Versionsnummern angegeben sein)
- [ ] Secret existenz bspw. in ENV (SYS.1.6.A8)
- [ ] Nutzung von Multi-Processes (SYS.1.6.A11), systemd und Co
- [ ] Metadatenkontrolle (SYS.1.6.A12)
- [ ] Signaturcheck (sigstore/gpg/hashes) (SYS.1.6.A12)
- [ ] Keine Updatetools wie APT, DNF etc (SYS.1.6.A14)
- [ ] Keine Ports von bekannten Fernwartungstools im Container (22) (SYS.1.6.A16)
- [ ] Keine Fernwartungstools wie telnet, ssh, RDP, vnc im Container (SYS.1.6.A16)

Kubernetes Manifest Kontrolle
- [ ] Health-Checks (SYS.1.6.A3, APP.4.4.A11)
- [ ] Network-Policies (SYS.1.6.A5, APP.4.4.A4, APP.4.4.A7, APP.4.4.A18 )
- [ ] Secret existenz (SYS.1.6.A8)
- [ ] Limits/Requests (SYS.1.6.A15)
- [ ] Keine Ports von bekannten Fernwartungstools im Container (22) (SYS.1.6.A16)
- [ ] Existenz von entsprechenden Restriktions / SCCs / Geringen Capabilities (SYS.1.6.A17, APP.4.4.A4)
- [ ] keine Nutzung von lokalem Speicher (SYS.1.6.A19)
- [ ] Schreibrechte auf Filesysteme (SYS.1.6.A23)
- [ ] Pruefung auf Affinity/Anti-Affinity Definitionen (SYS.1.6.A25)
- [ ] Definition von Node-Labels (SYS.1.6.A26)
- [ ] Pruefung ob Zweck des Serviceaccounts angegeben ist (APP.4.4.A3)
- [ ] Nutzung des default Serviceaccount (APP.4.4.A9)
- [ ] Explizite definition eines Serviceaccounts (APP.4.4.A9)


Allg. Test:
- [ ] Logging nach stdout (SYS.1.6.A7)
- [ ] Regelmaessiges Beenden und Pruefen ob Anwendung sauber und Schnell hoch kommt (SYS.1.6.A9)
- [ ] Pruefung ob nur ein Dienst gestartet wird (SYS.1.6.A11)

Architektur:
- Grundsaetze
  - Moeglichst die Red Hat Tools benutzen (It's a Red Hat Demo), es aber swappable gestalten
  - auf einem Openshift Cluster bleiben
  - Einfachheit vor Anforderungserfuellung
  - Pluggability von eigenen Policies aufzeigen
  - Keine Umsetzung von Anforderungen/Pruefungen, die die RUNTIME betreffen
  - Kontrollen werden moeglichst frueh im Entwicklungsprozess angewendet (Shift Left)
  - Testumgebung ist auch Build Umgebung
  - Wo immer moeglich wird GitOps eingesetzt
  - Fuer Accounts werden minimale Rechte verwendet (APP.4.4.A3 / APP.4.4.A10)
  - Jede Applikation hat ein eigenes Git-Projekt, Accounts, Berechtigungen (APP.4.4.A10)
    - Die Git-Projekte trennung umgebungen nach Branches
  - Jeder Namespace greift mit eigenen Credentials auf die Registry zu (APP.4.4.A12)
  - Eigene Nodes fuer CI/CD (APP.4.4.A14) -- nicht umgesetzt
  - Alle Komponenten werden nach moeglichkeit als Operator bereitgestellt (APP.4.4.A16)
  - Checks werden modular implementiert, damit sie nach Bedarf genutzt oder auch nicht genutzt werden koennen
- [ ] Kubernetes Manifeste stehen in Git (SYS.1.6.A20)
- [ ] Trennung von Test und Produktivumgebung (Namespaces) OPS.1.1.6A13 / SYS.1.6.A14 / APP.4.4.A1
- [ ] Trennung von Anwendungen mittels Namespaces (APP.4.4.A1)
- [ ] Rollout nach Tests in Testumgebung automatisch in Produktionsumgebung (Entscheidung) zu SYS.1.6.A14 (Moeglichkeit WebHook nach Slack o.Ae.)
- [ ] Alle Konfigurationsdateien fuer die Pipeline/Supply Chain liegen in Git (APP.4.4.A8)
- Anlieferung im Push-Verfahren
  - gezeigt, aber wg. Shift Left nicht zwingend sinnvoll (ausser interne Entwicklung)
- Anlieferung im Pull-Verfahren
  - Durchfuehren der Checks



Pipeline Konfiguration
- [ ] Erlaubte Registries (Vertrauenswuerdige Quellen) (SYS.1.6.A6 / SYS.1.6.A12)
- [ ] Steps bei eigener Software
  1. Pre-Commit Tests
     1. Kube-Linter mit SYS/APP Tests (siehe Kubernetes Manifest Kontrolle)
     2. Secret Scanning
  2. Funktionale Tests (Dummy) (OPS.1.1.6.A2 u OPS.1.1.6.A3)
  3. Freigabe (manuell, rausnehmen) (OPS.1.1.6.A4)
  4. nicht-funktionale Tests (OPS.1.1.6.A5)
  5. Sicherheitstests (CVE Scanning) SOURCE!!
  6. Regressionstests (OPS.1.1.6.A12) - nicht einbauen
  7. Penetrationstests (OPS.1.16.A14) - nicht einbauen
- [ ] Steps in Test
  1. [ ] Baselining von Kernelcalls (SYS.1.6.A21)
  2. [ ] Baselining von Netzverbindungen (SYS.1.6.A21 / APP.4.4.A7 / SYS.1.6.A5, APP.4.4.A4,  APP.4.4.A18 )

Openshift Konfiguration
- [ ] Erlaubte Registries (Vertrauenswuerdige Quellen) (SYS.1.6.A6 / SYS.1.6.A12)
- [ ] Signaturkontrolle bei Registry (SYS.1.6.A12)


ACS Policy als Governance (?):
- [ ] Wenn ein Image mit einer neueren Versionsnummer verfügbar ist, MUSS im Rahmen des Patch- und Änderungsmanagement geprüft werden, ob und wie dieses ausgerollt werden kann. (SYS.1.6.A6) Image Age
- [ ] Signaturen (SYS.1.6.A12)
- [ ] Erlaubte Registries (Vertrauenswuerdige Quellen) (SYS.1.6.A6 / SYS.1.6.A12)
- [ ] SYSCall Baselining und Enforcing (SYS.1.6.A21)