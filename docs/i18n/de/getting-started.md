<!-- Von der Community gepflegte Übersetzung von docs/getting-started.md (Quell-Commit: b05c5ff) — die englische Version ist maßgeblich. -->

# Erste Schritte

Die Abschnitte zum ersten Start und zum Monitor wurden anhand dieser Quellrevision aktualisiert; andere Abschnitte können hinter der englischen Fassung zurückliegen. [English](../../getting-started.md).

## Installation

Lightwork wird aus dem Quellcode installiert; Sie benötigen Python 3.11–3.12 und Git. Folgen Sie der [Anleitung zur Installation aus dem Quellcode](../../source-install.md), die die Befehle für macOS, Linux und Windows enthält. Vorgefertigte Binärdateien, PyPI-Pakete oder Container-Images werden noch nicht veröffentlicht. Derzeit ist keine Version veröffentlicht; installieren Sie von `main`.

Starten Sie anschließend `lightwork dashboard` und öffnen Sie <http://127.0.0.1:8765>, um die Einrichtung des Eigentümers und des Modellanbieters abzuschließen.

## Erster Start

Öffnen Sie im Dashboard **Start → Set up named sign-in**, bevor Sie ein Team einladen. Der lokale Eigentümer wählt eine E-Mail-Bezeichnung und eine Passphrase; damit endet der anonyme Administratorzugriff. Die E-Mail ist nur eine lokale Identitätsbezeichnung, das Postfach wird nicht verifiziert. Einladungslinks müssen privat bleiben. Zur erneuten Anmeldung auf diesem Computer dient `/auth/local-login`. Vergeben Sie Arbeitsbereichs- und Abteilungsrechte unter **Users**.

Die Ersteinrichtung des Eigentümers ist nur direkt auf dem lokalen Computer möglich, bevor Rollen oder eine verwaltete Anmeldung eingerichtet wurden. `[dashboard] local_owner_setup` ist standardmäßig `true`; `MAVERICK_LOCAL_OWNER_SETUP=0` deaktiviert sie. Bestehende Anmelde- und Einladungsrichtlinien gelten weiterhin.

Der Einrichtungsassistent und seine Prüfungen sind auch per Kommandozeile verfügbar:

```bash
lightwork init
lightwork preflight
lightwork doctor
```

Der Assistent schreibt `~/.maverick/config.toml` und `~/.maverick/.env`. Bei einer neuen privaten Einrichtung schlägt er $2 und 30 Minuten pro Aufgabe vor; Sie können andere oder keine Limits wählen. Unter **Settings → General → Spending per task** lässt sich das später ändern. Ohne Aufgabenlimit werden die Kosten weiterhin erfasst und vom Modellanbieter berechnet; ein Ausgabenlimit der Organisation gilt weiterhin. Siehe [Aufgabenlimits](../../task-limits.md).

Wenn kein laufender Docker-Daemon gefunden wurde, sind Dateiänderungen und Programmausführung ausgeschaltet: das Ausweich-Backend `local` würde Befehle ohne Isolation direkt auf diesem Computer ausführen. Beginnen Sie mit dieser Aufgabe:

```bash
lightwork start "Draft a one-page plan to reduce our customer support response time without adding headcount. State your assumptions and the facts you need from me."
```

## Dem Schwarm beim Zerlegen zusehen

Führen Sie `lightwork monitor` in einem zweiten Terminal aus. Für die erste Aufgabe könnte die Planung so aussehen:

```
Goal #1 active  2m elapsed
Draft a one-page support response plan

Plan tree
  ├─        done  #2 Identify likely response-time bottlenecks
  ├─      active  #3 Draft actions that do not require hiring
  └─     pending  #4 Check assumptions and questions for the owner

Latest episode #7 (running)  $0.0431  in=18,204 out=2,910 tools=11

Recent activity
  4s ago [researcher] decision: separate volume from process delays
  3s ago [writer] draft: owner-facing plan with assumptions
  1s ago [verifier] review: mark unsupported savings estimates

Cumulative spend on this DB: $0.21
```

Für Dateiänderungen oder Programme starten Sie später Docker oder Podman, wählen unter **Permissions → Where work runs** den Container und bestätigen **Allow file work**. Lightwork prüft den Container und zeigt weitere blockierende Richtlinien; `lightwork doctor` zeigt dieselbe Einschränkung.

Wenn alles fertig ist:

```bash
maverick status      # what's currently active or blocked
maverick skills      # what the swarm distilled from this run
maverick facts       # what it learned about you
```

## Pausieren / Fortsetzen

Braucht der Schwarm etwas, das nur Sie beantworten können, pausiert er und stellt eine Frage in die Warteschlange:

```bash
maverick status
# shows: open questions: #3 (goal 1): Which dates are you traveling?

maverick answer 3 "May 15-29"
maverick resume
```

Ziele überleben Neustarts. Sie können Ihren Laptop zuklappen und morgen weitermachen.

## Dateiänderungen eines Laufs rückgängig machen

Mit aktiviertem Workspace-Journal (`[workspace] journal = true`, oder mit Ja
im Assistenten-Schritt *Workspace journal*) wird jede Datei, die die Agenten
über die Datei-Tools überschreiben oder anlegen, vor der Änderung
festgehalten:

```bash
maverick journal list --goal 12     # was angefasst wurde
maverick journal diff --goal 12     # Zustand vor dem Lauf vs. Festplatte jetzt
maverick journal revert --goal 12   # stellt jede Datei wieder her, neueste zuerst
```

Ein Revert schreibt eine signierte `workspace_revert`-Auditzeile und
archiviert das Journal. Änderungen über die Shell (`rm`, `mv`, Umleitungen)
werden nicht journaliert — der Audit-Trail zeichnet diese Befehle auf.

## Aus einer beobachteten Aufgabe einen eigenen Spezialisten bauen

Sie müssen eine Aufgabe nicht in Worten beschreiben — Sie können sie auch
vorführen. Erfassen Sie eine geordnete Aufzeichnung davon, wie jemand die Arbeit
erledigt (die ausgeführten Aktionen und jede Erläuterung des Warum), als JSONL
oder als einfachen, mit Präfixen versehenen Text, und übergeben Sie die Datei
dann an Lightwork:

```
ACTION[gmail]: send the morning digest -> ops@acme.com
NOTE: only the top 5 stories, with one-line summaries
SEE: digest looks right, ops confirmed receipt
```

```bash
maverick learn-demo demo.txt
```

Dies parst die Vorführung, leitet daraus einen Entwurf für einen Spezialisten
ab, zeigt Ihnen den abgeleiteten Workflow und wartet auf Ihre Freigabe, bevor
gespeichert wird. Secrets werden direkt an der Tür unkenntlich gemacht, und der
Entwurf erbt dieselbe Capability-Begrenzung und denselben Persona-Scan wie ein
beschriebenes Pack — nichts wird ohne Ihr Ja aktiviert. Nützliche Flags:

```bash
maverick learn-demo demo.txt --name "Morning Digest" --no-llm --yes
```

`--no-llm` bildet die beobachteten Schritte deterministisch nach (Tools = das,
was die Person verwendet hat); lassen Sie es weg, damit das Modell aus dem
Transkript Vorschläge macht.

Derselbe Agent-Factory-Ablauf läuft, wenn Sie ein Pack im Dialog aufbauen:

```bash
maverick onboard
```

Nach der Freigabe stellt `onboard` das Pack nun bereit — es installiert die
Katalog-Skills, die sein Workflow benötigt, und synthetisiert alle deklarierten
Tools, die nicht von Haus aus vorhanden sind, sodass ein frisch freigegebener
Spezialist von der ersten Ausführung an für seine Aufgabe ausgerüstet ist.
(Dieser Schritt berücksichtigt die Konfiguration `[self_learning]` /
`provision_packs` und weitet die abgeklemmte Hülle des Packs niemals aus.)

## Spracheingabe (eingebaut, offline)

Der Mikrofon-Button im Dashboard und das Tool `transcribe_audio` funktionieren
ohne Provider-Schlüssel: Die lokale Whisper-Engine wird mit dem Dashboard-Paket
ausgeliefert, beim Öffnen der App werden Modelldateien aber standardmäßig nicht
heruntergeladen. Unter **Settings → Models** kann ein globaler Administrator
im Bereich für Sprachdiktat Quelle und Größe des konfigurierten Modells (beim
Standardmodell etwa 148 MB) prüfen und es kontrollieren oder herunterladen.
Der Fortschritt bleibt nach einem Neuladen der Seite erhalten; ein Abbruch
entfernt den unvollständigen Download, und Fehler lassen sich dort erneut
versuchen. Vorhandene Dateien gelten erst nach Prüfung von genauer Größe und
Prüfsumme als verifiziert. Das belegt weder, dass die Sprach-Engine geladen
ist, noch, dass das Mikrofon funktioniert.

Der Installer fragt ausdrücklich, ob Downloads beim Start erlaubt sind. Eine
gespeicherte Einstellung `[voice] auto_fetch_model = true` oder
`MAVERICK_VOICE_AUTO_FETCH=1` aktiviert sie weiterhin; die Netzwerkrichtlinie
gilt auch für Weiterleitungen. Verwaltete Pfade zu eigenen Modellen und ein
gewähltes Cloud-Sprachbackend bleiben erhalten. Die optionale CLI ist ebenfalls verfügbar:

```bash
maverick voice setup    # lädt das checksummen-geprüfte Modell (~148 MB)
maverick voice status   # zeigt, welche Speech-to-Text-Backends nutzbar sind
maverick voice transcribe clip.wav   # Schnelltest der Pipeline
```

Lieber eine System-Engine? Ein `whisper.cpp`-Binary im PATH
(`brew install whisper-cpp`) oder faster-whisper fügen sich in dieselbe
Kette ein. Mit `[voice] stt_backend = "local"` bleibt Audio auch dann auf der
Maschine, wenn OpenAI/Groq-Schlüssel konfiguriert sind.

## Modelle oder Provider wechseln

Öffnen Sie nach der Installation **Settings → Provider keys** oder
**Settings → Models**, um diese Werte zu ändern. Die Seite kennzeichnet Werte,
die vom Deployment vorgegeben werden; ein Installationsadministrator muss
diese Quelle ändern, bevor ein neuer Wert wirksam wird. Die zugrunde liegende
Konfiguration ist in [`configuration.md`](../../configuration.md) beschrieben.

## Wo die Daten liegen

| Datei | Inhalt |
|---|---|
| `~/.maverick/config.toml` | Ihre Konfiguration (Deployment, Modelle, Sicherheit, Budget) |
| `~/.maverick/.env` | API-Schlüssel (chmod 600) |
| `~/.maverick/world.db` | Persistentes Weltmodell: Ziele, Fakten, Episoden |
| `~/.maverick/skills/` | Automatisch destillierte SKILL.md-Dateien aus erfolgreichen Läufen |
| `~/maverick-workspace/` | Standard-Arbeitsverzeichnis der Sandbox |
| `~/.maverick/learned-skills/` | Von den Lernschleifen destillierte Skills |
| `~/.maverick/dreams/` | Konsolidierte Erkenntnisse, Probelauf-Warteschlange, Lern-Snapshots |

Lightwork speichert die oben genannten Dateien in Ihrem Deployment. Wenn Sie
Cloud-KI-Provider oder verbundene Dienste aktivieren, kann die an sie
gesendete Arbeit das Deployment verlassen. Prüfen Sie jeden Provider,
Connector und jede Egress-Richtlinie vor der Nutzung.

Sobald Sie ein paar Läufe hinter sich haben, besteht die Lernoberfläche aus vier
Befehlen: `maverick dream` (Erfahrung konsolidieren), `maverick hindsight` (hat
das Lernen geholfen oder zu einer Verschlechterung geführt?), `maverick proof`
(Ergebnisse, vermiedene Kosten, ROI) und `maverick domains-lint` (den Katalog
der Spezialisten-Agenten prüfen), dazu `maverick domains-audit`
(Governance-Lage: was jeder Agent erreichen, verweigern und ablehnen kann) und
`maverick domains-eval --check` (verhaltensbezogene Golden Cases).
