<!-- Traduzione mantenuta dalla community di docs/getting-started.md (commit di origine: b05c5ff) — la versione inglese è quella di riferimento. -->

# Primi passi

Le sezioni sul primo avvio e sul monitor sono aggiornate a questa revisione; altre sezioni possono essere indietro rispetto all'inglese. [English](../../getting-started.md).

## Installazione

Lightwork si installa dai sorgenti; servono Python 3.11–3.12 e Git. Segui la [guida all'installazione dai sorgenti](../../source-install.md), che riporta i comandi per macOS, Linux e Windows. Non sono ancora pubblicati binari precompilati, pacchetti PyPI né immagini container. Al momento non è pubblicata alcuna release; installa da `main`.

Poi esegui `lightwork dashboard` e apri <http://127.0.0.1:8765> per completare la configurazione del proprietario e del fornitore di modelli.

## Primo avvio

Nella dashboard, apri **Start → Set up named sign-in** prima di invitare il team. Il proprietario locale sceglie un indirizzo email come identificativo e una passphrase; questo chiude l'accesso anonimo da amministratore. L'email è un'identità locale: la casella non viene verificata. Mantieni privati i link di invito. Per accedere di nuovo da questo computer, usa `/auth/local-login`. Assegna i permessi per workspace e reparti in **Users**.

La configurazione del primo proprietario accetta solo richieste locali dirette sul computer, prima di impostare ruoli o accesso gestito. `[dashboard] local_owner_setup` è `true` per impostazione predefinita; `MAVERICK_LOCAL_OWNER_SETUP=0` la disabilita. Le politiche esistenti su accessi e inviti restano valide.

La procedura guidata e le verifiche sono disponibili anche da terminale:

```bash
lightwork init
lightwork preflight
lightwork doctor
```

La procedura scrive `~/.maverick/config.toml` e `~/.maverick/.env`. Una nuova configurazione personale propone $2 e 30 minuti per attività; puoi scegliere altri limiti o nessuno. Puoi modificarli in **Settings → General → Spending per task**. Senza limiti per attività, i costi vengono comunque registrati e addebitati dal fornitore; restano validi i limiti dell'organizzazione. Vedi i [limiti delle attività](../../task-limits.md).

Se non è stato trovato un daemon Docker in esecuzione, le modifiche ai file e l'esecuzione di programmi sono disattivate: il backend di ripiego `local` eseguirebbe comandi direttamente su questo computer, senza isolamento. Inizia con questa attività:

```bash
lightwork start "Draft a one-page plan to reduce our customer support response time without adding headcount. State your assumptions and the facts you need from me."
```

## Osserva lo sciame scomporre l'obiettivo

Esegui `lightwork monitor` in un secondo terminale. Per la prima attività, il piano potrebbe apparire così:

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

Per modificare file o eseguire programmi in seguito, avvia Docker o Podman, scegli il container in **Permissions → Where work runs** e conferma **Allow file work**. Lightwork verifica il container e mostra eventuali altre politiche che bloccano l'azione; `lightwork doctor` mostra la stessa limitazione.

Al termine:

```bash
maverick status      # what's currently active or blocked
maverick skills      # what the swarm distilled from this run
maverick facts       # what it learned about you
```

## Mettere in pausa / riprendere

Se lo sciame ha bisogno di qualcosa a cui solo tu puoi rispondere, si mette in pausa e accoda una domanda:

```bash
maverick status
# shows: open questions: #3 (goal 1): Which dates are you traveling?

maverick answer 3 "May 15-29"
maverick resume
```

Gli obiettivi sopravvivono ai riavvii. Puoi chiudere il portatile e tornare domani.

## Annullare le modifiche ai file di un'esecuzione

Con il journal dello spazio di lavoro attivo (`[workspace] journal = true`, o
rispondendo sì al passaggio *Workspace journal* della procedura guidata),
ogni file che gli agenti sovrascrivono o creano tramite gli strumenti file
viene catturato prima della modifica:

```bash
maverick journal list --goal 12     # cosa è stato toccato
maverick journal diff --goal 12     # stato pre-esecuzione vs il disco adesso
maverick journal revert --goal 12   # ripristina ogni file, dal più recente
```

Il ripristino scrive una riga di audit firmata `workspace_revert` e archivia
il journal. Le modifiche fatte dalla shell (`rm`, `mv`, redirezioni) non
vengono registrate nel journal — la traccia di audit registra quei comandi.

## Costruire il tuo specialista da un'attività osservata

Non sei obbligato a descrivere un lavoro a parole: puoi mostrarlo. Cattura una
registrazione ordinata di qualcuno che svolge il lavoro (le azioni che ha
compiuto e qualsiasi spiegazione del perché) come JSONL o come semplice testo con
prefissi, poi consegna il file a Lightwork:

```
ACTION[gmail]: send the morning digest -> ops@acme.com
NOTE: only the top 5 stories, with one-line summaries
SEE: digest looks right, ops confirmed receipt
```

```bash
maverick learn-demo demo.txt
```

Questo analizza la dimostrazione, induce una bozza di specialista, ti mostra il
flusso di lavoro derivato e attende la tua approvazione prima di salvare. I
segreti vengono oscurati all'ingresso e la bozza eredita lo stesso vincolo sulle
capacità e la stessa scansione della persona di un pack descritto: nulla si
attiva senza il tuo consenso. Flag utili:

```bash
maverick learn-demo demo.txt --name "Morning Digest" --no-llm --yes
```

`--no-llm` rispecchia in modo deterministico i passaggi osservati (gli strumenti
= quelli usati dalla persona); ometti il flag per lasciare che il modello proponga
a partire dalla trascrizione.

Lo stesso flusso di agent-factory si avvia quando costruisci un pack in modo
conversazionale:

```bash
maverick onboard
```

Una volta approvato, `onboard` ora effettua il provisioning del pack: installa le
skill del catalogo di cui il suo flusso di lavoro ha bisogno e sintetizza
qualsiasi strumento dichiarato che non sia già integrato, in modo che uno
specialista appena approvato sia attrezzato per svolgere il proprio compito fin
dalla prima esecuzione. (Questo passaggio rispetta la configurazione
`[self_learning]` / `provision_packs` e non amplia mai l'envelope vincolato del
pack.)

## Input vocale (integrato, offline)

Il pulsante del microfono nella dashboard e lo strumento `transcribe_audio`
funzionano senza chiave del provider: il motore Whisper locale è incluso nel
pacchetto della dashboard, ma aprire l'app non scarica i file del modello per
impostazione predefinita. In **Settings → Models**, nella sezione della dettatura
vocale, un amministratore globale può esaminare origine e dimensione del modello
configurato (circa 148 MB per quello predefinito) e verificarlo o scaricarlo.
L'avanzamento rimane dopo il ricaricamento della pagina; l'annullamento
rimuove il download incompleto e gli errori possono essere ritentati nella
stessa schermata. I file esistenti sono verificati solo dopo il controllo
della dimensione esatta e del checksum. Ciò non dimostra che il motore vocale
sia caricato o che il microfono funzioni.

L'installer chiede esplicitamente se consentire download all'avvio. Una
configurazione salvata `[voice] auto_fetch_model = true` o
`MAVERICK_VOICE_AUTO_FETCH=1` li abilita ancora; la politica di rete vale
anche per i reindirizzamenti. I percorsi gestiti di modelli personalizzati e
il backend vocale cloud selezionato mantengono la loro configurazione. La CLI opzionale resta disponibile:

```bash
maverick voice setup    # scarica il modello verificato tramite checksum (~148 MB)
maverick voice status   # mostra quali backend speech-to-text sono utilizzabili
maverick voice transcribe clip.wav   # test rapido della pipeline
```

Preferisci un motore di sistema? Un binario `whisper.cpp` nel PATH
(`brew install whisper-cpp`) o faster-whisper si agganciano alla stessa
catena. Imposta `[voice] stt_backend = "local"` per tenere l'audio sulla
macchina anche quando sono configurate chiavi OpenAI/Groq.

## Cambiare modelli o provider

Dopo l'installazione, apri **Settings → Provider keys** o **Settings → Models**
per cambiare queste opzioni. La pagina indica i valori controllati dal
deployment; un amministratore dell'installazione deve modificare quella fonte
prima che il nuovo valore abbia effetto. Consulta [`configuration.md`](../../configuration.md)
per le impostazioni sottostanti.

## Dove si trovano i dati

| File | Contenuto |
|---|---|
| `~/.maverick/config.toml` | La tua configurazione (deployment, modelli, sicurezza, budget) |
| `~/.maverick/.env` | Chiavi API (chmod 600) |
| `~/.maverick/world.db` | Modello del mondo persistente: obiettivi, fatti, episodi |
| `~/.maverick/skills/` | File SKILL.md distillati automaticamente dalle esecuzioni riuscite |
| `~/maverick-workspace/` | Directory di lavoro predefinita della sandbox |
| `~/.maverick/learned-skills/` | Skill distillate dai cicli di apprendimento |
| `~/.maverick/dreams/` | Insight consolidati, coda di prove, snapshot dell'apprendimento |

Lightwork conserva i file sopra elencati nel tuo deployment. Se abiliti
provider AI cloud o servizi connessi, il lavoro inviato a questi servizi può
uscire dal deployment. Esamina ogni provider, connettore e politica di uscita
prima di usarli.

Una volta che avrai alle spalle alcune esecuzioni, la superficie di apprendimento
si riduce a quattro comandi: `maverick dream` (consolidare l'esperienza),
`maverick hindsight` (l'apprendimento ha aiutato o peggiorato?), `maverick proof`
(risultati prodotti, costo evitato, ROI) e `maverick domains-lint` (verifica del
catalogo di specialisti), oltre a `maverick domains-audit`
(postura di governance: cosa ogni agente può raggiungere, nega e rifiuta) e
`maverick domains-eval --check` (casi golden comportamentali).
