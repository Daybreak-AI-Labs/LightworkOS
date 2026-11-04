<!-- Traducción mantenida por la comunidad. Archivo de origen: docs/getting-started.md (commit a7b9cee) — la versión en inglés es la autorizada. -->

# Primeros pasos

<!-- See the authoritative English page for the latest installation status. -->

## Instalación

Lightwork se instala desde el código fuente; necesita Python 3.11–3.12 y Git. Siga la [guía de instalación desde el código fuente](../../source-install.md), que incluye los comandos para macOS, Linux y Windows. Todavía no se publican binarios precompilados, paquetes de PyPI ni imágenes de contenedor. Por ahora no hay ninguna versión publicada; instale desde `main`.

Después ejecute `lightwork dashboard` y abra <http://127.0.0.1:8765> para completar la configuración del propietario y del proveedor de modelos.

## Primera ejecución

```bash
maverick init
```

El asistente tarda unos 2 minutos. Escribe `~/.maverick/config.toml` y `~/.maverick/.env`.

Después:

```bash
maverick start "Build a CLI that emails me a digest of today's top Hacker News stories — research the API, write it, and verify it runs"
```

## Observa cómo el enjambre descompone el objetivo

Ejecuta `maverick monitor` en una segunda terminal. El orquestador planifica el objetivo y luego lanza subagentes especialistas que trabajan en paralelo: aquí un investigador determina la API, un programador escribe la herramienta y un verificador la ejecuta:

```
Goal #1 active  2m elapsed
Build a CLI that emails me a digest of today's top Hacker News stories

Plan tree
  ├─        done  #2 Research the Hacker News Firebase API
  ├─      active  #3 Write the digest CLI (fetch + format + send)
  ├─      active  #4 Verify it runs and emails a sample digest
  ├─     pending  #5 Write a short usage README

Latest episode #7 (running)  $0.0431  in=18,204 out=2,910 tools=11

Recent activity
  4s ago [researcher] decision: top stories live at /v0/topstories.json, then /v0/item/<id>.json
  3s ago [coder] tool_call: write_file hn_digest.py (118 lines)
  1s ago [verifier] tool_call: run "python hn_digest.py --dry-run" -> printed 10 stories

Cumulative spend on this DB: $0.21
```

Al terminar:

```bash
maverick status      # what's currently active or blocked
maverick skills      # what the swarm distilled from this run
maverick facts       # what it learned about you
```

## Pausar / reanudar

Si el enjambre necesita algo que solo tú puedes responder, se pausa y pone una pregunta en cola:

```bash
maverick status
# shows: open questions: #3 (goal 1): Which dates are you traveling?

maverick answer 3 "May 15-29"
maverick resume
```

Los objetivos sobreviven a los reinicios. Puedes cerrar el portátil y volver mañana.

## Deshacer las ediciones de archivos de una ejecución

Con el diario del espacio de trabajo activado (`[workspace] journal = true`,
o respondiendo sí en el paso *Workspace journal* del asistente), cada archivo
que los agentes sobrescriben o crean a través de las herramientas de archivos
se captura antes de la mutación:

```bash
maverick journal list --goal 12     # qué se tocó
maverick journal diff --goal 12     # estado previo vs el disco ahora
maverick journal revert --goal 12   # restaura cada archivo, el más reciente primero
```

Revertir escribe una fila de auditoría firmada `workspace_revert` y archiva
el diario. Las mutaciones hechas desde la shell (`rm`, `mv`, redirecciones)
no se registran en el diario — el rastro de auditoría registra esos comandos.

## Crea tu propio especialista a partir de una tarea observada

No tienes que describir un trabajo con palabras: puedes mostrarlo. Captura un
registro ordenado de alguien haciendo el trabajo (las acciones que realizó y
cualquier narración del porqué) como JSONL o texto simple con prefijos, y luego
entrega el archivo a Lightwork:

```
ACTION[gmail]: send the morning digest -> ops@acme.com
NOTE: only the top 5 stories, with one-line summaries
SEE: digest looks right, ops confirmed receipt
```

```bash
maverick learn-demo demo.txt
```

Esto analiza la demostración, induce un borrador de especialista, te muestra el
flujo de trabajo derivado y espera tu aprobación antes de guardarlo. Los secretos
se ocultan en la puerta, y el borrador hereda el mismo límite de capacidades y
análisis de persona que recibe un pack descrito: nada se activa sin tu sí.
Opciones útiles:

```bash
maverick learn-demo demo.txt --name "Morning Digest" --no-llm --yes
```

`--no-llm` reproduce de forma determinista los pasos observados (las herramientas
= las que usó la persona); omítelo para dejar que el modelo proponga a partir de
la transcripción.

El mismo flujo de fábrica de agentes se ejecuta cuando construyes un pack de
forma conversacional:

```bash
maverick onboard
```

Al aprobarlo, `onboard` ahora aprovisiona el pack: instala las skills del
catálogo que necesita su flujo de trabajo y sintetiza cualquier herramienta
declarada que no esté incorporada, de modo que un especialista recién aprobado
está equipado para hacer su trabajo desde la primera ejecución. (Este paso
respeta la configuración `[self_learning]` / `provision_packs` y nunca amplía el
sobre limitado del pack.)

## Entrada de voz (integrada, sin conexión)

El botón de micrófono del panel y la herramienta `transcribe_audio` funcionan
sin clave de proveedor: el motor Whisper local viene incluido con el paquete
del panel, pero abrir la aplicación no descarga el modelo por defecto. En
**Settings → Models**, en la sección de dictado por voz, un administrador
global puede revisar
el origen y el tamaño del modelo configurado (unos 148 MB para el predeterminado)
y comprobarlo o descargarlo. El progreso continúa tras recargar la página;
cancelar elimina la descarga incompleta y los errores se pueden reintentar en
la misma pantalla. Un archivo solo se marca como verificado cuando coinciden
su tamaño exacto y su checksum. Esto no demuestra que el motor de voz esté
cargado ni que el micrófono funcione.

El instalador pregunta si se permiten descargas al arrancar. Una configuración
guardada de `[voice] auto_fetch_model = true` o `MAVERICK_VOICE_AUTO_FETCH=1`
sigue habilitándolas; la política de red se aplica también a las redirecciones.
Las rutas de modelos personalizados gestionadas y el backend de voz en la nube
seleccionado conservan su configuración. La CLI opcional también está disponible:

```bash
maverick voice setup    # descarga el modelo verificado por checksum (~148 MB)
maverick voice status   # muestra qué backends de voz a texto están disponibles
maverick voice transcribe clip.wav   # prueba rápida del pipeline
```

¿Prefieres un motor del sistema? Un binario `whisper.cpp` en el PATH
(`brew install whisper-cpp`) o faster-whisper encajan en la misma cadena.
Define `[voice] stt_backend = "local"` para que el audio nunca salga de la
máquina aunque haya claves de OpenAI/Groq configuradas.

## Cambiar de modelos o proveedores

Después de instalar, abre **Settings → Provider keys** o **Settings → Models**
para cambiar estas opciones. La página indica qué valores controla el
despliegue; un administrador de la instalación debe cambiar esa fuente para
que el nuevo valor surta efecto. Consulta [`configuration.md`](../../configuration.md)
para conocer la configuración subyacente.

## Dónde se guardan los datos

| Archivo | Qué contiene |
|---|---|
| `~/.maverick/config.toml` | Tu configuración (despliegue, modelos, seguridad, presupuesto) |
| `~/.maverick/.env` | Claves de API (chmod 600) |
| `~/.maverick/world.db` | Modelo del mundo persistente: objetivos, hechos, episodios |
| `~/.maverick/skills/` | Archivos SKILL.md destilados automáticamente de las ejecuciones con éxito |
| `~/maverick-workspace/` | Directorio de trabajo por defecto del sandbox |
| `~/.maverick/learned-skills/` | Skills destiladas por los bucles de aprendizaje |
| `~/.maverick/dreams/` | Conocimientos consolidados, cola de ensayo, instantáneas de aprendizaje |

Lightwork guarda los archivos anteriores en tu despliegue. Si activas
proveedores de IA en la nube o servicios conectados, el trabajo enviado a
ellos puede salir de ese despliegue. Revisa cada proveedor, conector y política
de salida antes de usarlos.

Una vez que tengas unas cuantas ejecuciones a tus espaldas, la superficie de
aprendizaje son cuatro comandos: `maverick dream` (consolida la experiencia),
`maverick hindsight` (¿el aprendizaje ayudó o empeoró?), `maverick proof`
(entregables, costes evitados, ROI) y `maverick domains-lint` (audita el catálogo
de especialistas), además de `maverick domains-audit` (postura de
gobernanza: qué puede alcanzar cada agente, qué deniega y qué rechaza) y
`maverick domains-eval --check` (casos dorados de comportamiento).
