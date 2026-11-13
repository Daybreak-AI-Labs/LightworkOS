<!-- Traduction maintenue par la communauté de docs/getting-started.md (commit source : b05c5ff) — la version anglaise fait foi. -->

# Premiers pas

Les sections de premier lancement et de suivi ont été mises à jour avec cette révision ; les autres sections peuvent être en retard sur l'anglais. [English](../../getting-started.md).

## Installation

Lightwork s'installe depuis les sources ; il faut Python 3.11–3.12 et Git. Suivez le [guide d'installation depuis les sources](../../source-install.md), qui donne les commandes pour macOS, Linux et Windows. Aucun binaire précompilé, paquet PyPI ou image de conteneur n'est encore publié. Aucune version n'est publiée pour l'instant ; installez depuis `main`.

Lancez ensuite `lightwork dashboard` et ouvrez <http://127.0.0.1:8765> pour terminer la configuration du propriétaire et du fournisseur de modèles.

## Premier lancement

Dans le tableau de bord, ouvrez **Start → Set up named sign-in** avant d'inviter une équipe. Le propriétaire local choisit une adresse comme identifiant et une phrase secrète ; cela ferme l'accès administrateur anonyme. L'adresse est une identité locale : la boîte mail n'est pas vérifiée. Gardez les liens d'invitation privés. Pour vous reconnecter sur cet ordinateur, utilisez `/auth/local-login`. Accordez les droits d'espace de travail et de département dans **Users**.

La création du premier propriétaire accepte uniquement les requêtes locales directes sur cet ordinateur, avant la configuration de rôles ou d'une connexion gérée. `[dashboard] local_owner_setup` vaut `true` par défaut ; `MAVERICK_LOCAL_OWNER_SETUP=0` la désactive. Les politiques de connexion et d'invitation existantes restent applicables.

L'assistant et ses vérifications sont aussi accessibles en ligne de commande :

```bash
lightwork init
lightwork preflight
lightwork doctor
```

L'assistant écrit `~/.maverick/config.toml` et `~/.maverick/.env`. Une nouvelle configuration personnelle propose une limite de 2 $ et 30 minutes par tâche ; vous pouvez choisir d'autres limites ou aucune. Modifiez ce choix dans **Settings → General → Spending per task**. Sans limite par tâche, les dépenses restent enregistrées et facturées par le fournisseur ; les plafonds de l'organisation restent applicables. Voir les [limites des tâches](../../task-limits.md).

Si aucun démon Docker actif n'a été trouvé, les modifications de fichiers et l'exécution de programmes sont désactivées : le moteur de repli `local` exécuterait des commandes directement sur cet ordinateur, sans isolation. Commencez par cette tâche :

```bash
lightwork start "Draft a one-page plan to reduce our customer support response time without adding headcount. State your assumptions and the facts you need from me."
```

## Regarder l'essaim décomposer l'objectif

Lancez `lightwork monitor` dans un second terminal. Voici un exemple de plan pour cette première tâche :

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

Pour modifier des fichiers ou exécuter des programmes ensuite, démarrez Docker ou Podman, choisissez le conteneur dans **Permissions → Where work runs**, puis confirmez **Allow file work**. Lightwork vérifie le conteneur et indique les autres politiques bloquantes ; `lightwork doctor` affiche la même limitation.

Une fois terminé :

```bash
maverick status      # what's currently active or blocked
maverick skills      # what the swarm distilled from this run
maverick facts       # what it learned about you
```

## Mettre en pause / reprendre

Si l'essaim a besoin d'une information que vous seul pouvez fournir, il se met en pause et place une question en file d'attente :

```bash
maverick status
# shows: open questions: #3 (goal 1): Which dates are you traveling?

maverick answer 3 "May 15-29"
maverick resume
```

Les objectifs survivent aux redémarrages. Vous pouvez fermer votre ordinateur portable et revenir demain.

## Annuler les modifications de fichiers d'une exécution

Avec le journal de l'espace de travail activé (`[workspace] journal = true`,
ou en répondant oui à l'étape *Workspace journal* de l'assistant), chaque
fichier que les agents écrasent ou créent via les outils de fichiers est
capturé avant la mutation :

```bash
maverick journal list --goal 12     # ce qui a été touché
maverick journal diff --goal 12     # état d'avant l'exécution vs le disque maintenant
maverick journal revert --goal 12   # restaure chaque fichier, du plus récent au plus ancien
```

La restauration écrit une ligne d'audit signée `workspace_revert` et archive
le journal. Les mutations faites par le shell (`rm`, `mv`, redirections) ne
sont pas journalisées — la piste d'audit enregistre ces commandes.

## Construire votre propre spécialiste à partir d'une tâche observée

Vous n'êtes pas obligé de décrire un travail avec des mots — vous pouvez le
montrer. Capturez un enregistrement ordonné de quelqu'un en train d'accomplir le
travail (les actions effectuées et toute explication du pourquoi) sous forme de
JSONL ou de simple texte préfixé, puis confiez le fichier à Lightwork :

```
ACTION[gmail]: send the morning digest -> ops@acme.com
NOTE: only the top 5 stories, with one-line summaries
SEE: digest looks right, ops confirmed receipt
```

```bash
maverick learn-demo demo.txt
```

Cela analyse la démonstration, induit un brouillon de spécialiste, vous montre le
workflow dérivé et attend votre approbation avant de l'enregistrer. Les secrets
sont expurgés dès l'entrée, et le brouillon hérite de la même limitation de
capacités et de la même analyse de persona qu'un pack décrit — rien ne s'active
sans votre accord. Options utiles :

```bash
maverick learn-demo demo.txt --name "Morning Digest" --no-llm --yes
```

`--no-llm` reproduit les étapes observées de manière déterministe (les outils =
ce que la personne a utilisé) ; omettez-le pour laisser le modèle faire des
propositions à partir de la transcription.

Le même flux d'usine à agents s'exécute lorsque vous construisez un pack de
manière conversationnelle :

```bash
maverick onboard
```

Une fois approuvé, `onboard` provisionne désormais le pack — il installe les
compétences du catalogue dont son workflow a besoin et synthétise tous les outils
déclarés qui ne sont pas intégrés, de sorte qu'un spécialiste fraîchement
approuvé est équipé pour faire son travail dès la première exécution. (Cette
étape respecte la configuration `[self_learning]` / `provision_packs` et n'élargit
jamais l'enveloppe verrouillée du pack.)

## Saisie vocale (intégrée, hors ligne)

Le bouton micro du tableau de bord et l'outil `transcribe_audio` fonctionnent
sans clé de fournisseur : le moteur Whisper local est livré avec le paquet du
tableau de bord, mais ouvrir l'application ne télécharge pas les fichiers du
modèle par défaut. Dans **Settings → Models**, sous la rubrique de dictée vocale,
un administrateur global peut examiner la source et la taille du modèle
configuré
(environ 148 Mo pour le modèle par défaut), puis le vérifier ou le télécharger.
La progression persiste après un rechargement de la page ; une annulation
supprime le téléchargement incomplet, et les échecs peuvent être réessayés
dans le même écran. Un fichier existant n'est déclaré vérifié que si sa taille
exacte et sa somme de contrôle correspondent. Cela ne prouve ni que le moteur
vocal est chargé, ni que le microphone fonctionne.

L'installateur demande explicitement si les téléchargements au démarrage sont
autorisés. Un réglage enregistré `[voice] auto_fetch_model = true` ou
`MAVERICK_VOICE_AUTO_FETCH=1` les active encore ; la politique réseau s'applique
aussi aux redirections. Les chemins de modèles personnalisés gérés et le
backend vocal cloud choisi conservent leur configuration. La CLI facultative reste disponible :

```bash
maverick voice setup    # télécharge le modèle vérifié par checksum (~148 Mo)
maverick voice status   # affiche les backends de reconnaissance vocale utilisables
maverick voice transcribe clip.wav   # test rapide du pipeline
```

Vous préférez un moteur système ? Un binaire `whisper.cpp` dans le PATH
(`brew install whisper-cpp`) ou faster-whisper s'insèrent dans la même
chaîne. Réglez `[voice] stt_backend = "local"` pour que l'audio ne quitte
jamais la machine, même avec des clés OpenAI/Groq configurées.

## Changer de modèles ou de fournisseurs

Après l'installation, ouvrez **Settings → Provider keys** ou
**Settings → Models** pour modifier ces choix. La page signale les valeurs
contrôlées par le déploiement ; un administrateur de l'installation doit
modifier cette source avant qu'une nouvelle valeur puisse prendre effet.
Consultez [`configuration.md`](../../configuration.md) pour les réglages sous-jacents.

## Où sont stockées les données

| Fichier | Contenu |
|---|---|
| `~/.maverick/config.toml` | Votre configuration (déploiement, modèles, sécurité, budget) |
| `~/.maverick/.env` | Clés d'API (chmod 600) |
| `~/.maverick/world.db` | Modèle du monde persistant : objectifs, faits, épisodes |
| `~/.maverick/skills/` | Fichiers SKILL.md distillés automatiquement à partir des exécutions réussies |
| `~/maverick-workspace/` | Répertoire de travail par défaut du bac à sable |
| `~/.maverick/learned-skills/` | Compétences distillées par les boucles d'apprentissage |
| `~/.maverick/dreams/` | Aperçus consolidés, file de répétition, instantanés d'apprentissage |

Lightwork stocke les fichiers ci-dessus dans votre déploiement. Si vous activez
des fournisseurs d'IA cloud ou des services connectés, le travail qui leur est
envoyé peut quitter ce déploiement. Vérifiez chaque fournisseur, connecteur et
politique de sortie avant de les utiliser.

Une fois que vous avez quelques exécutions derrière vous, la surface
d'apprentissage tient en quatre commandes : `maverick dream` (consolider
l'expérience), `maverick hindsight` (l'apprentissage a-t-il aidé ou régressé ?),
`maverick proof` (livrables, coûts évités, ROI) et `maverick domains-lint`
(auditer le catalogue de spécialistes), auxquelles s'ajoutent
`maverick domains-audit` (posture de gouvernance : ce que chaque agent peut
atteindre, refuse et rejette) et `maverick domains-eval --check` (cas de
référence comportementaux).
