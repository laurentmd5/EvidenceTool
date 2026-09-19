[English](PRODUCT_CONTRACT.md) | **Français**

# EvidenceTool — PRODUCT_CONTRACT.md (Contrat Produit & Invariants Architecturaux)

**Version :** 10.6 (Moteur Déterministe de Raisonnement Causal Opérationnel & Modèle d'Incident V1.0.6)  
**Statut :** Spécification active pour la Confiance Opérationnelle en Boucle Fermée V1.0.6 (Modes A, B, C) & Gouvernance de l'Incertitude Locale  
**Périmètre :** Ce document définit le contrat fonctionnel et architectural minimal et intangible que la base de code EvidenceTool doit respecter.

---

## 0. Principe Fondateur

> EvidenceTool n'automatise pas les actions en premier. Il rend d'abord les décisions opérationnelles explicables.

EvidenceTool sépare formellement **l'observation**, **la recommandation**, **l'autorisation**, et **l'exécution**. Il ne modifie jamais le système qu'il inspecte.

---

## 1. Périmètre V0.2 & V0.3

### 1.1 Frontière de Capacité d'Exécution

Les capacités d'exécution sont strictement disjointes de la politique diagnostique :
- La frontière de capacité détermine si un appelant a le droit de collecter une observation donnée.
- La politique diagnostique détermine de quelle manière les preuves collectées impactent une décision opérationnelle.
- Le provider réseau n'est pas bloqué globalement sur les cibles privées ou loopback : l'appelant peut autoriser explicitement ces cibles via une politique de capacité (`NetworkCapability`), en bornant les opérations, cibles, ports, budgets de sondes et timeouts. Tout refus de capacité est un échec d'intégrité et de sécurité, jamais un simple résultat réseau.

La découverte de provider et la confiance envers un provider sont séparées :
- Les providers intégrés sont estampillés `builtin` (confiance native).
- Les providers découverts dynamiquement sont considérés comme `experimental` tant qu'ils ne sont pas explicitement approuvés.
- Les appelants automatisés peuvent imposer `require_trusted: true`.
- Les plugins externes peuvent être activés via un manifeste déclarant leur namespace, module d'import et condensat SHA-256 (vérifié avant import).

**Définition :**
> Un outil d'observation opérationnelle et de décision en lecture seule permettant de diagnostiquer les incidents de production et d'évaluer si une remédiation proposée est suffisamment justifiée par les preuves disponibles.

**Flux d'Exécution :**
```
Incident
   ↓
Collecte d'observations (Providers en lecture seule)
   ↓
Évaluation des preuves (PASS / FAIL / UNKNOWN)
   ↓
Corrélation d'états (Situations & SituationEvaluation)
   ↓
Évaluation de politique (V2 Situationnelle)
   ↓
Production de décision (BLOCK / HUMAN_REVIEW / ALLOW)
   ↓
Validation d'intégrité de la décision (Invariants mathématiques)
```

---

## 2. Modèle de Preuve (Evidence Model)

Chaque observation produite par un provider respecte cette structure :

```json
{
  "id": "tls.certificate_valid",
  "source": "tls",
  "category": "certificate",
  "collector": "tls_provider",
  "method": "openssl x509 -in /etc/letsencrypt/live/example.com/fullchain.pem -noout -checkend 0",
  "value": {
    "status": "PASS"
  },
  "message": "Certificate is valid and not expired",
  "observed_at": "2026-08-12T08:30:00Z",
  "collected_at": "2026-08-12T08:30:01Z",
  "host": "prod-web-01"
}
```

| Champ | Type | Requis | Remarques |
|---|---|---|---|
| `id` | string | oui | Namespace pointé : `<source>.<category>.<check>` |
| `source` | string | oui | ex: `nginx`, `tls`, `systemd`, `filesystem`, `otel` |
| `category` | string | oui | Sous-groupe au sein de la source |
| `collector` | string | oui | Nom du provider / collecteur émetteur |
| `method` | string | oui | Commande ou API concrète utilisée (ex: `nginx -t`) |
| `value` | any | oui | Valeur brute observée |
| `message` | string | oui | Explication intelligible du fait observé |
| `observed_at` | timestamp ISO 8601 | oui | Horodatage où le fait sous-jacent était avéré |
| `collected_at` | timestamp ISO 8601 | oui | Horodatage où EvidenceTool a exécuté la collecte |
| `host` | string | non | Hôte cible si exécution distante sans agent (Agentless SSH) |

### 2.1 Fraîcheur des Preuves

La fraîcheur découle de `observed_at` par rapport à l'heure d'évaluation lorsqu'une politique définit `max_age` :
- `FRESH` : observé dans l'intervalle inférieur à `max_age`.
- `STALE` : observé il y a `max_age` secondes ou plus.

---

## 3. États des Preuves (Evidence States)

Trois états strictement exclusifs :
- **PASS** — la condition a été vérifiée et est satisfaite.
- **FAIL** — la condition a été vérifiée et n'est pas satisfaite.
- **UNKNOWN** — la preuve n'a pas pu être obtenue, vérifiée ou déterminée.

**Règle Explicite :**
> `UNKNOWN ≠ FAIL`. `UNKNOWN` est un état indépendant. Qu'il bloque ou non une décision dépend de la directive `on_unknown` de la politique ou de la résolution situationnelle, jamais d'une assimilation arbitraire.

---

## 4. Exigences de Preuve (Evidence Requirements)

Une politique déclare les éléments requis pour une action et leur comportement en cas de statut `UNKNOWN` :

```yaml
required_evidence:
  - id: nginx.config_valid
    on_unknown: BLOCK
  - id: tls.certificate_exists
    on_unknown: BLOCK
  - id: filesystem.disk_space_available
    on_unknown: IGNORE
```

| Statut de Preuve | Résultat de l'Exigence |
|---|---|
| `PASS` | Exigence satisfaite |
| `FAIL` | Exigence violée $\to$ contribue à `BLOCK` |
| `UNKNOWN`, `on_unknown: BLOCK` | Exigence violée $\to$ contribue à `BLOCK` |
| `UNKNOWN`, `on_unknown: IGNORE` | Non-bloquant ; consigné comme non-vérifiable dans la sortie |

Par défaut, l'omission de `on_unknown` équivaut à **`BLOCK`** (*fail-closed*).

---

## 5. Modèle de Décision

Trois décisions possibles :
- **ALLOW** — conditions requises satisfaites, aucun risque n'exigeant d'arbitrage humain.
- **BLOCK** — l'action ne doit pas être exécutée ni présentée comme autorisée.
- **HUMAN_REVIEW** — les preuves éclairent l'incident, mais l'action nécessite une validation humaine formelle.

### 5.1 Précédence de Décision

```
BLOCK  >  HUMAN_REVIEW  >  ALLOW
```

Si une preuve requise est bloquante ou si une situation bloquée est active, la décision est systématiquement `BLOCK`, sans égard pour le niveau de risque ou le flag `human_approval`.

---

## 6. Modèle de Risque

Quatre niveaux déclaratifs : `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.  
Le risque est déclaré par l'auteur de la politique, jamais inféré par une IA.

---

## 7. Contrat de Politique

Structure standard conforme au schéma V2 situationnel :
- `allow` : liste des situations autorisant l'action de remédiation.
- `blocked_by` : liste des situations bloquant formellement l'action.
- `required_evidence` : exigences explicites avec clauses `on_unknown`.
- `human_approval` : booléen imposant une revue humaine même si la situation est autorisée.

---

## 8. Contrat de Sortie JSON

Le format JSON constitue le contrat véritable. La sortie terminal n'en est qu'une projection de rendu.
Le JSON doit respecter `schemas/diagnosis-result.schema.json` et encapsuler :
`incident`, `evidence`, `policy`, `decision`, `recommendation`, `causality`, et `authority`.

---

## 9. Contrat CLI

Commandes standards :
- Mode lisible humain : `evidencetool diagnose <target>`
- Mode machine JSON : `evidencetool diagnose <target> --output json`
- Politiques et catalogues explicites via `--policy` et `--catalog`
- Exécution distante sans agent via `--host <hostname>`

Codes de retour :
- `0` : ALLOW
- `1` : BLOCK
- `2` : HUMAN_REVIEW
- `3` : INTEGRITY_VIOLATION

---

## 10. Limitations Connues

EvidenceTool s'interdit formellement de :
- modifier le système de quelque manière que ce soit ;
- déclencher automatiquement un redémarrage ou une remédiation ;
- muter l'état d'un cluster Kubernetes (inspection strictement en lecture seule) ;
- recourir à un LLM dans la boucle déterministe d'évaluation des preuves ou de décision ;
- exposer un serveur web ou un tableau de bord graphique intégré ;
- agréger les preuves en un score unique 0–100 sans valeur causale ;
- pratiquer une analyse de cause racine probabiliste ou spéculative.

---

## 11. Définition de Terminé (Definition of Done)

Le flux de diagnostic est réputé complet lorsqu'il s'exécute de bout en bout contre des incidents réels ou simulés de manière reproductible (certificat manquant/expiré, clé désynchronisée, syntaxe Nginx invalide, saturation disque, conflit de ports, saturation de pools DB).

---

## 12. Contrat SLI / SLO

Règle fondamentale : **RÉUSSITE DE L'EXÉCUTION ≠ SUCCÈS OPÉRATIONNEL DU SYSTÈME INSPECTÉ**.
Une exécution qui diagnostique correctement une panne et retourne `BLOCK` est une exécution réussie d'EvidenceTool.

- **SLI Fiabilité** : `evidencetool_last_run_success` (Gauge 1/0), `evidencetool_integrity_violation`.
- **SLI Performance** : Durée d'exécution totale et par provider.
- **SLO** : $\ge 99.5\%$ des diagnostics s'exécutent avec succès sur une fenêtre glissante de 30 jours.

---

## 13. Contrat d'Intégrité de la Décision

L'intégrité de la décision est une propriété mathématique invariante validée avant toute restitution :
1. Précédence : `BLOCK > HUMAN_REVIEW > ALLOW`.
2. Toute preuve requise en échec (`FAIL`) entraîne un `BLOCK`.
3. Tout état ambigu non résolu entraîne un `BLOCK` (*fail-closed*).
4. Toute situation active figurant dans `policy.blocked_by` entraîne un `BLOCK`.
5. Si `policy.human_approval` est actif et qu'aucun blocage n'existe, la décision est `HUMAN_REVIEW`.
6. En cas de violation d'intégrité, `metrics.success = False` et le code de sortie CLI devient `3`.

---

## 14. Contrat Situationnel V0.3 (Gelé)

Le modèle de corrélation par situations discrètes (`catalogs/*.yaml`) évalue les signatures multi-signaux, identifie les situations actives et calcule `ambiguous` en cas d'observations `UNKNOWN` critiques.

---

## 15. Environnement Docker & Compromis de Privilège (V0.4)

Accéder au socket `/var/run/docker.sock` équivaut en pratique aux privilèges `root` sur l'hôte.
Par conséquent :
- Le provider `docker` n'exécute que des sous-commandes de lecture : `inspect`, `logs`, `ps`.
- Il n'invoque JAMAIS `run`, `exec`, `stop`, `restart`, `kill` ou `rm`.

---

## 16. Expansion Observabilité (V0.5)

Introduction des providers `network` (ports, connectivité TCP, DNS), `process` (états noyau, zombies, CPU/RAM, descripteurs) et `filesystem` (espace et pression disque). Le moteur de décision reste strictement générique et indépendant de l'environnement d'exécution.

---

## 17. Dépendances Données & Applications (V0.6)

Introduction des sondes de données et de middleware :
- `postgres` : accessibilité TCP, saturation du pool de connexions, statut de réplica standby.
- `mysql` : handshake borné, détection de saturation de connexions (Erreur 1040), statut lecture seule.
- `redis` : client RESP natif borné, `PING/PONG`, détection de saturation mémoire (OOM) et rupture de réplication.
- `dependency` : vérification HTTP d'API amont, budget de latence SLA et détection de coupe-circuit.

---

## 18. Causalité de Premier Ordre, Provenance & Feuille de Route (V1.0)

Le diagnostic distingue la preuve de cause racine (`root_cause`), les preuves de support nominal (`supporting_evidence`), et le niveau de confiance déterministe (`confidence`).

---

## 19. Domaine de Diagnostic Kubernetes (V0.7+)

1. Exécution CLI `kubectl` sous forme de listes d'arguments sans shell.
2. Garantie de zéro mutation : requêtes `get`, `describe`.
3. Confinement strict par namespace avec interdiction sur les namespaces système (`kube-system`, etc.).
4. Distinction panne de transport (`UNKNOWN`) vs anomalie réelle de pod/nœud (`FAIL`).

---

## 20. Diagnostic Distribué & Corrélation Multi-Domaines (V0.8)

Évaluation conjointe des signaux réseau, applicatifs et base de données permettant de discriminer les pannes en cascade (ex: saturation pool DB provoquant des erreurs 500 et des dépassements de SLA amont).

---

## 21. Passerelle de Sécurité pour Agents IA & Modèle d'Autorité (V0.9)

Séparation stricte en 4 couches :
1. **Observation** : Faits bruts en lecture seule.
2. **Situation** : Corrélation sémantique d'état.
3. **Gouvernance** : Politique de décision d'action (`BLOCK > HUMAN_REVIEW > ALLOW`).
4. **Autorité** : Enveloppe de capacités (cibles autorisées, ports, quotas de sondes).

Tout dépassement de quota (`max_probes`) déclenche un arrêt immédiat avec refus d'intégrité (*fail-closed*).

---

## 22. Raisonnement Causal Déterministe (V1.0)

1. Les symptômes de surface ne sont jamais des causes racines.
2. Les dépendances saines réfutent les hypothèses concurrentes (`precluded_hypotheses`).
3. Les défaillances observées directement prévalent sur les dégradations indirectes de latence.
4. Les propagations causales sont 100% déclaratives (`causality/*.yaml`).

---

## 23. Correction Décisionnelle & Modèle d'Incertitude Locale (V1.0.2)

- L'ambiguïté est évaluée par situation (`SituationEvaluation`).
- Une observation `UNKNOWN` dans un domaine disjoint (ex: Redis) ne bloque pas une décision nominale vérifiée dans le domaine cible (ex: Nginx).
- Tout échec de provider ou refus de capacité produit des observations de repli `UNKNOWN` pour préserver le caractère explicite des preuves.

---

## 24. Tracing Outbound OpenTelemetry Mode B (V1.0.3)

1. **Indépendance de l'Observabilité** : Les traces décrivent le raisonnement opérationnel sans jamais influencer la décision.
2. **Non-Interférence Hôte** : Utilise le `TracerProvider` existant de l'hôte sans le réinitialiser.
3. **Non-Authentification** : Le W3C `traceparent` est purement un identifiant de corrélation, sans valeur d'autorisation.
4. **Sémantique de Statut de Span** : Un `BLOCK` ou `HUMAN_REVIEW` est une décision de gouvernance normale (`StatusCode.OK`). `StatusCode.ERROR` est réservé aux pannes d'exécution ou d'intégrité.
5. **Repli Zéro-Dépendance** : Fonctionne en Python standard pur sans exiger le SDK OTel externe.

---

## 25. Télémétrie Inbound OpenTelemetry Mode A (V1.0.4)

1. Ingestion externe non-intrusive depuis Prometheus et Tempo/Jaeger.
2. Le provider `otel` observe et normalise les valeurs brutes ; l'évaluateur de politique applique les seuils SLA.
3. Client HTTP sécurisé : interdiction stricte des redirections 3xx (protection anti-SSRF), blocage d'adresses de métadonnées cloud (`169.254.169.254`), charges utiles bornées à 1 Mo en streaming.
4. Indépendance de la disponibilité de la télémétrie : une coupure de Prometheus produit un statut `UNKNOWN` technique, jamais une fausse panne applicative (`UNKNOWN ≠ FAIL`).

---

## 26. Raisonnement Causal Hybride Mode C & Hardening Adversarial (Contrat V1.0.6)

1. **Zéro Causalité Implicite (C13)** : Deux défaillances observées simultanément sans règle déclarative formelle dans un catalogue causal ne portent strictement aucune relation causale. En l'absence de règle : `primary_root_cause = None`, `causal_chain = []` et `status = ROOT_CAUSE_UNKNOWN`.
2. **États Déterministes des Candidats** :
   - `CONFIRMED` : Signature ou preuve physique vérifiée, règle active, aucune préclusion active.
   - `POSSIBLE` : Plusieurs causes indépendantes confirmées sans hiérarchie déclarée ou en cas de cycle/égalité de priorité.
   - `UNRESOLVED` : Hypothèse explicative dont les preuves requises sont `UNKNOWN`.
3. **Isolation d'Incertitude de Sous-Graphe** : Une observation `UNKNOWN` n'affecte que les hypothèses directement dépendantes de cette preuve. Les sous-graphes disjoints conservent leur immunité complète.
4. **Arbitrage Déterministe Multi-Candidats (C9, C9b, C10)** :
   - Aucun tirage au sort ni heuristique probabiliste.
   - Sans priorité (C10) : `primary_root_cause = None`, `status = ROOT_CAUSE_CONSTRAINED`, tous les candidats confirmés conservés avec `state = POSSIBLE`.
   - Priorité explicite (C9) : La règle avec la plus haute valeur de métadonnée `priority: <int>` est désignée comme cause primaire (`ROOT_CAUSE_IDENTIFIED`).
   - Égalité stricte de priorité (C9b) : Si plusieurs causes racines partagent la même priorité maximale ($\text{priority}(A) == \text{priority}(B) == \max$), le moteur s'interdit d'utiliser l'ordre d'insertion des dictionnaires Python ou du fichier YAML. L'égalité est irrésolue $\to$ `status = ROOT_CAUSE_CONSTRAINED`, `primary_root_cause = None`, tous les candidats conservés avec `state = POSSIBLE`.
   - Résolution hiérarchique : Un chemin orienté multi-sauts ($C_1 \longrightarrow^* C_2$) désigne mathématiquement le candidat amont $C_1$ comme cause primaire par rapport aux nœuds intermédiaires.
5. **Relations Causales Formelles (C11, C12)** :
   - `PROPAGATES_TO` ($A \longrightarrow B$) : La cause $A$ engendre le symptôme $B$.
   - `PRECLUDES` ($A \mathrel{\rlap{\quad\not}\longrightarrow} B$) : La preuve $A$ réfute formellement l'hypothèse $B$.
   - `REQUIRES` ($A \xleftarrow{\text{req}} B$) : L'hypothèse $A$ requiert la vérification préalable de la précondition $B$ :
     - Si $B = \text{PASS}$ : $A$ peut être évalué et confirmé.
     - Si $B = \text{UNKNOWN}$ (C11) : $A$ devient `UNRESOLVED` avec `missing_evidence: [B]`, consigné dans `unresolved_hypotheses`.
     - Si $B = \text{FAIL}$ (C12) : Le prérequis indispensable ayant échoué, l'hypothèse $A$ est formellement réfutée $\to A$ devient **`PRECLUDED`**, consigné dans `precluded_hypotheses`.
6. **Schéma d'Explication Causale & Provenance** : Restitution complète dans le résultat de diagnostic (`status`, `primary_root_cause`, `causal_chain`, `propagated_symptoms`, `precluded_hypotheses`, `unresolved_hypotheses`, `candidate_causes`, `cycles_detected`).
7. **Validation Préalable du Graphe & Gestion des Cycles (C7)** :
   - *La validation du graphe causal DOIT précéder l'arbitrage causal*. `_arbitrate_candidates()` ne doit jamais présupposer un graphe acyclique.
   - Détection explicite des cycles avant l'élection d'une racine.
   - En cas de cycle causal ($A \longrightarrow B \longrightarrow A$), aucun nœud ne possède `in_degree == 0` au sein du cycle. Le moteur ne doit jamais lever d'exception sur un ensemble de racines vide : `primary_root_cause = None`, `status = ROOT_CAUSE_CONSTRAINED`, candidats préservés avec `state = POSSIBLE`, et cycles répertoriés dans `cycles_detected`.
   - Robustesse générale : Le moteur gère sans exception les graphes acycliques, cycliques, vides, déconnectés ou multi-composantes.
8. **Préservation Topologique des Chaînes Longues (C8)** :
   - Pour tout chemin multi-sauts ($A \longrightarrow B \longrightarrow C \longrightarrow D \longrightarrow S$) :
     - Intégrité : Aucun nœud intermédiaire n'est omis dans `causal_chain`.
     - Ordre topologique strict : La séquence ordonnée dans `causal_chain` respecte scrupuleusement les arêtes déclarées ($[A, B, C, D, S]$). Toute permutation arbitraire est proscrite.
