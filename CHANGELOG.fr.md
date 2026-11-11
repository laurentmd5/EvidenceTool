[English](CHANGELOG.md) | **Français**

# Journal des Modifications (Changelog)

Tous les changements notables apportés à ce projet sont documentés dans ce fichier.

## [1.0.7] - 2026-09-19
### Durcissement de Production du Mode A & du Mode B
- **Mode A (Télémétrie Inbound) Application des Budgets & Défenses (`A1`, `A2`)** :
  - **Application Exhaustive de TelemetryBudget (`A1`)** : Application effective de toutes les dimensions du budget au runtime : délai d'expiration socket (`read_timeout`), découpage des vecteurs Prometheus (`max_result_items`), limitation des traces distribuées requêtées (`max_traces`), et bornage de l'itération CPU des spans par trace (`max_spans_per_trace`).
  - **Plafonds Inviolables Anti-Contournement (`A1`)** : Introduction des constantes immuables `HARD_BUDGET_CEILINGS` et du constructeur `build_clamped_telemetry_budget`, bridant strictement les paramètres issus de `ProviderContext` contre tout déni de service ou tentative de contournement de quota.
  - **Spécification Déterministe du Lookback (`A2`)** : Implémentation de `_parse_lookback` :
    - Lookback valide $\le$ budget : préservé à l'identique.
    - Lookback valide $>$ budget : bridé à `max_lookback_seconds` avec métadonnées de transparence et d'audit (`requested_lookback`, `effective_lookback`, `lookback_clamped: true`).
    - Syntaxe invalide : évaluée fail-closed en `Observation(status="UNKNOWN")` (`transport_status="failed"`), éliminant tout repli silencieux vers 5m.
  - **Bornage des Flux Pré-Désérialisation (`A2`)** : Lecture bornée des octets bruts avant l'appel à `json.loads` pour protéger la mémoire et le CPU.
- **Mode B (Tracing Outbound) Résilience & Identité Canonique des Spans (`B1`, `B2`)** :
  - **Export Asynchrone par Lots (`B1`)** : Remplacement de `SimpleSpanProcessor` par `BatchSpanProcessor` (`max_queue_size=512`) en mode autonome. La clôture d'une span (`end_span()`) s'effectue en mémoire sans blocage synchrone sur les allers-retours réseau du collecteur.
  - **Double Budgets Temporels Bornés (`B1`)** :
    - `OTLP_EXPORT_TIMEOUT_SECONDS = 2.0` : Délai d'expiration strict pour la connexion et requête HTTP de l'export OTLP.
    - `OTLP_FLUSH_TIMEOUT_MILLIS = 2000` : Délai maximal de vidage lors de `tracer.finish()`.
    - Délai d'expiration du fallback pur Python harmonisé à 2,0s.
  - **Invariant Défaillance d'Export $\neq$ Défaillance de Diagnostic (`B1`)** : Tout code HTTP 500, coupure réseau ou exception d'expiration émis par le collecteur est consigné comme avertissement d'observabilité sans jamais faire échouer ni corrompre le diagnostic.
  - **Identité Canonique des Spans (`B2`)** : Suivi des spans réarchitecturé autour du `span_id` unique comme clé primaire (`_active_spans_by_id`, `_active_otel_spans_by_id`). Les orchestrateurs internes (`diagnose.py`) manipulent directement les descripteurs `SpanRecord`, évitant toute collision ou écrasement en cas de noms identiques concurrents ou successifs. Une pile LIFO secondaire préserve la rétrocompatibilité pour les recherches par nom textuel.
- **Portes de Qualité & Parité Bilingue Étendues** :
  - Ajout de tests unitaires dédiés pour A1, A2, B1 et B2. Suite complète portée de 296 à **307 tests réussis à 100 %**.
  - Parité documentaire bilingue intégrale (100 %) en français et en anglais.

## [1.0.6] - 2026-09-18
### Durcissement Causal du Mode C (Raisonnement Causal Hybride & Adversaire)
- **Validation du Graphe & Détection de Cycles Préalable à l'Arbitrage (`C7`)** :
  - Implémentation de `_detect_cycles()` réalisant la recherche déterministe de cycles avant l'arbitrage des candidats racines.
  - Application stricte de l'invariant : *La validation du graphe causal DOIT précéder l'arbitrage causal*.
  - Correction du crash `ValueError` dans `_arbitrate_candidates` lorsque tous les nœuds confirmés forment un cycle dirigé ($A \longrightarrow B \longrightarrow A$).
  - En présence d'un cycle, le moteur évite tout plantage, positionne `primary_root_cause = None`, conserve les candidats en `state = POSSIBLE` et renseigne les chemins de cycles dans `cycles_detected`.
- **Préservation et Ordre Strict de la Chaîne Topologique (`C8`)** :
  - Ordre strict et déterministe garanti dans `_find_causal_path` et `_build_causal_chain` via le tri des nœuds adjacents.
  - Les chaînes multi-sauts longues ($A \longrightarrow B \longrightarrow C \longrightarrow D \longrightarrow S$) conservent tous les nœuds intermédiaires dans l'ordre topologique strict ($[A, B, C, D, S]$).
- **Désambiguïsation par Priorité & Invariant d'Égalité de Priorité (`C9`, `C9b`)** :
  - Priorité entière explicite (`priority: <int>`) élisant de manière déterministe le candidat racine de plus haute priorité.
  - Ajout de l'invariant d'égalité de priorité (Priority Tie) : si plusieurs racines partagent la même priorité maximale, aucun départage arbitraire (ordre d'insertion ou dictionnaire) n'est toléré $\to$ repli sur `ROOT_CAUSE_CONSTRAINED` et conservation des candidats en `POSSIBLE`.
- **Sémantique des Prérequis Indispensables (`C11`, `C12`)** :
  - Formalisation du comportement tripartite de `REQUIRES` :
    - $B = \text{PASS} \implies A$ peut être évalué normalement.
    - $B = \text{UNKNOWN} \implies A$ bascule en `UNRESOLVED` (enregistré dans `unresolved_hypotheses` avec `missing_evidence: [B]`).
- **Atteignabilité du Sous-Graphe Causal & Isolation des Symptômes (`C14`, `C19` / `H1`)** :
  - Élimination de la boucle résiduelle ajoutant les symptômes non visités ou inatteignables à `causal_chain`.
  - Application stricte de l'invariant d'atteignabilité : tout nœud dans `causal_chain` et `propagated_symptoms` doit appartenir au sous-graphe orienté atteignable de la cause racine primaire.
  - Les symptômes disjoints ($S_2$) issus de composants distincts ou non confirmés ($B \longrightarrow S_2$) sont strictement isolés et ne polluent jamais l'explication de la racine $A$.
- **Sémantique de Chemin Causal Continu & Graphe Ramifié (`C15` / `H2`)** :
  - Formalisation de `causal_chain` comme un chemin orienté contigu $[v_0, \dots, v_k]$ où chaque transition adjacente $(v_i, v_{i+1})$ correspond à une arête directe déclarée ($v_i \longrightarrow v_{i+1}$).
  - Dans les topologies ramifiées ($A \longrightarrow B \longrightarrow S$ et $A \longrightarrow C \longrightarrow S$), élimination des pseudo-chaînes ($[A, B, C, S]$) contenant des transitions inexistantes.
  - Le BFS parcourt les voisins ordonnés par priorité d'arêtes (assurant un nombre minimal de sauts) ; `_build_causal_chain` sélectionne ensuite parmi les chemins candidats en évaluant la profondeur de chaîne, la somme des priorités d'arête et un départage lexicographique strict.
- **Préservation des Règles Multiples par Source (`C16` / `H3`)** :
  - Remplacement du dictionnaire unitaire par `dict[str, list[CausalRule]]`, empêchant l'écrasement de règles lorsqu'un nœud source émet plusieurs branches ($A \longrightarrow B$ et $A \longrightarrow C$).
  - La priorité du candidat racine évalue le maximum des priorités de ses règles sortantes. La description du candidat reflète la règle active de la branche empruntée.
- **Validation Fail-Closed & Zéro Coercition Silencieuse des Catalogues (`C17`, `C18`, `C20-C23` / `H4`, `H4.1`)** :
  - Champs obligatoires `id`, `source`, `target` et `relation` strictement imposés dans le parseur YAML.
  - Élimination du repli silencieux vers `PROPAGATES_TO` en cas d'erreur de frappe (`PROPAGATSE_TO` lève immédiatement une `ValueError`). Les catalogues corrompus échouent à froid (*fail-closed*).
  - Règle de zéro coercition silencieuse (H4.1) : les priorités non entières (`priority: "HIGH"`, booléens, flottants) lèvent `ValueError` (C20) ; les conditions mal formées ou statuts invalides lèvent `ValueError` (C21) ; les drapeaux non booléens lèvent `ValueError` (C22) ; les entrées de règles non dictionnaires lèvent `ValueError` (C23).
- **Clarification du Modèle C12** :
  - Spécification formelle que `PRECLUDED` est un résultat d'exclusion consigné dans `precluded_hypotheses` ; ce n'est pas un état de `CausalCandidateState` actif (qui demeurent `CONFIRMED`, `POSSIBLE`, `UNRESOLVED`).
- **Suite Complète de Tests Adversaires** :
  - Ajout de 10 nouveaux scénarios adversaires (C14 à C23) dans `tests/test_causality_mode_c_adversarial.py`.
  - La suite de tests passe de 286 à **296 tests réussis à 100 %** avec typage strict (`mypy`), linter (`ruff`) et audit de sécurité (`bandit`).

## [1.0.5] - 2026-09-18
### Moteur de Raisonnement Causal Hybride Mode C (Phase 2)
- **Refonte Déclarative du Moteur de Graphe Causal** :
  - Suppression de tous les indicateurs et règles de préclusion codés en dur dans le code Python, au profit de règles 100 % déclaratives en YAML.
  - Support formel des 3 relations causales fondamentales : `PROPAGATES_TO` ($A \longrightarrow B$), `PRECLUDES` ($A \mathrel{\rlap{\quad\not}\longrightarrow} B$), et `REQUIRES` ($A \xleftarrow{\text{req}} B$).
  - Isolation de l'incertitude par sous-graphe : une observation `UNKNOWN` n'affecte que les hypothèses qui en dépendent directement, préservant l'immunité complète des sous-graphes de sondes disjointes.
- **Arbitrage Déterministe Multi-Candidats** :
  - Élimination de tout départage arbitraire : lorsque plusieurs causes racines indépendantes sont confirmées sans hiérarchie déclarée, tous les candidats sont préservés en `POSSIBLE` avec `status = ROOT_CAUSE_CONSTRAINED` et `primary_root_cause = None`.
  - Résolution déterministe rendue possible uniquement via la hiérarchie topologique du graphe ou une priorité explicite `priority: <int>`.
  - Causalité implicite nulle : plusieurs situations en échec sans règles de propagation causale s'évaluent à `status = ROOT_CAUSE_UNKNOWN` et `causal_chain = []`.
- **Modèles de Domaine Causal & Alignement du Schéma** :
  - Extension des modèles de données avec `CausalCandidateState` (`CONFIRMED`, `POSSIBLE`, `UNRESOLVED`), la classe de données `CausalCandidate`, et `unresolved_hypotheses`.
  - Mise à jour de `schemas/diagnosis-result.schema.json` pour supporter à la fois les identifiants textuels et les objets structurés de candidats.
- **Suite de Vérification Formelle (Scénarios C1 à C6)** :
  - Ajout de la suite de tests `tests/test_causality_mode_c.py` vérifiant les scénarios C1 à C6 et la relation `REQUIRES`.
  - Suite de tests portée à 275 tests réussis à 100 %.
- **Formalisation dans le Contrat Produit** :
  - Ajout de la Section 26 dans `PRODUCT_CONTRACT.md` et `PRODUCT_CONTRACT.fr.md` détaillant les 6 invariants fondamentaux du Mode C.

## [1.0.4] - 2026-09-18
### Télémétrie Entrante OpenTelemetry Mode A & Corrélation Hybride Mode C
- **Fournisseur de Télémétrie Entrante (`otel`)** :
  - Implémentation de `OTelProvider` (`@provider("otel", trust=ProviderTrust.BUILTIN)`), permettant l'ingestion sans effet de bord des métriques applicatives et des traces en erreur depuis Prometheus et Tempo/Jaeger.
  - Augmentation du nombre de providers natifs de 12 à 13 modules protégés contre toute altération.
- **Séparation des Responsabilités du Provider** :
  - Le provider est strictement limité à l'observation et la normalisation des valeurs brutes (taux d'erreur `0.073`, latence `842.0ms`, spans d'erreurs `17`).
  - L'évaluation des seuils métier SLA (`PASS` / `FAIL`) est exécutée de façon déterministe par l'`Evidence Evaluator` selon `EvidenceRequirement(threshold, comparator)` déclaré dans la politique.
- **Client HTTP Centralisé `TelemetryHTTPClient` & Protection Anti-SSRF** :
  - Rejet systématique des redirections HTTP 3xx (`RedirectDenied` / `UNKNOWN`) pour contrer les rebonds SSRF.
  - Validation avant connexion via `NetworkCapability` (`operation="otel_query"`), avec blocage automatique des métadonnées cloud (`169.254.169.254`).
  - Budget de télémétrie multi-dimensionnel : requêtes bornées (5 max), lecture de flux bornée (1 Mo max), longueur de requête limitée.
  - Caviarisation systématique des identifiants et tokens dans les logs et traces (`[REDACTED]`).
- **Séparation de la Disponibilité de la Télémétrie et de la Santé du Service** :
  - L'accessibilité technique (`otel.metrics_reachable`, `otel.traces_reachable`) évalue la disponibilité du transport (`PASS` / `UNKNOWN`).
  - Une indisponibilité du monitoring produit `TELEMETRY_METRICS_UNAVAILABLE` sans générer de faux positifs sur le service inspecté (`UNKNOWN ≠ FAIL`).
- **Corrélation Causale Hybride Mode C** :
  - Catalogues déclaratifs `catalogs/telemetry.yaml` et `causality/telemetry.yaml` reliant les symptômes de surface aux causes physiques réelles.
- **Suite de Tests** :
  - 14 nouveaux tests portant le total à 266 tests réussis à 100 %.

## [1.0.3] - 2026-09-18
### Traçage Distribué Sortant OpenTelemetry Mode B
- **Non-Interférence avec le TracerProvider Hôte** :
  - Récupération du traceur de l'application hôte via `trace.get_tracer("evidencetool", "1.0.3")` sans jamais muter ou réinitialiser le `TracerProvider` global.
  - Repli zéro-dépendance en pur Python standard vers JSON HTTP si le SDK OpenTelemetry est absent.
- **Propagation de Contexte Distribué W3C** :
  - Hiérarchie de priorité à 4 niveaux : Argument explicite > Variable `TRACEPARENT` > Span actif de l'hôte > Nouvelle trace racine.
  - Analyseur strict W3C avec repli sécurisé.
  - Paramètre `traceparent` exposé dans `AgentDiagnosisRequest`, `AgentSafetyGate.evaluate()`, `diagnose()` et `--traceparent`.
- **Sémantique des Statuts de Spans** :
  - Les décisions `BLOCK` et `HUMAN_REVIEW` produisent un statut `StatusCode.OK`. Le statut `StatusCode.ERROR` est strictement réservé aux pannes d'exécution ou d'intégrité.
- **Intégration d'un E2E Jaeger Réel en CI** :
  - Exécution d'un conteneur Jaeger réel en CI testant l'export filaire et l'indexation via l'API Jaeger Query.

## [1.0.2] - 2026-09-18
### Correction Décisionnelle & Robustesse Réseau
- **Invariant d'Incertitude Locale** : Remplacement de l'ambiguïté globale par une évaluation par situation `SituationEvaluation`. Une preuve non résolue dans un domaine disjoint (ex: Redis) ne contamine plus une décision vérifiée sur le domaine cible (ex: Nginx).
- **Repli Exhaustif UNKNOWN en V2** : Génération systématique d'observations de repli `UNKNOWN` lors des échecs de providers ou de refus de capacités.
- **Analyseurs Réseau Bornés** : Bounding du parseur RESP Redis (16 Mo / 64 Ko) et de la poignée de main MySQL (64 Ko).
- **SSH ConnectTimeout** : Ajout d'un timeout de connexion strict pour éviter les blocages de 2 minutes sur hôtes inaccessibles.

## [1.0.1] - 2026-08-26
### Durcissement de Sécurité & d'Autorité
- **Vérification TLS Stricte par Défaut (`SEC-01`)** : Validation obligatoire des certificats et noms d'hôtes.
- **Frontière Statique de Confiance des Providers (`SEC-02`)** : Enregistrement statique des providers natifs ; validation SHA-256 obligatoire pour les plugins externes.
- **Immutabilité des Politiques d'Agents (`SEC-03`)** : Correspondance stricte imposée entre `policy.action` et `request.action`.
- **Validation Sémantique des Conflits de Politiques (`SEC-04`)** : Contrôle au chargement garantissant que `allow` et `blocked_by` sont strictement disjoints.
- **Isolation du Budget de Sondes par Évaluation (`DES-01`)** : Quotas de sondes isolés par requête.
- **Distinction des Défaillances de Transport (`DES-03`)** : Erreurs d'authentification ou timeouts reclassés en `UNKNOWN`, réservant `FAIL` aux défauts avérés.

## [1.0.0] - 2026-08-26
### Ajouts Majeurs
- **Moteur Déterministe de Raisonnement Causal (`evidencetool.causality`)** : Reconstruction de chaînes de propagation causale sans hallucination ni probabilités.
- **Évaluation Causale Tri-State (`CausalityStatus`)** : Distinction explicite entre `ROOT_CAUSE_IDENTIFIED`, `ROOT_CAUSE_CONSTRAINED` et `ROOT_CAUSE_UNKNOWN`.
- **Catalogues Causaux Déclaratifs (`causality/`)** : Règles YAML définissant `PROPAGATES_TO` et `PRECLUDES`.
- **Modèle Unifié d'Incident Opérationnel (`OperationalIncident`)** : Synthèse explicable intégrant observations, situations, cause racine, chaîne et décision de gouvernance.

## [0.9.0] - 2026-08-25
### Ajouts
- **SDK pour Agents IA & Passerelle de Sécurité (`evidencetool.agent`)** : Passerelle programmatique `AgentSafetyGate`, `AgentDiagnosisRequest` et `AgentDiagnosisResult`.
- **Suivi d'Identité de l'Appelant** : `CallerIdentity` (`AI_AGENT`, `HUMAN`, `AUTOMATED_PIPELINE`).
- **Quotas de Sondes** : `ProbeTracker` avec plafond strict (`max_probes`).
- **Protection Anti-Altération** : Empreinte SHA-256 vérifiée pour les politiques de capacités.

## [0.8.0] - 2026-08-25
### Ajouts
- **Diagnostic Distribué & Corrélation Multi-Signaux Inter-Domaines** : Corrélation des couches applicatives, données, caches et réseau.
- **Catalogue de Situations Distribuées (`catalogs/distributed.yaml`)** : 7 signatures d'incidents distribués.

## [0.7.0] - 2026-08-25
### Ajouts
- **Provider Kubernetes (`k8s` / `kubernetes`)** : Inspection `kubectl` en lecture seule avec confinement d'espace de noms.

## [0.6.0] - 2026-08-25
### Ajouts
- **Providers Données & Middleware** : `postgres`, `mysql`, `redis`, `dependency`.

## [0.5.0] - 2026-08-23
### Ajouts
- **Providers Système & Réseau** : `network`, `process`, `filesystem.disk_pressure`.

## [0.4.0] - 2026-08-22
### Ajouts
- **Provider Multi-Environnement Docker (`docker` / `container`)** : Inspection de conteneurs en lecture seule stricte.

## [0.3.0] - 2026-08-22
### Ajouts
- Moteur de politique situationnelle V2.
- Schéma JSON détaillé pour les résultats de diagnostic.

## [0.2.0] - 2026-08-14
### Ajouts
- Exécution distante sans agent via SSH (`--host`).

## [0.1.0] - Version Initiale
### Ajouts
- Modèles fondamentaux Evidence, Policy et Decision.
- Moteur de politique initial V1 et diagnostic Nginx vertical.
