# Rapport d'audit sécurité et conception — EvidenceTool

**Date :** 26 août 2026  
**Version de référence :** `pyproject.toml` déclare `0.5.0`  
**Périmètre :** code Python sous `src/evidencetool/`, tests, policies/catalogues YAML, packaging et documentation de sécurité  
**Nature :** revue statique, analyse des chemins d'exécution et contrôles outillés locaux

## 1. Résumé exécutif

EvidenceTool possède de bonnes bases de sécurité : exécution subprocess sans `shell=True`, séparation providers/evidence/decision/recommendation, policies fail-closed sur plusieurs preuves critiques, validation de namespace des observations, capabilities réseau/Kubernetes, hash SHA-256 des plugins explicitement approuvés et tests dédiés aux injections SSH.

L'audit identifie cependant plusieurs risques importants avant usage comme passerelle de sécurité de production :

- **Risque élevé :** les sondes HTTPS de dépendances désactivent la validation des certificats (`CERT_NONE` localement et `curl -k` à distance). Un attaquant capable d'intercepter le trafic peut falsifier le résultat de diagnostic.
- **Risque élevé conditionnel :** le registre importe automatiquement les modules Python déposés dans le package avant qu'un contrôle de confiance ne puisse les empêcher de s'exécuter. Une écriture non autorisée dans le répertoire de l'application devient une possibilité d'exécution de code au chargement.
- **Risque moyen :** le SDK agent accepte un `policy_path` fourni par la requête et ne vérifie pas qu'il correspond à la policy par défaut, à une allowlist ou à une signature. Un agent qui peut choisir ce chemin peut sélectionner une policy plus permissive.
- **Risque moyen :** les valeurs de policy, catalogues et contexte sont insuffisamment validées sémantiquement; des configurations incohérentes peuvent produire des décisions bloquantes, des diagnostics faux ou une confiance excessive dans les signatures.
- **Risque moyen :** des données de diagnostic sensibles ou internes sont conservées dans les observations JSON et messages; la redaction est partielle et dépend de motifs.
- **Défauts de conception :** budget de probes mutable et cumulatif sur une instance de gate, défauts permissifs pour plusieurs capabilities, confusion `FAIL`/`UNKNOWN` dans Kubernetes et versionnement contradictoire.

**Conclusion globale :** la posture est prometteuse pour un outil d'observation, mais le statut « safety gateway » exige de corriger en priorité la validation TLS, le chargement des providers et la gouvernance des policies. Bandit et Ruff ne détectent pas ces défauts logiques.

## 2. Méthode et limites

L'analyse a porté sur les chemins de collecte locale et distante, le CLI, l'Agent Safety Gate, les loaders YAML, le registre de providers, la sortie JSON, les métriques et les tests. Elle n'a pas inclus :

- un test d'intrusion sur une machine Linux ou un cluster réel ;
- une vérification de permissions de fichiers du dépôt et de l'environnement d'exécution ;
- un scan SCA isolé dans un environnement virtuel construit uniquement depuis les dépendances de production ;
- la preuve qu'un attaquant dispose effectivement d'un accès en écriture au répertoire de l'application.

Les niveaux utilisés sont : **Critique**, **Élevé**, **Moyen**, **Faible**, ou **Observation**. Les risques conditionnels indiquent que l'impact dépend d'une condition de déploiement précise.

## 3. Constats prioritaires

### SEC-01 — Validation TLS désactivée pour les dépendances HTTPS

**Gravité : Élevée**  
**Confiance : élevée**  
**Composant :** `src/evidencetool/providers/dependency.py`

Dans le chemin local HTTPS, `ssl.create_default_context()` est immédiatement suivi de `check_hostname = False` et `verify_mode = ssl.CERT_NONE`. Dans le chemin distant, la commande curl utilise `-k`. Le diagnostic accepte donc un certificat auto-signé, expiré ou présenté par un intermédiaire malveillant.

**Impact :** un MITM ou un proxy compromis peut faire apparaître une dépendance amont comme disponible, saine ou conforme au SLA. Pour une décision `ALLOW`, cela compromet la fiabilité de la preuve et peut conduire l'appelant à entreprendre une remédiation injustifiée.

**Remédiation :** valider les certificats et le nom d'hôte par défaut; rendre l'exception explicite dans la policy avec une capability dédiée, un CA configurable et une trace d'exception. Supprimer `-k` du chemin distant. Ajouter des tests qui rejettent un certificat invalide et vérifient le comportement avec un CA de confiance contrôlé.

### SEC-02 — Import automatique de providers avant contrôle de confiance

**Gravité : Élevée conditionnelle**  
**Confiance : élevée**  
**Composant :** `src/evidencetool/providers/registry.py`

`diagnose()` appelle `load_all_providers()` sans désactiver les modules expérimentaux. Le registre parcourt tous les modules Python présents dans le package et les importe. Le contrôle `require_trusted_providers` intervient ensuite, au moment de l'exécution du provider, et non avant l'import Python. Le mécanisme SHA-256 existe pour `load_approved_plugins()`, mais il n'est pas le chemin imposé par la découverte automatique.

**Impact :** si un tiers peut déposer ou remplacer un `.py` dans `src/evidencetool/providers`, son code top-level s'exécute au démarrage, même si le provider est ultérieurement refusé comme non fiable. Cela peut mener à exécution de code avec les privilèges du processus, lecture de secrets ou altération du diagnostic.

**Remédiation :** désactiver la découverte automatique par défaut pour les agents; charger uniquement une liste statique de built-ins; exiger un manifeste signé ou hashé avant tout import externe; vérifier propriétaire, permissions et emplacement des modules. Ne pas considérer le contrôle de confiance post-import comme une barrière d'exécution.

### SEC-03 — Policy sélectionnable par la requête de l'agent

**Gravité : Moyenne à élevée selon l'intégration**  
**Confiance : élevée**  
**Composant :** `src/evidencetool/agent/gate.py`, `src/evidencetool/agent/models.py`

La requête contient `policy_path`. Si cette valeur est présente, `AgentSafetyGate.evaluate()` charge cette policy; elle prime sur `_default_policy`. Il n'existe pas de vérification de chemin autorisé, d'empreinte attendue, de signature, ni de contrôle que `policy.action` corresponde à `request.action`.

**Impact :** un agent ou un appelant ayant accès à l'API peut sélectionner une policy permissive, une policy V1 legacy ou une policy ne couvrant pas l'action demandée. Le résultat `is_allowed` ne doit alors pas être interprété comme l'autorisation de `request.action`.

**Remédiation :** interdire `policy_path` dans les requêtes d'agents non administratifs; utiliser une policy immuable configurée par le gate; sinon appliquer une allowlist de chemins/empreintes, vérifier `policy.action == request.action`, imposer V2 pour les agents et journaliser l'identité de la policy effectivement utilisée.

### SEC-04 — Absence de validation sémantique des policies et catalogues

**Gravité : Moyenne**  
**Confiance : élevée**  
**Composants :** `src/evidencetool/policy/loader.py`, `src/evidencetool/diagnostic/loader.py`, `src/evidencetool/models/policy.py`

Les loaders vérifient la structure YAML et les enums, mais n'imposent pas plusieurs invariants essentiels : identifiants au format attendu, absence de doublons, `max_age` fini et non négatif, action cohérente avec la requête, situations référencées existantes, preuves de signatures présentes dans `required_evidence`, ou non-recouvrement explicite des situations autorisées et bloquées.

**Impact :** une faute de configuration peut rendre une situation impossible à matcher et provoquer un blocage systématique, ou laisser une policy présentée comme complète alors qu'elle ne couvre pas la preuve nécessaire. Avec une policy externe, cela élargit la surface de contournement par mauvaise configuration.

**Remédiation :** introduire une validation de schéma et de cohérence au chargement; refuser les doublons et les références orphelines; exiger un catalogue associé pour les policies V2; vérifier les types numériques et borner les tailles des listes, chaînes et descriptions; versionner et signer les policies de production.

### SEC-05 — Redaction des informations sensibles incomplète

**Gravité : Moyenne**  
**Confiance : élevée**  
**Composants :** `providers/dependency.py`, `providers/docker.py`, `models/observation.py`, `cli/render.py`

La redaction des URLs dépend d'une liste de paramètres sensibles. La redaction des logs Docker utilise une regex limitée aux formes `password`, `token`, `secret`, `api_key` et `authorization`. Les observations conservent par ailleurs `method`, `message`, `value`, chemins de certificats/clés, erreurs système, noms d'hôtes, sorties de commandes et parfois des champs bruts (`raw`). La sortie JSON expose toutes ces données à l'appelant.

**Impact :** fuite de topologie, chemins sensibles, noms de services, paramètres secrets non reconnus, messages d'erreur contenant des credentials ou données applicatives. Une regex ne peut pas garantir la suppression de secrets structurés, encodés ou placés dans un corps de réponse.

**Remédiation :** adopter une fonction de redaction centralisée avant création de l'observation et avant sérialisation; ne jamais conserver le contenu brut par défaut; utiliser une allowlist de champs exportables, borner toutes les sorties, masquer les chemins de clés privées et traiter les secrets via une bibliothèque/configuration structurée. Ajouter des tests de redaction URI, headers, logs, exceptions et sorties distantes.

### SEC-06 — Falsification possible de l'heure d'observation et fraîcheur

**Gravité : Moyenne**  
**Confiance : moyenne à élevée**  
**Composants :** `models/observation.py`, `evidence/evaluator.py`, providers

La fraîcheur est calculée à partir de `observed_at`, valeur produite par le provider. Les providers intégrés utilisent l'horloge locale, mais un provider dynamique ou une observation injectée peut fournir une date future ou une date choisie. Aucune règle visible ne rejette les dates futures, les timestamps trop éloignés ou les horloges incohérentes entre hôte local et hôte distant.

**Impact :** une preuve peut être considérée fraîche alors que son origine est ancienne, ou être rendue artificiellement périmée. Dans un système acceptant des providers externes, cela affaiblit le contrat de fraîcheur.

**Remédiation :** renseigner `collected_at` côté moteur et vérifier l'écart maximal entre `observed_at` et `collected_at`; rejeter ou marquer `UNKNOWN` les dates futures et les dates hors fenêtre; authentifier la provenance des providers distants.

## 4. Défauts de conception et risques de robustesse

### DES-01 — Budget de probes partagé et mutabilité cachée

`CapabilitySet` est une dataclass gelée mais contient un `ProbeTracker` mutable. Le tracker est réutilisé par une instance de `AgentSafetyGate` entre les appels `evaluate()`. Une requête peut donc consommer le budget des requêtes suivantes. De plus, `record_probe()` incrémente avant de vérifier la limite : une tentative refusée consomme le compteur.

**Impact :** déni de service logique entre sessions, résultats dépendants de l'ordre des requêtes et audit moins prévisible.

**Remédiation :** créer un tracker par évaluation ou par session explicitement définie; décider séparément si les tentatives refusées comptent; rendre la durée de vie et la concurrence du quota explicites.

### DES-02 — Valeurs par défaut trop permissives pour une gateway

`NetworkCapability` autorise par défaut toutes les opérations et la cible `"*"`; `KubernetesCapability` autorise tous les namespaces sauf trois namespaces système. La protection SSH ajoutée dans le gate impose une policy explicite, mais les autres probes restent largement ouvertes si l'appelant construit directement un `ExecutionContext` ou utilise le SDK sans policy restrictive.

**Impact :** une mauvaise intégration peut permettre des probes vers des cibles internes, des ports arbitraires ou des namespaces inattendus. Ce n'est pas une injection de commande, mais une violation possible du principe de moindre privilège.

**Remédiation :** defaults deny pour les agents; exiger une policy explicite pour toute opération réseau et Kubernetes; imposer une allowlist de cibles et namespaces; séparer les capabilities de diagnostic local et distant.

### DES-03 — Classification Kubernetes trop affirmative

Le provider transforme l'échec de `kubectl get pod`, une absence de pod ou une erreur de parsing JSON en observation `FAIL` sur `k8s.pod_phase`. Une impossibilité de collecter ou de vérifier une donnée devrait généralement être `UNKNOWN`, tandis qu'un pod réellement absent, une erreur d'autorisation et une panne de kubectl sont des causes différentes.

**Impact :** le système peut présenter une panne confirmée alors qu'il n'a qu'une erreur de transport ou d'autorisation. La décision reste souvent bloquée, mais l'explication et la cause racine sont fausses, ce qui peut provoquer une mauvaise remédiation humaine.

**Remédiation :** distinguer `POD_NOT_FOUND`, `FORBIDDEN`, timeout, outil absent et JSON invalide; réserver `FAIL` aux faits observés sur le pod; produire `UNKNOWN` pour les erreurs de collecte et inclure un champ d'état du transport.

### DES-04 — Dépendances et versions non gouvernées par un lock de production

`pyproject.toml` épingle six dépendances directes ou de développement, mais il n'y a pas de lockfile de résolution de production visible. Le scan réalisé avec `pip-audit --local` a trouvé 112 alertes dans 23 paquets de l'environnement courant, notamment des paquets non déclarés par EvidenceTool; il ne permet donc pas de conclure sur l'artefact de production.

**Impact :** reproductibilité et traçabilité insuffisantes, risque d'installer indirectement une version vulnérable ou différente entre environnements.

**Remédiation :** produire un lockfile/rapport SBOM par environnement, scanner un environnement vierge construit depuis le projet, séparer dépendances runtime et outils de test, automatiser le seuil de blocage CVE et documenter les exceptions.

### DES-05 — Contrats et versions documentés contradictoires

`SECURITY.md` mentionne la release `0.5.0`, `pyproject.toml` déclare `0.5.0`, mais d'autres documents et métadonnées du workspace mentionnent V0.8/V0.9 ou des versions plus anciennes. Le contrat contient aussi des mentions historiques incompatibles avec le support Kubernetes actuel.

**Impact :** mauvaise gestion des correctifs, difficulté à savoir quelle policy, quel schéma JSON et quelle surface de sécurité sont effectivement supportés; risque de publier un audit ou une advisory contre une version erronée.

**Remédiation :** définir une source de vérité de version, synchroniser README, SECURITY, CHANGELOG, métadonnées et contrat, et ajouter un contrôle CI sur les versions et claims de support.

## 5. Contrôles positifs observés

- Les commandes utilisent des listes d'arguments et non `shell=True`; les tests vérifient aussi le quoting des arguments SSH.
- `StrictHostKeyChecking=yes` et `BatchMode=yes` sont activés pour SSH; le CLI applique un format de host restreint.
- Le moteur valide que les observations retournées restent dans le namespace et la source attendus.
- `UNKNOWN` est distinct de `FAIL` dans le modèle et le moteur; le défaut `on_unknown` est fail-closed.
- L'ordre de décision est `BLOCK > HUMAN_REVIEW > ALLOW` et la recommandation est calculée après la décision.
- Les providers dynamiques explicitement approuvés peuvent être vérifiés par hash SHA-256.
- Les tests couvrent l'architecture, les capabilities, le transport SSH, la redaction de plusieurs données et les invariants de décision.
- Bandit : aucune alerte sur `src` avec la configuration du projet. Ruff : contrôle réussi sur `src` et `tests`.

Ces contrôles réduisent le risque, mais ils ne compensent pas une validation TLS désactivée ou une policy non gouvernée : un outil de sécurité peut être syntaxiquement propre tout en produisant une preuve métier non fiable.

## 6. Plan de remédiation priorisé

### P0 — avant usage comme autorité de confiance

1. Réactiver la validation TLS pour les probes locales et distantes; documenter une exception contrôlée uniquement si nécessaire.
2. Désactiver l'import automatique des providers expérimentaux et imposer l'approbation/hash avant import.
3. Empêcher un agent de choisir librement `policy_path`; vérifier l'action, l'empreinte, la version et le schéma de la policy.
4. Traiter les erreurs de collecte Kubernetes et similaires comme `UNKNOWN` lorsqu'aucun fait d'incident n'a été observé.

### P1 — durcissement de la gouvernance

1. Ajouter une validation sémantique stricte des policies/catalogues.
2. Centraliser la redaction et supprimer les sorties brutes non indispensables.
3. Isoler les quotas de probes par appel/session et passer les defaults agent en deny-by-default.
4. Produire un environnement de build reproductible, un SBOM et un scan SCA propre.

### P2 — qualité et exploitation

1. Synchroniser version, contrat produit et documentation de support.
2. Ajouter des tests adversariaux pour MITM TLS, policy path, provider malveillant, timestamps futurs, fuite de secrets et concurrence du quota.
3. Formaliser les journaux d'audit : policy fingerprint, provider trust, cible, capability utilisée, résultat du transport et motif de blocage.

## 7. Validation exécutée

| Contrôle | Résultat |
|---|---|
| `bandit -r src -c pyproject.toml` | PASS, 0 alerte |
| `ruff check src tests` | PASS |
| `pytest -q` | PASS, 197 tests |
| `pip-audit --local` | NON CONCLUANT pour le projet : 112 alertes / 23 paquets de l'environnement courant |

Le résultat `pip-audit` doit être relancé dans un environnement virtuel propre avant de qualifier les dépendances runtime comme vulnérables ou saines.

## 8. Avis final

EvidenceTool est conçu avec une séparation saine entre observation et décision et montre une bonne maturité sur les injections shell et les invariants de décision. Les failles les plus préoccupantes ne sont pas détectées par les scanners syntaxiques : elles concernent la confiance accordée aux preuves réseau, l'import de code avant autorisation, et la capacité d'un appelant à choisir la policy.

**Avis : non recommandé comme passerelle d'autorisation de remédiation en production avant clôture des constats SEC-01, SEC-02 et SEC-03.** Il peut continuer à être utilisé comme outil d'observation sous contrôle, avec sortie et accès réseau limités, en attendant ces corrections.
