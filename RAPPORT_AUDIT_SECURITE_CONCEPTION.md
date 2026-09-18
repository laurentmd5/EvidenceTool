# Rapport d'audit sécurité et conception — EvidenceTool

**Date de mise à jour :** 26 août 2026  
**Version de référence :** `pyproject.toml` déclare `1.0.1`  
**Périmètre :** code Python sous `src/evidencetool/`, tests, policies/catalogues YAML, packaging et documentation de sécurité  
**Nature :** revue statique, analyse des chemins d'exécution et contrôles outillés locaux

## 1. Résumé exécutif

EvidenceTool possède de bonnes bases de sécurité : exécution subprocess sans `shell=True`, séparation providers/evidence/decision/recommendation, policies fail-closed sur plusieurs preuves critiques, validation de namespace des observations, capabilities réseau/Kubernetes, hash SHA-256 des plugins explicitement approuvés et tests dédiés aux injections SSH.

La réévaluation du code après les correctifs montre que SEC-01 à SEC-03, SEC-06, DES-01 et DES-03 sont corrigés. Les risques encore ouverts ou partiellement traités sont les suivants :

- **Risque moyen résiduel :** la redaction centralisée protège désormais la sortie JSON, mais elle reste fondée sur des motifs et les données internes peuvent encore contenir des informations sensibles.
- **Risque moyen résiduel :** la validation sémantique des policies couvre désormais les types, identifiants, doublons, âges et conflits allow/blocked_by, mais pas toutes les références catalogue/policy ni la signature des policies de production.
- **Risque moyen :** les valeurs par défaut des capabilities réseau et Kubernetes restent permissives pour un appelant qui construit directement un `ExecutionContext`.
- **Risque de gouvernance :** le lockfile/SBOM de production et la cohérence complète des documents doivent encore être vérifiés dans un environnement propre.

**Conclusion globale mise à jour :** les barrières prioritaires précédemment identifiées sont corrigées dans le code courant. Le statut « safety gateway » reste conditionné à la gouvernance des policies, aux defaults des capabilities utilisées directement et à la chaîne d'approvisionnement.

## 2. Méthode et limites

L'analyse a porté sur les chemins de collecte locale et distante, le CLI, l'Agent Safety Gate, les loaders YAML, le registre de providers, la sortie JSON, les métriques et les tests. Elle n'a pas inclus :

- un test d'intrusion sur une machine Linux ou un cluster réel ;
- une vérification de permissions de fichiers du dépôt et de l'environnement d'exécution ;
- un scan SCA isolé dans un environnement virtuel construit uniquement depuis les dépendances de production ;
- la preuve qu'un attaquant dispose effectivement d'un accès en écriture au répertoire de l'application.

Les niveaux utilisés sont : **Critique**, **Élevé**, **Moyen**, **Faible**, ou **Observation**. Les risques conditionnels indiquent que l'impact dépend d'une condition de déploiement précise.

## 3. Constats prioritaires

### SEC-01 — CORRIGÉ — Validation TLS des dépendances HTTPS

**Gravité : Élevée**  
**Confiance : élevée**  
**Composant :** `src/evidencetool/providers/dependency.py`

Le défaut précédent a été corrigé. Le chemin local utilise désormais `CERT_REQUIRED` et la vérification du nom d'hôte. Le chemin distant n'ajoute `-k` que lorsque `allow_insecure_tls` est explicitement activé par la capability réseau.

**Impact :** un MITM ou un proxy compromis peut faire apparaître une dépendance amont comme disponible, saine ou conforme au SLA. Pour une décision `ALLOW`, cela compromet la fiabilité de la preuve et peut conduire l'appelant à entreprendre une remédiation injustifiée.

**Vérification :** `tests/test_dependency_provider.py` couvre le TLS strict par défaut et l'exception explicitement gouvernée. **Risque résiduel :** `allow_insecure_tls` reste disponible et doit être interdit dans les capabilities de production.

### SEC-02 — CORRIGÉ — Import automatique de providers avant contrôle de confiance

**Gravité : Élevée conditionnelle**  
**Confiance : élevée**  
**Composant :** `src/evidencetool/providers/registry.py`

Le registre importe désormais une liste statique de providers built-in vérifiés. Les providers externes ne sont plus découverts automatiquement; ils doivent passer par `load_approved_plugins()` et une vérification SHA-256 avant import.

**Impact historique :** ce risque existait lorsque la découverte parcourait automatiquement le package. Il est désormais réduit par l'import statique des built-ins; une altération d'un built-in installé reste un risque général d'intégrité de l'environnement.

**Remédiation :** désactiver la découverte automatique par défaut pour les agents; charger uniquement une liste statique de built-ins; exiger un manifeste signé ou hashé avant tout import externe; vérifier propriétaire, permissions et emplacement des modules. Ne pas considérer le contrôle de confiance post-import comme une barrière d'exécution.

### SEC-03 — CORRIGÉ — Policy sélectionnable par la requête de l'agent

**Gravité : Moyenne à élevée selon l'intégration**  
**Confiance : élevée**  
**Composant :** `src/evidencetool/agent/gate.py`, `src/evidencetool/agent/models.py`

Le gate donne désormais priorité à la policy par défaut configurée. `policy_path` n'est utilisé qu'en l'absence de policy par défaut et l'action de la policy est comparée à `request.action`; un mismatch est rejeté.

**Impact historique :** avant le correctif, un appelant pouvait sélectionner une policy permissive ou incohérente avec l'action. Le contrôle courant empêche ce scénario lorsque le gate dispose d'une policy par défaut et rejette les mismatches d'action.

**Vérification :** la policy par défaut est prioritaire et `policy.action` est comparée à `request.action`. **Amélioration restante :** ajouter une allowlist/empreinte pour le fallback et imposer V2 selon le profil de déploiement.

### SEC-04 — PARTIELLEMENT CORRIGÉ — Validation sémantique des policies et catalogues

**Gravité : Moyenne**  
**Confiance : élevée**  
**Composants :** `src/evidencetool/policy/loader.py`, `src/evidencetool/diagnostic/loader.py`, `src/evidencetool/models/policy.py`

Le loader policy valide désormais la structure YAML, les enums, les actions non vides, les identifiants d'evidence, les doublons, `max_age` fini et non négatif, ainsi que le non-recouvrement de `allow` et `blocked_by`. Les références entre policy et catalogue, les preuves de signature requises et la signature cryptographique des policies ne sont pas encore vérifiées.

**Impact :** une faute de configuration peut rendre une situation impossible à matcher et provoquer un blocage systématique, ou laisser une policy présentée comme complète alors qu'elle ne couvre pas la preuve nécessaire. Avec une policy externe, cela élargit la surface de contournement par mauvaise configuration.

**Remédiation restante :** introduire une validation policy/catalogue couplée; exiger un catalogue associé aux policies V2; vérifier les références orphelines et borner les tailles; versionner et signer les policies de production.

### SEC-05 — PARTIELLEMENT CORRIGÉ — Redaction des informations sensibles

**Gravité : Moyenne**  
**Confiance : élevée**  
**Composants :** `providers/dependency.py`, `providers/docker.py`, `models/observation.py`, `cli/render.py`

Une redaction centralisée est désormais appliquée à `method`, `message` et `value` lors de la sérialisation JSON, en complément des protections URL et logs Docker. Elle reste fondée sur des motifs et ne supprime pas toutes les informations internes avant leur conservation dans les objets d'observation.

**Impact :** fuite de topologie, chemins sensibles, noms de services, paramètres secrets non reconnus, messages d'erreur contenant des credentials ou données applicatives. Une regex ne peut pas garantir la suppression de secrets structurés, encodés ou placés dans un corps de réponse.

**Remédiation restante :** appliquer une allowlist de champs exportables, supprimer les contenus bruts non indispensables, masquer les chemins sensibles et ajouter des tests pour headers, exceptions et sorties distantes.

### SEC-06 — CORRIGÉ — Falsification possible de l'heure d'observation et fraîcheur

**Gravité : Moyenne**  
**Confiance : moyenne à élevée**  
**Composants :** `models/observation.py`, `evidence/evaluator.py`, providers

L'évaluateur rejette désormais les timestamps futurs de plus de cinq secondes en convertissant la preuve en `UNKNOWN` et marque l'observation comme stale. La règle de fraîcheur existante continue à appliquer `max_age` avant décision.

**Impact :** une preuve peut être considérée fraîche alors que son origine est ancienne, ou être rendue artificiellement périmée. Dans un système acceptant des providers externes, cela affaiblit le contrat de fraîcheur.

**Vérification :** des tests couvrent les timestamps futurs et les observations périmées. **Risque résiduel :** la provenance distante n'est pas cryptographiquement attestée.

## 4. Défauts de conception et risques de robustesse

### DES-01 — CORRIGÉ — Budget de probes partagé et mutabilité cachée

`CapabilitySet` contient toujours un `ProbeTracker` mutable, mais le gate crée désormais une copie isolée avec tracker neuf pour chaque évaluation. Les compteurs ne fuient donc plus entre requêtes.

**Impact :** déni de service logique entre sessions, résultats dépendants de l'ordre des requêtes et audit moins prévisible.

**Vérification :** `tests/test_agent_sdk.py` vérifie l'isolation du budget. **Risque résiduel :** une tentative refusée est encore comptabilisée avant le contrôle de limite.

### DES-02 — PARTIELLEMENT CORRIGÉ — Valeurs par défaut trop permissives pour une gateway

Le `AgentSafetyGate` utilise désormais par défaut une allowlist loopback et désactive Kubernetes sans capability explicite. Les classes `NetworkCapability` et `KubernetesCapability` restent permissives lorsqu'un appelant construit directement un `ExecutionContext` ou les instancie sans policy restrictive.

**Impact :** une mauvaise intégration peut permettre des probes vers des cibles internes, des ports arbitraires ou des namespaces inattendus. Ce n'est pas une injection de commande, mais une violation possible du principe de moindre privilège.

**Remédiation restante :** conserver le profil loopback du gate, documenter ou imposer des defaults deny dans les API de construction directe et séparer les capabilities locales/distantes.

### DES-03 — CORRIGÉ — Classification Kubernetes trop affirmative

Le provider distingue désormais le pod absent (`FAIL` avec `POD_NOT_FOUND`) des erreurs de transport/permission (`UNKNOWN`) et des erreurs de parsing (`UNKNOWN`), avec un statut de transport explicite.

**Impact historique :** le système pouvait présenter une panne confirmée pour une erreur de transport ou d'autorisation. Le correctif conserve le blocage de sûreté tout en améliorant l'exactitude de l'explication.

**Vérification :** les tests Kubernetes couvrent la distinction entre absence, erreur de collecte et JSON invalide.

### DES-04 — Dépendances et versions non gouvernées par un lock de production

`pyproject.toml` épingle six dépendances directes ou de développement, mais il n'y a pas de lockfile de résolution de production visible. Le scan réalisé avec `pip-audit --local` a trouvé 112 alertes dans 23 paquets de l'environnement courant, notamment des paquets non déclarés par EvidenceTool; il ne permet donc pas de conclure sur l'artefact de production.

**Impact :** reproductibilité et traçabilité insuffisantes, risque d'installer indirectement une version vulnérable ou différente entre environnements.

**Remédiation :** produire un lockfile/rapport SBOM par environnement, scanner un environnement vierge construit depuis le projet, séparer dépendances runtime et outils de test, automatiser le seuil de blocage CVE et documenter les exceptions.

### DES-05 — PARTIELLEMENT CORRIGÉ — Contrats et versions documentés contradictoires

`pyproject.toml` et `SECURITY.md` ont été alignés sur `1.0.1`, mais des documents historiques ou métadonnées peuvent encore mentionner V0.8/V0.9 ou des versions antérieures. Le contrat peut également conserver des mentions historiques incompatibles avec le support Kubernetes actuel.

**Impact :** mauvaise gestion des correctifs, difficulté à savoir quelle policy, quel schéma JSON et quelle surface de sécurité sont effectivement supportés; risque de publier un audit ou une advisory contre une version erronée.

**Remédiation :** définir une source de vérité de version, synchroniser README, SECURITY, CHANGELOG, métadonnées et contrat, et ajouter un contrôle CI sur les versions et claims de support.

## 5. Contrôles positifs observés

- Les commandes utilisent des listes d'arguments et non `shell=True`; les tests vérifient aussi le quoting des arguments SSH.
- `StrictHostKeyChecking=yes` et `BatchMode=yes` sont activés pour SSH; le CLI applique un format de host restreint.
- Le moteur valide que les observations retournées restent dans le namespace et la source attendus.
- `UNKNOWN` est distinct de `FAIL` dans le modèle et le moteur; le défaut `on_unknown` est fail-closed.
- L'ordre de décision est `BLOCK > HUMAN_REVIEW > ALLOW` et la recommandation est calculée après la décision.
- Les providers externes explicitement approuvés peuvent être vérifiés par hash SHA-256 avant import.
- Les tests couvrent l'architecture, les capabilities, le transport SSH, la redaction de plusieurs données et les invariants de décision.
- Bandit : aucune alerte sur `src` avec la configuration du projet. Ruff : contrôle réussi sur `src` et `tests`.

Ces contrôles réduisent le risque, mais l'option TLS insecure, la redaction partielle et une policy non gouvernée restent à traiter explicitement en production.

## 6. Plan de remédiation priorisé

### P0 — vérifications restantes avant usage comme autorité de confiance

1. Interdire `allow_insecure_tls` dans les capabilities de production et contrôler la provenance des manifests de plugins.
2. Ajouter une allowlist/empreinte de policy pour le fallback agent et imposer V2 selon le profil de déploiement.
3. Vérifier en environnement représentatif les permissions, la chaîne SSH, les certificats de confiance et le comportement des providers corrigés.

### P1 — durcissement de la gouvernance

1. Compléter la validation sémantique des policies/catalogues, notamment les références catalogue/policy.
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
| `pytest -q` | PASS, 210 tests |
| `pip-audit --local` | NON CONCLUANT pour le projet : 112 alertes / 23 paquets de l'environnement courant |

Le résultat `pip-audit` doit être relancé dans un environnement virtuel propre avant de qualifier les dépendances runtime comme vulnérables ou saines.

## 8. Avis final

EvidenceTool est conçu avec une séparation saine entre observation et décision et montre une bonne maturité sur les injections shell et les invariants de décision. Les constats prioritaires du rapport précédent concernant TLS, l'import de code non approuvé, la sélection de policy, les timestamps, les quotas et la classification Kubernetes ont été traités dans le commit courant. Les risques restants concernent surtout la gouvernance, la redaction, les defaults de capabilities et la chaîne d'approvisionnement.

**Avis mis à jour : utilisable comme passerelle sous réserve de gouvernance des policies, de durcissement des capabilities directes et de validation E2E représentative; les constats SEC-01, SEC-02 et SEC-03 ne sont plus ouverts dans le code audité.**
