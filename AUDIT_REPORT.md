# Rapport d'Audit — EvidenceTool (v0.9.0)

**Date de l'audit** : 25 Août 2026  
**Version évaluée** : `v0.9.0` annoncée par `CHANGELOG.md` (branche `dev` — commit `e145bd8`)
**Date de vérification** : 25 août 2026
**Méthode** : revue statique ciblée, tests automatisés et contrôles qualité locaux
**Statut Global** : **NON APPROUVÉ POUR UNE INTÉGRATION AGENT/SSH EN PRODUCTION**

---

## 1. Résumé Exécutif

EvidenceTool est un moteur d'observabilité opérationnelle, d'évaluation de preuves et d'aide à la décision en lecture seule conçu pour diagnostiquer les incidents d'infrastructure avant toute action corrective automatique ou humaine.

L'audit a porté sur les piliers suivants :
1. **Architecture & Découplage** : Étanchéité entre la collecte de preuves, les modèles de décision, l'évaluation des politiques et les recommandations.
2. **Sécurité Offensive / Défensive (AppSec & SAST)** : Analyse statique de code, prévention des injections de commandes (`subprocess`), désanonymisation des secrets dans les logs, et confinement des sondes.
3. **Sécurité de la Chaîne d'Approvisionnement (SCA)** : Audit des dépendances figées contre les bases de vulnérabilités CVE / PyPA.
4. **Modèle de Confinement & Confiance (Capabilities & Provider Trust)** : Mécanisme de permission granulaire pour les agents autonomes et validation cryptographique (SHA-256) des plugins externes.
5. **Couverture & Fiabilité des Tests** : Tests unitaires, intégration et couverture des chemins locaux/distants.
6. **Conformité des Contrats & Documentation** : Respect des invariants formels définis dans `PRODUCT_CONTRACT.md`, `README.md` et `SECURITY.md`.

---

## 2. Synthèse des Métriques et Résultats Techniques

| Domaine d'Audit | Outil / Méthode | Objectif | Résultat Obtenu | Statut |
| :--- | :--- | :--- | :--- | :---: |
| **Qualité & Style de Code** | Ruff | Analyse `src/` et `tests/` | **0 erreur** | PASS |
| **Typage Statique Strict** | Mypy | `mypy src` | **0 erreur** | PASS |
| **Sécurité du Code (SAST)** | Bandit | Scan `src/` | **0 alerte** | PASS |
| **Tests Unitaires & Intégration** | Pytest | Suite complète | **190 réussis, 1 échec sur 191** | FAIL |
| **Couverture de Code** | Pytest-cov | Suite complète | **83%**, chemins distants data partiellement couverts | ATTENTION |
| **Analyse des dépendances** | pip-audit | Environnement Python courant | **112 alertes dans 23 paquets**; scan pollué par l’environnement global | NON CONCLUANT |
| **E2E Linux/Docker** | Scripts Bash | Non exécutés sur Windows | **Non vérifiés dans cet audit** | NON VÉRIFIÉ |

## 3. Findings

### F-01 — Élevé — Destination SSH non confinée pour le SDK agent

`AgentDiagnosisRequest.context` est converti en contexte provider sans validation. Le champ `host` peut donc être fourni par l’agent et transmis à SSH, alors que `ExecutionContext.transport_host` n’est jamais comparé à une liste autorisée et que `NetworkCapability` ne contrôle pas les destinations SSH.

**Impact :** un agent autorisé à utiliser le SDK peut déclencher des collectes sur tout hôte SSH accessible avec les identifiants présents dans l’environnement. Cela contredit le modèle Zero-Trust documenté.

**Correctif recommandé :** ajouter une capability dédiée aux hôtes de transport, valider l’hôte dans le SDK avant toute collecte et refuser toute divergence entre le transport déclaré et `context["host"]`. Ajouter des tests d’autorisation et de refus.

### F-02 — Élevé — Les providers de données ignorent le transport distant

Le provider MySQL et le provider Redis utilisent `socket.create_connection` directement même lorsqu’un `host` SSH est fourni. PostgreSQL utilise aussi un socket local dans son fallback lorsque `pg_isready` n’est pas disponible.

**Impact :** une exécution distante peut combiner une connectivité mesurée sur la machine distante avec des preuves applicatives collectées localement. Une décision `ALLOW` peut ainsi être fondée sur le mauvais serveur.

**Correctif recommandé :** exécuter chaque sonde via le transport SSH lorsque `host` est défini, ou retourner `UNKNOWN` si le provider distant ne supporte pas cette sonde. Ajouter des tests d’intégration distants pour MySQL, PostgreSQL et Redis.

### F-03 — Moyen — Secrets potentiellement rendus dans les observations dependency

L’URL fournie au provider dependency est conservée dans `value`, `method` et les messages. Une URL contenant `user:password@host` ou un token dans sa query string peut donc apparaître dans le JSON CLI et les journaux d’audit.

**Correctif recommandé :** parser puis normaliser les URLs pour supprimer les identifiants et paramètres sensibles avant de les stocker ou de les afficher; conserver uniquement l’hôte, le port et le chemin non sensible.

### F-04 — Faible — Limite de fraîcheur incorrecte à la borne exacte

Le contrat définit une preuve comme obsolète à `max_age` secondes ou plus. L’évaluateur utilise `age > max_age`; une preuve exactement à la limite reste donc considérée comme fraîche.

**Correctif recommandé :** utiliser `age >= max_age` et ajouter un test de frontière.

### F-05 — Moyen — La mesure de latence peut masquer une violation de SLA

Le provider dependency arrondit la latence mesurée à deux décimales avant de la comparer au budget SLA. Dans le scénario de test avec un budget de `0.00001` ms, la mesure devient `0.0` ms et la situation `UPSTREAM_LATENCY_DEGRADATION` n'est pas corrélée.

**Impact :** les budgets SLA inférieurs à la précision effective de l'arrondi peuvent être classés à tort comme respectés, et le scénario de décision associé échoue.

**Correctif recommandé :** comparer la mesure non arrondie au budget, puis arrondir uniquement la valeur destinée à l'affichage. Ajouter des tests avec des budgets réalistes et des valeurs proches de la limite.

---

## 4. Analyse Détaillée par Axe

### 4.1. Architecture & Intégrité Décisionnelle

```
                 [ PROVIDER ]
                      │
                      ▼
               [ OBSERVATION ] (Brute, horodatée, scope local/remote)
                      │
                      ▼
            [ EVIDENCE EVALUATOR ] (PASS, FAIL, UNKNOWN, STALE)
                      │
                      ▼
               [ POLICY ENGINE ] (Signature & Conditions)
                      │
                      ▼
              [ DECISION ENGINE ] (Invariants de sécurité formels)
                 ├── BLOCK          (Priorité 1)
                 ├── HUMAN_REVIEW   (Priorité 2)
                 └── ALLOW          (Priorité 3)
                      │
                      ▼
             [ RECOMMENDATION ] (Advisory, purement informatif)
```

- **Invariant fondamental** : La recommandation est un module purement consultatif en aval de la décision. Les tests d'architecture (`tests/test_architecture.py` et `tests/test_nginx_scenarios.py::test_06_recommendation_changes_decision_unchanged_e2e`) garantissent formellement qu'une modification des règles de recommandation ne peut **jamais** modifier une décision `BLOCK` en `ALLOW`.
- **Anti-Spoofing** : `diagnose.py` filtre et valide que chaque provider émet uniquement des observations appartenant à son namespace légitime (impossible pour un provider tiers de falsifier des preuves `docker.*` ou `systemd.*`).

### 4.2. Sécurité Applicative & Protection contre les Injections

- **Exécution Shell Sécurisée** :
  - Aucun appel n'utilise `shell=True`.
  - Tous les arguments dynamiques pour les sondes locales ou distantes (SSH) sont strictement filtrés et échappés avec `shlex.quote()`.
- **Réduction partielle de l'exposition des données** :
  - `DockerProvider` applique un filtre Regex `_sanitize_logs()` et limite les logs à 8 192 caractères.
  - Ce filtre ne protège pas les URLs dependency contenant des credentials ou des tokens; voir F-03.
- **Gestion Cryptographique Universelle (TLS Provider)** :
  - Remplacement des anciens appels spécifiques RSA par `openssl x509 -pubkey` et `openssl pkey -pubout`.
  - Support certifié de toutes les paires cryptographiques modernes : RSA, ECDSA (P-256, P-384, P-521) et Ed25519.

### 4.3. Système de Capacités & Confinement d'Exécution (`CapabilitySet`)

Pour une intégration sécurisée dans des environnements d'agents autonomes :
- **Réseau restreint (`NetworkCapability`)** :
  - Liste blanche d'opérations : `dns_lookup`, `tcp_connect`, `icmp_echo`.
  - Contrôle d'accès par IP/CIDR (ex: restreindre à `10.0.0.0/8` ou `127.0.0.1`).
  - Restriction de ports autorisés et plafond sur le nombre de sondes (`max_probes`).
  - En cas de dépassement ou de tentative non autorisée, levée de `CapabilityDenied` et production d'une preuve `UNKNOWN` dans les chemins pris en charge.
  - Le confinement des hôtes SSH n'est pas implémenté pour le SDK agent; voir F-01.
- **Vérification d'intégrité des Plugins (`load_approved_plugins`)** :
  - Les providers externes doivent être déclarés avec leur hash **SHA-256**. Tout fichier modifié ou corrompu est rejeté avant même son importation dans l'interpréteur Python.

### 4.4. Chaîne d'Approvisionnement & Dépendances

L'ensemble des dépendances directes du projet est rigoureusement verrouillé :
- `pyyaml == 6.0.2`
- `click == 8.3.3`
- `cryptography == 50.0.0`
- `pytest == 9.0.3`
- `jsonschema == 4.23.0`
- `types-PyYAML == 6.0.12.20241230`

Le scan `pip-audit` exécuté dans l'environnement courant a retourné 112 alertes sur 23 paquets installés. Ce résultat inclut des paquets sans rapport avec les dépendances directes du projet; il est donc non concluant pour la release. Le pipeline doit être exécuté dans un environnement virtuel propre et son résultat archivé.

---

## 5. Bilan des Tests & Couverture

La suite locale compte **191 tests, dont 190 réussis et 1 échec**. L'échec est `test_scenario_upstream_latency_degradation_blocks_restart` dans `tests/test_data_correlation.py`. La couverture mesurée est de **83%**. Les tests couvrent principalement les chemins locaux et les mocks SSH; ils ne détectent pas F-02, car les providers de données ne disposent pas de scénarios distants représentatifs.

Les scripts E2E Linux/Docker existent dans `tests/e2e/`, mais n'ont pas été exécutés dans cet audit sur l'environnement Windows.

---

## 6. Recommandations & Axes d'Amélioration

Les actions prioritaires avant approbation sont :

1. Corriger F-01 et ajouter une liste blanche explicite des hôtes SSH.
2. Corriger F-02 et tester chaque provider de données en mode distant.
3. Corriger F-03 avec une fonction commune de redaction des URLs et secrets.
4. Corriger F-05 en conservant la précision de mesure jusqu'à la comparaison SLA.
5. Corriger F-04 et ajouter le test de frontière `age == max_age`.
6. Relancer `pip-audit` dans un environnement virtuel propre et vérifier les dépendances de production séparément des outils de test.

---

## 7. Conclusion de l'Audit

EvidenceTool présente une base partiellement saine: Ruff, Mypy et Bandit passent, mais la suite de tests n'est pas entièrement verte. Les défauts de confinement SSH, de collecte distante et de mesure SLA peuvent fausser une décision opérationnelle ou élargir l'accès d'un agent au-delà de ses permissions déclarées.

**Avis final : non approuvé pour une intégration agent/SSH en production avant correction de F-01 et F-02.**
