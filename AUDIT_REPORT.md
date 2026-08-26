# Rapport d'Audit — EvidenceTool (v0.9.0)

**Date de l'audit** : 25 août 2026
**Version évaluée** : `v0.9.0` (branche `dev` — état de travail post-corrections)
**Date de vérification** : 25 août 2026
**Méthode** : revue statique ciblée, tests automatisés et contrôles qualité locaux
**Statut Global** : **APPROUVABLE SOUS RÉSERVE DE VALIDATION E2E ET SCA PROPRE**

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
| **Tests Unitaires & Intégration** | Pytest | Suite complète | **195 / 195 tests passés** | PASS |
| **Couverture de Code** | Pytest-cov | Suite complète | **83%**, chemins distants data partiellement couverts | ATTENTION |
| **Analyse des dépendances** | pip-audit | Environnement Python courant | **112 alertes dans 23 paquets**; scan pollué par l’environnement global | NON CONCLUANT |
| **E2E Linux/Docker** | Scripts Bash | Non exécutés sur Windows | **Non vérifiés dans cet audit** | NON VÉRIFIÉ |

## 3. Findings

### F-01 — Résolu — Destination SSH permissive par défaut dans le SDK agent

Le SDK exige désormais une capability policy explicite lorsqu’un agent demande un transport SSH, puis vérifie la cible avec l’opération `ssh_transport`. Une policy explicitement wildcard reste volontairement permissive, mais ce choix est désormais visible et contrôlé par l’appelant.

**Vérification :** le refus sans policy explicite et le refus d’une cible hors liste blanche sont couverts par les tests SDK.

**Risque résiduel accepté :** une policy explicitement configurée avec `targets: ["*"]` autorise tous les hôtes accessibles; cette configuration relève de la responsabilité de l’opérateur.

### F-02 — Résolu avec limitation documentée — Transport distant Redis

PostgreSQL, MySQL et Redis utilisent désormais des commandes distantes lorsque `host` est défini. Redis collecte à distance `PING`, latence, mémoire et rôle lorsque la cible ne requiert pas d’authentification. Si un mot de passe est fourni, les sondes dépendantes retournent `UNKNOWN` plutôt que d’exposer le secret.

**Impact résiduel :** Redis authentifié à distance ne peut pas encore être sondé avec les commandes CLI actuelles; l’état `UNKNOWN` doit donc être traité comme bloquant par les politiques exigeantes.

**Vérification :** les sondes distantes et le comportement authentifié sans fuite sont testés. L’ajout d’un transport de secret hors arguments reste une amélioration future, non une autorisation implicite.

### F-03 — Résolu — Secrets dans les observations dependency

Les URLs rendues dans les observations sont nettoyées. Les credentials et paramètres connus comme sensibles sont redigés, et les erreurs de commande utilisent désormais une représentation sûre pour l’affichage.

**Vérification :** tests de redaction des URLs et des erreurs présents.

### F-04 — Résolu — Limite de fraîcheur à la borne exacte

La comparaison utilise maintenant `age >= max_age`, conformément au contrat, et un test de frontière est présent.

**Vérification :** correction couverte par `tests/test_evidence.py`.

### F-05 — Résolu — La mesure de latence peut masquer une violation de SLA

Le provider compare maintenant la latence brute au budget SLA et réserve l’arrondi à l’affichage. Le scénario de dégradation upstream passe avec une latence simulée de 250 ms et un budget de 50 ms.

**Vérification :** correction couverte par `tests/test_data_correlation.py`.

### F-06 — Résolu — Mot de passe Redis dans les arguments de commande distante

Le provider ne construit plus `redis-cli -a <password>`. En mode distant authentifié, il retourne des observations `UNKNOWN` explicites sans transmettre le mot de passe à la commande ou au transport SSH.

**Vérification :** un test confirme que le mot de passe n’apparaît dans aucun argument de commande.

**Limitation documentée :** un mécanisme de secret hors ligne de commande pourra être ajouté ultérieurement pour rétablir les sondes authentifiées à distance.

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
  - Les URLs dependency et les erreurs de commande sont également redigées; les secrets non détectables par motif restent à éviter dans les entrées.
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
  - Le SDK agent exige une capability policy explicite pour tout transport SSH et contrôle la cible via `ssh_transport`.
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

La suite locale compte **197 tests réussis**. La couverture mesurée est de **83%**; la mesure émet aussi des avertissements pour deux modules dynamiques absents du workspace (`broken_dynamic.py` et `dummy_dynamic.py`). Les tests couvrent les chemins locaux et les principaux chemins SSH mockés. Les E2E Linux/Docker restent à exécuter sur un environnement Linux.

Les scripts E2E Linux/Docker existent dans `tests/e2e/`, mais n'ont pas été exécutés dans cet audit sur l'environnement Windows.

---

## 6. Recommandations & Axes d'Amélioration

Les actions prioritaires avant approbation sont :

1. Exécuter les E2E Linux/Docker dans un environnement Linux représentatif.
2. Relancer `pip-audit` dans un environnement virtuel propre et vérifier les dépendances de production séparément des outils de test.
3. Ajouter ultérieurement un transport sécurisé de secret pour les sondes Redis distantes authentifiées.

---

## 7. Conclusion de l'Audit

EvidenceTool présente une base saine: 197 tests passent, Ruff, Mypy et Bandit sont au vert, et les findings F-01, F-03, F-04, F-05 et F-06 sont corrigés. F-02 est traité de manière fail-closed pour Redis authentifié distant. Les validations E2E Linux/Docker et SCA propre restent nécessaires avant une déclaration de release définitive.

**Avis final : approuvable sous réserve de validation E2E Linux/Docker et d’un scan SCA dans un environnement virtuel propre.**
