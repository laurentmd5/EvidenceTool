[English](hybrid-causal-reasoning.md) | **Français**

# Mode C : Guide du Raisonnement Causal Hybride & Durcissement Causal

EvidenceTool intègre le **Mode C (Raisonnement Causal Hybride)** pour relier la télémétrie de surface de haut niveau aux preuves physiques profondes du système, au moyen de graphes orientés acycliques (DAG) déclaratifs et déterministes.

```
             MODE A : Télémétrie Externe (Prometheus / Tempo)
                                   │
                                   ▼
                         Symptômes de Surface
                    (ex: HTTP_ERROR_RATE_HIGH)
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   MODE C : MOTEUR CAUSAL HYBRIDE                       │
│                                                                        │
│   Relations Causales Déclaratives :                                    │
│     - PROPAGATES_TO :  A ──> B (Propagation causale)                   │
│     - PRECLUDES     :  A ──/──> B (Réfutation / exclusion mutuelle)    │
│     - REQUIRES      :  A <──req── B (Condition préalable)              │
│                                                                        │
│   Détection de Cycles & Validation (Précède l'Arbitrage)               │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   ▲
                                   │
             Sondes Physiques Natives (Sockets, DB, Noyau Linux)
                     (ex: POSTGRES_POOL_EXHAUSTED)
                                   │
                                   ▼
                   Cause Racine Primaire & Verrou d'Action
                       (BLOCK > HUMAN_REVIEW > ALLOW)
```

---

## 1. Philosophie Architecturale & Les Trois Piliers

EvidenceTool impose une séparation stricte et étanche entre trois piliers fondamentaux :
1. **Preuve (Observation)** : Que constate-t-on ? (Faits vérifiables collectés avec zéro effet de bord).
2. **Causalité (Explication)** : Qu'est-ce qui peut expliquer quoi ? (Parcours de graphe déterministe basé exclusivement sur des règles déclaratives).
3. **Autorité (Gouvernance)** : Qu'est-ce que le système a le droit de faire ? (Politiques déterminant `ALLOW`, `BLOCK` ou `HUMAN_REVIEW`).

> [!IMPORTANT]
> **Invariant Fondateur** : *« Plus d'observations. Plus de preuves. Jamais plus d'autorité. »*  
> La télémétrie révèle le symptôme de surface ; les sondes physiques confirment ou réfutent les causes racines candidates.  
> **Aucune causalité n'est implicite. Aucune supposition n'est tolérée. L'ambiguïté est préservée.**

---

## 2. Primitives Déclaratives du Graphe Causal

Toutes les relations causales sont définies dans des catalogues YAML déclaratifs (ex: `causality/distributed.yaml`, `causality/telemetry.yaml`), jamais codées en dur dans le code Python.

### Types de Relations

| Relation | Notation | Sémantique |
|:---|:---|:---|
| `PROPAGATES_TO` | `A -> B` | L'incident `A` provoque ou se manifeste par le symptôme aval `B`. |
| `PRECLUDES` | `A --/--> B` | La preuve confirmant `A` réfute et élimine explicitement l'hypothèse `B`. |
| `REQUIRES` | `A <-req- B` | L'hypothèse `A` ne peut être confirmée que si le prérequis `B` s'évalue à `PASS`. |

### Sémantique des Prérequis (`REQUIRES`)

```
REQUIRES(Prérequis B)
     │
     ├── B = PASS     ──> L'hypothèse A peut être évaluée normalement
     ├── B = UNKNOWN  ──> L'hypothèse A devient UNRESOLVED (manque d'évidence)
     └── B = FAIL     ──> L'hypothèse A devient PRECLUDED (réfutée explicitement)
```

---

## 3. États Déterministes des Candidats Causaux

Chaque candidat causal évalué est classé dans un état formel :

- **`CONFIRMED`** : Prouvé par des signatures physiques positives sans préclusion réfutante.
- **`POSSIBLE`** : Hypothèse plausible conservée lorsque plusieurs causes coexistent sans hiérarchie déclarée.
- **`UNRESOLVED`** : Candidat correspondant au symptôme mais bloqué par des prérequis manquants ou à l'état `UNKNOWN`.
- **`PRECLUDED`** : Candidat explicitement éliminé suite au déclenchement d'une règle `PRECLUDES` ou à l'échec d'un prérequis `REQUIRES`.

---

## 4. Invariants de Durcissement (C1 à C13)

Le moteur causal applique 13 invariants stricts validés par des tests adversaires automatisés :

### C1 — Cause Racine Unique Confirmée
Lorsqu'une preuve physique confirme une cause racine unique $A$ propageant vers le symptôme $S$, $A$ est désignée `primary_root_cause` (`ROOT_CAUSE_IDENTIFIED`) et la chaîne complète $[A, \dots, S]$ est reconstruite.

### C2 — Cause Racine Inconnue / Non Résolue
Lorsque la preuve de la cause candidate $A$ s'évalue à `UNKNOWN`, $A$ est marquée `UNRESOLVED`. Le système renvoie `primary_root_cause = None` (`ROOT_CAUSE_UNKNOWN`).

### C3 — Causes Racines Multiples Concurrentes
Lorsque plusieurs causes indépendantes sont confirmées sans ordre de priorité déclaré, aucun arbitrage arbitraire n'est réalisé. Le statut devient `ROOT_CAUSE_CONSTRAINED` et tous les candidats sont conservés en `POSSIBLE`.

### C4 — Hypothèse Préclue (Réfutation)
Lorsqu'une règle active réfute le candidat $A$, celui-ci est consigné dans `precluded_hypotheses` et exclu des causes candidates.

### C5 — Isolation de l'Incertitude par Sous-Graphe
L'incertitude (`UNKNOWN`) est strictement circonscrite à son sous-graphe causal. Une sonde manquante sur un composant disjoint (ex: certificat TLS) ne contamine jamais une cause confirmée indépendamment (ex: épuisement de pool PostgreSQL).

### C6 — Absence de Causalité Non Déclarée
En l'absence de règle explicite liant deux composants, aucune causalité n'est inférée, même si les deux composants sont en échec simultané.

### C7 — Détection de Cycles Préalable à l'Arbitrage
La validation du graphe **DOIT précéder** l'arbitrage causal.  
Si les règles contiennent des dépendances circulaires ($A \to B \to A$), le moteur détecte tous les cycles, les consigne dans `cycles_detected` et bascule en `ROOT_CAUSE_CONSTRAINED` sans lever d'exception non gérée.

### C8 — Complétude et Ordre des Chaînes Longues
Pour une chaîne profonde ($A \to B \to C \to D \to S$), la reconstruction garantit une complétude à 100% et un ordre topologique strict $[A, B, C, D, S]$.

### C9 — Arbitrage par Priorité Explicite
Lorsque plusieurs racines sont confirmées, des entiers de priorité explicites déclarés dans le catalogue (`priority: 20 > priority: 10`) permettent un arbitrage déterministe.

### C9b — Invariant d'Égalité de Priorité (Priority Tie)
Lorsque des causes candidates partagent exactement la même priorité maximale, **aucun départage arbitraire** (ordre alphabétique, adresse mémoire ou ordre de hachage) n'est toléré. Le statut se replie sur `ROOT_CAUSE_CONSTRAINED` et tous les candidats à égalité restent `POSSIBLE`.

### C10 — Préservation de l'Ambiguïté Non Classée
Les candidats sans priorité déclarée (`priority: 0`) sont préservés sans élimination hasardeuse.

### C11 — `REQUIRES` + `UNKNOWN` $\implies$ `UNRESOLVED`
Si une sonde prérequise est indisponible ou `UNKNOWN`, l'hypothèse dépendante est rétrogradée en `UNRESOLVED`.

### C12 — `REQUIRES` + `FAIL` $\implies$ `PRECLUDED`
Si une sonde prérequise indispensable échoue, l'hypothèse dépendante est explicitement réfutée, ajoutée à `precluded_hypotheses` et disqualifiée. À noter que `PRECLUDED` est un statut d'exclusion consigné dans `precluded_hypotheses` ; ce n'est pas un état de `CausalCandidateState` actif (qui demeurent `CONFIRMED`, `POSSIBLE`, `UNRESOLVED`).

### C13 — Signaux Disjoints et Causalité Nulle
Des sondes en échec dans des domaines distincts sans lien déclaré produisent `ROOT_CAUSE_UNKNOWN` et une chaîne causale vide.

### C14 — Isolation du Sous-Graphe Causal & Atteignabilité (H1)
Tout nœud figurant dans `causal_chain` ou `propagated_symptoms` doit appartenir strictement au sous-graphe orienté atteignable de la cause racine primaire. Les symptômes issus de composants distincts ou non confirmés ne doivent jamais polluer l'explication causale de la racine.

### C15 — Sémantique de Chemin Causal Continu & Graphe Ramifié (H2)
`causal_chain` représente un chemin orienté unique, valide et contigu $[v_0, v_1, \dots, v_k]$ où chaque transition adjacente $(v_i, v_{i+1})$ correspond à une arête directe déclarée ($v_i \longrightarrow v_{i+1}$). Dans un graphe ramifié ($A \longrightarrow B \longrightarrow S$ et $A \longrightarrow C \longrightarrow S$), les concaténations de nœuds formant des transitions inexistantes ($[A, B, C, S]$) sont proscrites. Le BFS parcourt les voisins ordonnés par priorité d'arêtes (assurant un nombre minimal de sauts) ; `_build_causal_chain` sélectionne ensuite parmi les chemins candidats en évaluant la profondeur du chemin, la somme des priorités d'arête et un départage lexicographique strict.

### C16 — Préservation des Règles Multiples par Source (H3)
Plusieurs règles de propagation issues du même nœud source ($A \longrightarrow B$ et $A \longrightarrow C$) sont conservées sans écrasement. La priorité du candidat racine évalue le maximum des priorités déclarées sur ses règles sortantes.

### C17 & C18 — Validation Fail-Closed des Catalogues (H4)
Le parseur de catalogues impose obligatoirement les champs non vides `id`, `source`, `target` et `relation`. Les fautes de frappe (ex: `PROPAGATSE_TO`) lèvent immédiatement une `ValueError`. La conversion silencieuse vers une relation par défaut est strictement interdite.

### C19 — Graphe Ramifié avec Symptôme Externe Disjoint (H1 + H2)
Lorsqu'une topologie ramifiée coexiste avec des symptômes externes non reliés, l'atteignabilité garantit que seuls les nœuds du chemin causal actif vers les symptômes atteignables sont inclus. Les symptômes externes sont totalement exclus.

### C20–C23 — Zéro Coercition Silencieuse dans le Parseur de Catalogues (H4.1)
Le parseur YAML (`loader.py`) rejette toute priorité non entière (C20), toute condition mal formée ou non analysable (C21), tout drapeau non booléen (C22), ou toute entrée de règle non dictionnaire (C23) avec une `ValueError`. Aucune coercition silencieuse de type ou présomption implicite n'est admise.

---

## 5. Contrat JSON Lisible par Machine

Le résultat produit par le moteur causal respecte rigoureusement `schemas/diagnosis-result.schema.json` :

```json
{
  "causality": {
    "status": "ROOT_CAUSE_IDENTIFIED",
    "primary_root_cause": "POSTGRES_POOL_EXHAUSTED",
    "target_situation": "SERVICE_ERROR_RATE_EXCEEDED",
    "causal_chain": [
      "POSTGRES_POOL_EXHAUSTED",
      "DATABASE_QUERY_DEADLOCK",
      "SERVICE_ERROR_RATE_EXCEEDED"
    ],
    "candidate_causes": [
      {
        "id": "POSTGRES_POOL_EXHAUSTED",
        "state": "CONFIRMED",
        "causal_path": ["POSTGRES_POOL_EXHAUSTED", "SERVICE_ERROR_RATE_EXCEEDED"],
        "missing_evidence": [],
        "description": "Le pool de connexions PostgreSQL est saturé"
      }
    ],
    "precluded_hypotheses": [
      {
        "id": "APPLICATION_DATABASE_QUERY_DEADLOCK",
        "reason": "Required prerequisite network.database_port_reachable evaluated to FAIL"
      }
    ],
    "unresolved_hypotheses": [],
    "cycles_detected": []
  }
}
```

---

## 6. Exemple de Déclaration de Catalogue Causal

```yaml
version: "1.0"
namespace: distributed_causality

rules:
  - from: POSTGRES_POOL_EXHAUSTED
    to: SERVICE_ERROR_RATE_EXCEEDED
    type: PROPAGATES_TO
    priority: 20
    description: "L'épuisement du pool PostgreSQL provoque une cascade d'erreurs HTTP 500"

  - from: DATABASE_PORT_CLOSED
    to: POSTGRES_POOL_EXHAUSTED
    type: PRECLUDES
    description: "Si le port TCP est fermé, l'épuisement du pool applicatif est réfuté"

  - from: APPLICATION_DATABASE_QUERY_DEADLOCK
    to: network.database_port_reachable
    type: REQUIRES
    description: "Le diagnostic de deadlock exige que l'accessibilité réseau soit à PASS"
```
