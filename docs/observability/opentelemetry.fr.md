[English](opentelemetry.md) | **Français**

# Guide d'Intégration OpenTelemetry (Mode A Inbound & Mode B Outbound)

EvidenceTool fournit une intégration bidirectionnelle native avec OpenTelemetry, formant une boucle fermée de confiance opérationnelle :
- **Mode A (Télémétrie Externe Entrante / Inbound)** : Ingère les métriques de surface et la santé des traces distribuées depuis les backends compatibles Prometheus et Tempo/Jaeger via le provider natif `otel`.
- **Mode B (Traçage Distribué Sortant / Outbound)** : Émet des spans OpenTelemetry structurés et corrélés au standard W3C, projetant l'intégralité du pipeline de raisonnement causal et de décision dans votre APM.

```
┌────────────────────────────────────────────────────────────────────────┐
│                   MODE A : TÉLÉMÉTRIE EXTERNE ENTRANTE                 │
│    Requête Prometheus (Métriques/Latence) & Tempo/Jaeger (Erreurs)     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Symptômes de surface
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   MODE C : RAISONNEMENT CAUSAL HYBRIDE                 │
│    Corrèle les symptômes de surface avec les sondes physiques natives  │
│    (Pool Postgres, OOM Redis, Expiration TLS, Deadlock Process)        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Décision Déterministe
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   MODE B : TRAÇAGE DISTRIBUÉ SORTANT                   │
│    Émet la trace de diagnostic corrélée W3C (Spans racine + enfants)   │
│    Envoyée au Collecteur OpenTelemetry / Jaeger / Grafana Tempo        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Mode A : Fournisseur de Télémétrie Entrante (`otel`)

Le provider `otel` permet à EvidenceTool d'observer les signaux de télémétrie externe sans devenir un second outil de monitoring. Il collecte strictement des faits observables et délègue l'évaluation des seuils aux politiques déclaratives.

### Sondes Supportées

| Identifiant Sonde | Backend Cible | Métrique / Requête | Condition Évaluée |
|:---|:---|:---|:---|
| `otel.metrics_reachable` | Prometheus / Mimir / Thanos | `/api/v1/query?query=1` | Le backend de métriques est joignable et répond. |
| `otel.traces_reachable` | Grafana Tempo / Jaeger | `/api/traces?limit=1` | Le backend de traces est joignable et répond. |
| `otel.http_error_rate_high` | Prometheus / Mimir | Requête PromQL (ex: taux 5xx > seuil) | Taux d'erreur HTTP élevé observé sur le service cible. |
| `otel.p99_latency_high` | Prometheus / Mimir | Requête PromQL percentile histogramme | La latence P99 dépasse le seuil de budget SLA configuré. |
| `otel.active_traces_failing` | Grafana Tempo / Jaeger | Requête de traces avec filtre `status=error` | Les traces distribuées actives contiennent des spans en erreur. |

### Invariants de Sécurité & d'Opération (Mode A)

1. **Invariant de Pure Observation** : Le provider collecte uniquement des faits observables ; il ne prend aucune décision diagnostique et ne remplace pas les sondes physiques.
2. **Défense Anti-SSRF** : Les adresses cibles doivent se résoudre en adresses IP publiques valides, sauf si elles sont explicitement autorisées dans `CapabilitySet.network.targets` (protection contre les attaques SSRF ciblant les métadonnées cloud `169.254.169.254` ou les services internes).
3. **Limites de Transport Strictes** :
   - Les redirections HTTP sont refusées (`allow_redirects=False`).
   - La taille de charge utile de réponse est bornée à 1 Mo (`MAX_PAYLOAD_BYTES = 1048576`).
   - Le timeout réseau est strictement appliqué (`timeout_seconds = 5`).
4. **Désensibilisation des Identifiants** : Les jetons Bearer et identifiants Basic Auth transmis en arguments ou variables d'environnement sont masqués (`***`) dans les logs et preuves exportées.

### Exemple CLI (Mode A)

```bash
evidencetool diagnose dependency \
  --catalog catalogs/telemetry.yaml \
  --policy policies/telemetry.yaml \
  -a otel_metrics_endpoint=http://prometheus.monitoring:9090 \
  -a otel_traces_endpoint=http://tempo.monitoring:3200 \
  -a service=checkout-service
```

---

## 2. Mode B : Traçage Distribué Sortant

EvidenceTool émet des traces OpenTelemetry structurées cartographiant l'intégralité de son pipeline décisionnel :

```
Application Hôte / Mesh d'Agents IA
      │ (Contexte W3C traceparent)
      ▼
EvidenceTool DiagnosisTracer
      │
      ├── evidencetool.diagnosis (span racine)
      │     ├── evidencetool.provider.<namespace> (latence de collecte et volume)
      │     ├── evidencetool.evaluation (répartition PASS / FAIL / UNKNOWN)
      │     ├── evidencetool.correlation (correspondance de situations)
      │     ├── evidencetool.causality (cause racine, propagation DAG, préclusions)
      │     └── evidencetool.decision (verdict, règles de politique, preuves bloquantes)
      │
      ▼
Collecteur OpenTelemetry / Jaeger / Grafana Tempo
```

### Invariants Architecturaux Cœur (Mode B)

1. **Indépendance de l'Observabilité** : OpenTelemetry est strictement une couche d'observabilité. Il ne doit **JAMAIS** influencer les décisions diagnostiques, causales, politiques ou d'autorité.
2. **Non-Interférence avec le TracerProvider Hôte** : Lorsqu'il s'exécute au sein d'une application déjà instrumentée (ex: framework d'agent IA, FastAPI, LangChain), EvidenceTool obtient son traceur via `trace.get_tracer("evidencetool", "1.0.6")` et **NE MODIFIE, N'INSTALLE ET NE RÉINITIALISE JAMAIS** le `TracerProvider` global de l'hôte.
3. **Non-Authentification du Contexte de Trace** : Un en-tête `traceparent` W3C est un identifiant de corrélation télémétrique. Il ne porte aucun droit d'authentification ou d'autorisation et ne peut contourner le `CapabilitySet` ou les empreintes de politique.
4. **Repli Zéro-Dépendance** : Si le paquet `opentelemetry` n'est pas installé, EvidenceTool accumule les spans en mémoire et les exporte au format standard OTLP/JSON via le module HTTP standard de Python ou dans un fichier.
5. **Sémantique des Statuts de Spans** : Les décisions opérationnelles légitimes (`BLOCK`, `HUMAN_REVIEW`, `ALLOW`) sont des résultats normaux de gouvernance et produisent un statut de span `StatusCode.OK`. Le statut `StatusCode.ERROR` est réservé exclusivement aux échecs d'exécution ou d'intégrité (`metrics.success == False`), évitant les fausses alertes APM.

---

## 3. Hiérarchie de Propagation du Contexte

EvidenceTool résout le contexte de trace selon une priorité stricte en 4 niveaux :

| Priorité | Source | Description |
|:---|:---|:---|
| **Niveau 1** | Argument explicite | Passé via le SDK (`AgentDiagnosisRequest.traceparent`) ou la CLI (`--traceparent`). |
| **Niveau 2** | Variable `TRACEPARENT` | Variable standard W3C d'environnement. |
| **Niveau 3** | Span actif de l'hôte | Contexte du span en cours récupéré via `otel_trace.get_current_span()`. |
| **Niveau 4** | Trace racine indépendante | Génère un nouvel identifiant hexadécimal de 32 caractères et enregistre une trace racine autonome. |

---

## 4. Référence de Configuration

### Variables d'Environnement

| Variable | Description | Valeur par Défaut |
|:---|:---|:---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Point de terminaison traces OTLP/HTTP (ex: `http://localhost:4318/v1/traces`) | `None` |
| `OTEL_SERVICE_NAME` | Nom logique du service émettant la trace | `evidencetool` |
| `TRACEPARENT` | Chaîne conforme W3C traceparent | `None` |
| `OTEL_ENABLE_TRACING` | Mettre à `true` ou `1` pour activer le traçage même sans endpoint explicite | `false` |

### Utilisation en Ligne de Commande (CLI)

```bash
# Exporter la trace directement vers un collecteur OpenTelemetry
evidencetool diagnose nginx \
  --otel-endpoint http://localhost:4318/v1/traces

# Poursuivre une trace distribuée existante (W3C traceparent)
evidencetool diagnose nginx \
  --traceparent 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01 \
  --otel-endpoint http://localhost:4318/v1/traces

# Écrire la trace dans un fichier JSON local pour audit ou artefacts CI
evidencetool diagnose nginx \
  --otel-trace-file /tmp/diagnosis_trace.json
```

---

## 5. Intégration dans le SDK d'un Agent IA

Les agents autonomes transmettent leur contexte de trace W3C dans `AgentDiagnosisRequest` :

```python
from evidencetool.agent import AgentSafetyGate, AgentDiagnosisRequest

gate = AgentSafetyGate(
    capability_policy="capabilities/agent-restricted.yaml",
    catalog="catalogs/distributed.yaml",
    default_policy="policies/distributed.yaml",
)

# L'agent crée une requête de diagnostic liée à sa trace distribuée
request = AgentDiagnosisRequest(
    agent_id="remediation-agent-01",
    action="restart_application",
    target="orders-service",
    context={"url": "http://127.0.0.1:8080/health"},
    traceparent="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
)

result = gate.evaluate(request)

# L'identifiant de trace est accessible directement sur le résultat
print(f"Décision : {result.status}, Trace ID : {result.trace_id}")
```

---

## 6. Recette Docker Compose (Jaeger + OTel Collector)

Enregistrez ce fichier sous `docker-compose.otel.yaml` :

```yaml
version: "3.8"
services:
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686" # Interface Web Jaeger
      - "4317:4317"   # Récepteur gRPC OTLP
      - "4318:4318"   # Récepteur HTTP OTLP
    environment:
      - COLLECTOR_OTLP_ENABLED=true

  otel-collector:
    image: otel/opentelemetry-collector-contrib:latest
    command: ["--config=/etc/otel-collector-config.yaml"]
    volumes:
      - ./otel-collector-config.yaml:/etc/otel-collector-config.yaml
    ports:
      - "4318"        # Récepteur HTTP
    depends_on:
      - jaeger
```

Démarrer l'infrastructure :
```bash
docker compose -f docker-compose.otel.yaml up -d
```

Exécuter un diagnostic avec transmission des traces à Jaeger :
```bash
evidencetool diagnose nginx \
  -a service=nginx \
  --otel-endpoint http://localhost:4318/v1/traces
```

Accédez à `http://localhost:16686` pour visualiser le parcours complet de décision opérationnelle.
