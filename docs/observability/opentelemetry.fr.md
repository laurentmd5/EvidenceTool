[English](opentelemetry.md) | **Français**

# Guide d'Intégration du Tracing Outbound OpenTelemetry (Mode B)

EvidenceTool intègre nativement le **Mode B OpenTelemetry (Tracing Distribué Sortant)** pour projeter son pipeline de raisonnement opérationnel directement dans vos backends d'observabilité tels que **Jaeger**, **Grafana Tempo**, ou des **Collecteurs OpenTelemetry** standards.

```
Application Hôte / Mesh d'Agents IA
      │ (Contexte W3C traceparent)
      ▼
EvidenceTool DiagnosisTracer
      │
      ├── evidencetool.diagnosis (span racine)
      │     ├── evidencetool.provider.<namespace>
      │     ├── evidencetool.evaluation
      │     ├── evidencetool.correlation
      │     ├── evidencetool.causality
      │     └── evidencetool.decision
      │
      ▼
Collecteur OpenTelemetry / Jaeger / Grafana Tempo
```

---

## 1. Invariants Architecturaux Fondamentaux

1. **Invariant d'Indépendance de l'Observabilité** : OpenTelemetry est strictement une couche d'observabilité. Il **NE DOIT EN AUCUN CAS** influencer les décisions diagnostiques, causales, politiques ou d'autorité d'EvidenceTool. Les spans décrivent le raisonnement opérationnel ; ils ne le modifient ni ne le déterminent jamais.
2. **Invariant de Non-Interférence avec le TracerProvider Hôte** : Lorsqu'il s'exécute au sein d'une application hôte déjà instrumentée (ex: framework d'agent IA, service FastAPI, harness LangChain), EvidenceTool obtient son traceur via `trace.get_tracer("evidencetool", "1.0.5")` et **NE MUTILE, N'INSTALLE ET NE RÉINITIALISE JAMAIS** le `TracerProvider` global de l'application hôte.
3. **Invariant de Non-Authentification par le Contexte de Trace** : Un `traceparent` W3C est exclusivement un identifiant de corrélation télémétrique. Il ne porte aucune sémantique d'authentification, d'autorisation ou de capacité, et ne peut en aucun cas contourner `CapabilitySet`, les quotas de sondes ou les empreintes de politique.
4. **Repli Zéro-Dépendance** : Si la bibliothèque `opentelemetry` n'est pas installée, EvidenceTool collecte les spans en mémoire et exporte du standard OTLP/JSON via la bibliothèque standard Python en HTTP ou vers un fichier.
5. **Invariant de Sémantique du Statut de Span** : Les décisions opérationnelles légitimes (`BLOCK`, `HUMAN_REVIEW`, `ALLOW`) constituent des issues de gouvernance nominales et produisent un statut de span OpenTelemetry `StatusCode.OK`. Le statut `StatusCode.ERROR` est strictement réservé aux pannes d'exécution ou d'intégrité (`metrics.success == False`), éliminant ainsi toute fausse alerte APM.
6. **Double Pipeline d'Exportation** : En mode autonome avec `opentelemetry-exporter-otlp-proto-http` installé, EvidenceTool transmet du Protobuf binaire sur HTTP via `OTLPSpanExporter`. En mode sans dépendance, il bascule sans couture sur l'export JSON natif en Python standard.

---

## 2. Propagation de Contexte & Hiérarchie de Précédence

EvidenceTool résout le contexte de trace selon une hiérarchie stricte à 4 niveaux :

| Précédence | Source | Description |
|:---|:---|:---|
| **Niveau 1** | Argument explicite | Passé directement via le SDK (`AgentDiagnosisRequest.traceparent`) ou la CLI (`--traceparent`). |
| **Niveau 2** | Variable `TRACEPARENT` | Variable d'environnement standard W3C traceparent. |
| **Niveau 3** | Span actif de l'hôte | Contexte de span actif récupéré via `otel_trace.get_current_span()`. |
| **Niveau 4** | Trace racine indépendante | Génère un nouvel identifiant de trace 32-hex et démarre une trace racine indépendante. |

> [!NOTE]
> **Règle de Sauvegarde (Fail-Safe)** : Si un agent transmet un `traceparent` malformé ou invalide alors qu'un span hôte est actif dans le contexte d'exécution, EvidenceTool émet un avertissement dans les logs et se rattache en enfant du span hôte actif au lieu de s'isoler dans une trace déconnectée.

---

## 3. Référence de Configuration

### Variables d'Environnement

| Variable | Description | Défaut |
|:---|:---|:---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Point de terminaison traces OTLP/HTTP (ex: `http://localhost:4318/v1/traces`) | `None` |
| `OTEL_SERVICE_NAME` | Nom logique du service émettant la trace de diagnostic | `evidencetool` |
| `TRACEPARENT` | Chaîne conforme au standard W3C traceparent | `None` |
| `OTEL_ENABLE_TRACING` | Définir à `true` ou `1` pour forcer le traçage même sans endpoint explicite | `false` |

### Utilisation en Ligne de Commande (CLI)

```bash
# Exporter la trace directement vers un collecteur OpenTelemetry local ou distant
evidencetool diagnose nginx \
  --otel-endpoint http://localhost:4318/v1/traces

# Continuer une trace distribuée existante depuis un appelant amont
evidencetool diagnose nginx \
  --traceparent 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01 \
  --otel-endpoint http://localhost:4318/v1/traces

# Sauvegarder la trace localement dans un fichier JSON pour inspection hors-ligne ou artéfacts CI
evidencetool diagnose nginx \
  --otel-trace-file /tmp/diagnosis_trace.json
```

---

## 4. Intégration dans le SDK d'Agent IA

Les agents autonomes transmettent leur contexte de trace W3C dans `AgentDiagnosisRequest` :

```python
from evidencetool.agent import AgentSafetyGate, AgentDiagnosisRequest

gate = AgentSafetyGate(
    capability_policy="capabilities/agent-restricted.yaml",
    catalog="catalogs/distributed.yaml",
    default_policy="policies/distributed.yaml",
)

# L'agent crée une demande de diagnostic rattachée à son workflow distribué
request = AgentDiagnosisRequest(
    agent_id="remediation-agent-01",
    action="restart_application",
    target="orders-service",
    context={"url": "http://127.0.0.1:8080/health"},
    traceparent="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
)

result = gate.evaluate(request)

# L'ID de trace est accessible directement sur le résultat d'évaluation
print(f"Décision : {result.status}, Trace ID : {result.trace_id}")
```

---

## 5. Test Local avec Jaeger & Collecteur OTel (Docker Compose)

Enregistrez la configuration suivante sous le nom `docker-compose.otel.yaml` :

```yaml
version: "3.8"
services:
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686" # Interface Web Jaeger
      - "4317:4317"   # Récepteur OTLP gRPC
      - "4318:4318"   # Récepteur OTLP HTTP
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

Démarrer Jaeger :
```bash
docker compose -f docker-compose.otel.yaml up -d
```

Lancer un diagnostic avec exportation des traces vers Jaeger :
```bash
evidencetool diagnose nginx \
  -a service=nginx \
  --otel-endpoint http://localhost:4318/v1/traces
```

Ouvrez `http://localhost:16686` dans votre navigateur pour inspecter l'arbre complet de raisonnement opérationnel (`evidencetool.diagnosis`, `evidencetool.provider.*`, `evidencetool.causality`, et `evidencetool.decision`).
