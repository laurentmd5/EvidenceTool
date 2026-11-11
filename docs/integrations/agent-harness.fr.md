[English](agent-harness.md) | **Français**

# Guide d'Intégration pour Harness d'Agent

EvidenceTool est spécifiquement conçu pour être orchestré en toute sécurité par des agents autonomes. Ce guide définit la manière dont un harness d'agent doit encapsuler EvidenceTool.

## 1. Règle de Fraîcheur des Preuves

Les agents doivent réexécuter EvidenceTool immédiatement avant d'appliquer une action. Toute observation plus ancienne que la valeur `max_age` configurée dans la politique est considérée comme obsolète (*stale*) et doit être re-collectée. Les politiques nécessitant une fenêtre de fraîcheur de 60 secondes doivent déclarer explicitement `max_age: 60`.

Un agent ne doit JAMAIS exécuter une action en se basant sur une décision `ALLOW` antérieure si cette décision repose sur des preuves périmées.

Pour une exécution automatisée, le harness doit fournir une politique explicite de capacités (`capability_policy`). Elle permet de restreindre les opérations réseau, les cibles, les ports, le nombre de sondes autorisées et la confiance accordée aux providers, sans modifier la politique diagnostique qui interprète les preuves. Tout refus de capacité ou appel à un provider non approuvé constitue un échec d'intégrité et doit stopper net l'action de l'agent.

Les providers externes utilisés par un harness automatisé doivent figurer dans un manifeste externe et être vérifiés par leur empreinte SHA-256 avant toute activation. La simple découverte dynamique ne vaut pas approbation.

## 2. Intégration Programmatique via AgentSafetyGate (`evidencetool.agent`)

Les agents IA autonomes peuvent intégrer directement EvidenceTool via `AgentSafetyGate` :

```python
from evidencetool.agent import AgentSafetyGate, AgentDiagnosisRequest

gate = AgentSafetyGate(
    capability_policy="capabilities/agent-restricted.yaml",
    catalog="catalogs/distributed.yaml",
    default_policy="policies/distributed.yaml",
)

request = AgentDiagnosisRequest(
    agent_id="agent-007",
    action="restart_application",
    target="orders-service",
    context={
        "url": "http://127.0.0.1:8080/health",
        "db_host": "127.0.0.1",
        "redis_host": "127.0.0.1",
    }
)

result = gate.evaluate(request)
if result.is_allowed:
    # L'action de remédiation peut se poursuivre en toute sécurité
    pass
else:
    # Action bloquée avec motif causal explicable
    print(f"Action BLOQUÉE : {result.reason}")
    print(f"Cause racine causale : {result.causality.primary_root_cause if result.causality else 'N/A'}")
```

## 3. Intégrité Décisionnelle & Vérification du Contrat JSON

Chaque sortie JSON générée par EvidenceTool respecte `schemas/diagnosis-result.schema.json` et intègre une représentation cryptographiquement stable de la décision.
Les agents DOIVENT valider programmatiquement l'intégrité de la décision avant d'agir sur un `ALLOW` :

```python
import json
import jsonschema
from evidencetool.decision.integrity import validate_decision_integrity

# 1. Validation de conformité au schéma JSON
with open("schemas/diagnosis-result.schema.json") as f:
    schema = json.load(f)
jsonschema.validate(instance=result_dict, schema=schema)

# 2. Validation d'intégrité de la décision
integrity = validate_decision_integrity(result.decision, policy, result.evidence, state=result.incident.state)
if not integrity.is_valid:
    raise SecurityViolation(f"Intégrité de la décision compromise : {integrity.violations}")
```

## 4. Gestion du Verdict HUMAN_REVIEW

Si le moteur retourne `HUMAN_REVIEW`, l'agent DOIT suspendre son exécution et solliciter une validation explicite auprès d'un opérateur humain. Traiter silencieusement un `HUMAN_REVIEW` comme un `ALLOW` viole les invariants fondamentaux de sécurité du contrat produit.

## 5. Traçage Distribué & Auditabilité APM (OpenTelemetry Mode B)

Pour la gouvernance, l'observabilité et la piste d'audit dans les architectures d'agents distribués en entreprise, EvidenceTool exporte nativement des traces distribuées via OTLP/HTTP.

Le harness d'agent peut ainsi corréler ses propres spans de raisonnement LLM avec les spans de diagnostic d'EvidenceTool :

```python
from evidencetool.agent import AgentSafetyGate, AgentDiagnosisRequest
from evidencetool.observability.tracing import DiagnosisTracer

# Optionnel : Instancier un tracer pour diffuser les spans vers Jaeger ou Grafana Tempo
tracer = DiagnosisTracer(
    service_name="agent-safety-gateway",
    endpoint="http://collector.monitoring:4318/v1/traces",
)

result = gate.evaluate(request, tracer=tracer)

# Récupérer l'ID de trace W3C pour l'associer aux journaux d'audit de l'agent
if result.trace_id:
    print(f"Trace ID Distribuée : {result.trace_id}")
    # Visualiser la trace dans l'interface Jaeger :
    # http://jaeger:16686/trace/{result.trace_id}
```

La trace résultante contient :
- `evidencetool.diagnosis` : Span racine taguée avec `evidencetool.authority.caller_id` (`agent_id`) et `session_id`.
- `evidencetool.provider.<namespace>` : Latence et nombre d'observations par sonde d'infrastructure.
- `evidencetool.evaluation` : Répartition des preuves évaluées.
- `evidencetool.correlation` : Hypothèses situationnelles évaluées.
- `evidencetool.causality` : Cause racine primaire et chaîne de propagation causale.
- `evidencetool.decision` : Verdict déterministe (`ALLOW` / `BLOCK`), justification et preuves bloquantes.
