[English](CONTRIBUTING.md) | **Français**

# Contribuer à EvidenceTool

Bienvenue ! Avant de contribuer, veuillez prendre connaissance des invariants stricts de ce projet. La valeur d'EvidenceTool repose sur ses contraintes. Toute Pull Request (PR) violant ces invariants sera rejetée, quelle que soit son utilité apparente.

## Invariants Non-Négociables

1. **Aucun `shell=True`** : Un fournisseur (provider) ne doit jamais construire une commande shell sous forme de chaîne de caractères. Utilisez systématiquement des listes `["commande", "arg"]`. Cela prévient formellement toute vulnérabilité d'injection de commande shell.
2. **Provenance Obligatoire** : Chaque `Observation` doit porter sa provenance : qui l'a collectée, comment, et d'où (`collector`, `method`, `host`).
3. **Décisions Immuables** : Une `Decision` ne doit jamais être modifiée après avoir été émise. Elle ne peut en aucun cas être influencée par une `Recommendation`.
4. **Règle de Précédence** : `BLOCK > HUMAN_REVIEW > ALLOW`. Cette règle est toujours vraie, sans aucune exception.
5. **Fermeture par Défaut en cas d'Incertitude (`Fail-Closed`)** : En mode `V2_SITUATIONAL`, si une preuve est `UNKNOWN` pour une hypothèse évaluée et qu'aucune situation bloquante ne correspond, la situation est ambiguë et le moteur doit refuser l'action par défaut (`BLOCK`).
6. **Incertitude Locale** : L'incertitude est circonscrite à l'hypothèse qu'elle concerne. Une preuve `UNKNOWN` dans un domaine disjoint (ex: Redis) ne doit pas contaminer une décision nette et vérifiée dans le domaine cible (ex: Nginx).
7. **La Panne de Transport n'est pas une Défaillance du Composant** : Les timeouts réseau, réinitialisations de connexion ou erreurs HTTP 403 sur des APIs de sonde (ex: `kubectl`) se dégradent en `UNKNOWN` (`transport_status="failed"`), jamais en défaut physique du composant (`FAIL`). L'absence de preuve n'est pas la preuve d'un échec.
8. **Tests Obligatoires** : Tout nouveau provider ou situation DOIT être accompagné de tests unitaires, de validation de schéma JSON, et le cas échéant, de tests de bout en bout (E2E).

## Environnement de Développement

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
```

Veuillez exécuter `pytest tests/` et vous assurer que tous les contrôles CI passent avec succès avant de soumettre une PR.
