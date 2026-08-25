# Rapport d'Analyse — Typologie des Incidents de Production Diagnostiqués par EvidenceTool (v0.5.0)

**Date** : 25 Août 2026  
**Version** : `v0.5.0` (Branche `dev`)  
**Périmètre** : 7 Providers Opérationnels (`docker`, `nginx`, `tls`, `systemd`, `filesystem`, `network`, `process`)

---

## 1. Vue d'Ensemble & Positionnement

EvidenceTool est un moteur de diagnostic factuel en lecture seule (*Read-Only Operational Evidence Engine*). Il ne prend pas d'initiative hasardeuse : **il collecte des preuves vérifiables, corrèle les états du système, identifie la cause racine parmi un catalogue de situations et décide si une action corrective est sûre (`ALLOW`), interdite (`BLOCK`), ou requiert un arbitrage (`HUMAN_REVIEW`)**.

```
                   ┌──────────────────────────────────────────────┐
                   │           7 PROVIDERS D'OBSERVATION          │
                   │  (docker, nginx, tls, systemd, fs, net, proc)│
                   └──────────────────────┬───────────────────────┘
                                          │
                                          ▼
                   ┌──────────────────────────────────────────────┐
                   │    CORRÉLATION & SIGNATURES DE SITUATIONS    │
                   │  (13 Situations formelles multi-domaines)    │
                   └──────────────────────┬───────────────────────┘
                                          │
                                          ▼
                   ┌──────────────────────────────────────────────┐
                   │             DÉCISION OPÉRATIONNELLE          │
                   │   BLOCK > HUMAN_REVIEW > ALLOW (+ Advisory)  │
                   └──────────────────────────────────────────────┘
```

---

## 2. Typologie des Incidents Diagnostiqués par Domaine

### A. Incidents Web & Reverse Proxy (Nginx)

| Incident de Production | Symptôme Observé | Preuves & Détection Technique | Décision & Règle de Sécurité |
| :--- | :--- | :--- | :---: |
| **Erreur de Syntaxe de Configuration** | Nginx refuse de démarrer après modification de `nginx.conf` ou d'un vhost. | Probe `nginx.config_valid` via `nginx -t -c <path>`. Analyse le code retour et filtre les faux positifs (droits de logs). | 🛑 **BLOCK** (`NGINX_CONFIG_INVALID`)<br>Empêche tout redémarrage en boucle. |
| **Service Inactif / Tombé Sans Panne de Config** | Le service Nginx est arrêté alors que tout le système est nominal. | `systemd.service_active: FAIL` + `nginx.config_valid: PASS` + `tls.*: PASS` + `fs.disk: PASS`. | 🟢 **ALLOW** (`NGINX_SERVICE_DOWN`)<br>Redémarrage autorisé (`restart_nginx`). |
| **Service Non Installé / Manquant** | Demande de redémarrage d'un service inexistant ou désinstallé. | `systemd.service_exists: FAIL` via `systemctl show -p LoadState`. | 🛑 **BLOCK** (`NGINX_SERVICE_NOT_INSTALLED`) |

---

### B. Incidents Cryptographiques & Sécurité TLS / SSL

| Incident de Production | Symptôme Observé | Preuves & Détection Technique | Décision & Règle de Sécurité |
| :--- | :--- | :--- | :---: |
| **Certificat Expiré** | Erreurs SSL/TLS côté clients (`SEC_ERROR_EXPIRED_CERTIFICATE`). | Probe `tls.certificate_valid` extrait les dates de validité (`not_valid_after_utc`) via `cryptography.x509` / `openssl`. | 🛑 **BLOCK** (`TLS_CERTIFICATE_EXPIRED`)<br>Un restart ne réparera pas un cert expiré. |
| **Désynchronisation Clé Privée / Certificat (Mismatch)** | Nginx échoue au boot : `SSL_CTX_use_PrivateKey_file failed: key values mismatch`. | Probe `tls.key_matches_certificate` extrait les clés publiques universelles (`openssl x509 -pubkey` vs `openssl pkey -pubout`) compatibles RSA, ECDSA, Ed25519. | 🛑 **BLOCK** (`TLS_KEY_MISMATCH`) |
| **Fichier Certificat ou Clé Manquant** | Déploiement incomplet ou chemin erroné. | Probes `tls.certificate_exists` et `tls.private_key_exists`. | 🛑 **BLOCK** (`TLS_CERTIFICATE_MISSING`, `TLS_KEY_MISSING`) |

---

### C. Incidents de Conteneurisation & Microservices (Docker)

| Incident de Production | Symptôme Observé | Preuves & Détection Technique | Décision & Règle de Sécurité |
| :--- | :--- | :--- | :---: |
| **Boucle de Crash Infinie (CrashLoopBackOff)** | Conteneur configuré avec `--restart=always` qui crashe en continu. | Probe `container.restarting: FAIL` (`State.Restarting == true`). Extraction des logs d'erreur masqués. | 🟢 **ALLOW** (`CONTAINER_CRASH_LOOP`)<br>Autorise l'investigation et restart. |
| **Échec de Healthcheck Applicatif** | L'application ne répond plus ou est en deadlock interne. | Probe `container.health: FAIL` (`State.Health.Status == 'unhealthy'`). | 🟢 **ALLOW** (`CONTAINER_UNHEALTHY`) |
| **Arrêt / Crash Inattendu (Conteneur Éteint)** | Conteneur à l'arrêt (`Exited`). | Probe `container.exists: PASS` et `container.running: FAIL`. | 🟢 **ALLOW** (`CONTAINER_STOPPED`) |
| **Conteneur Tué par OOM (Out Of Memory)** | Processus tué subitement par le noyau Linux par manque de RAM. | Probe `container.exit_code` inspecte `State.OOMKilled == true` et extrait la stack trace mémoire. | 🟢 **ALLOW** (avec avertissement OOM dans la recommandation) |
| **Conteneur Inexistant ou Supprimé** | Ciblage d'un conteneur inexistant sur l'hôte Docker. | Probe `container.exists: FAIL`. | 🛑 **BLOCK** (`CONTAINER_NOT_FOUND`) |
| **Action Injustifiée sur Conteneur Sain** | Tentative de redémarrer un conteneur qui tourne parfaitement. | `container.running: PASS` + `container.health: PASS` + `exit_code: 0`. | 🛑 **BLOCK** (Action non autorisée car inutile). |

---

### D. Incidents Système, Processus & Filesystem

| Incident de Production | Symptôme Observé | Preuves & Détection Technique | Décision & Règle de Sécurité |
| :--- | :--- | :--- | :---: |
| **Saturation / Disque Plein** | Incapacité d'écrire des logs ou des bases de données. | Probe `filesystem.disk_space_available` et `filesystem.disk_pressure` via `statvfs` / `df -k`. | 🛑 **BLOCK** (`DISK_FULL`, `DISK_PRESSURE`)<br>Bloque l'action pour éviter corruption de données. |
| **Processus Crashé / Absent** | Démon Linux arrêté en tâche de fond. | Probe `process.running: FAIL` via scan de la table des processus (`pgrep -f` / `ps`). | 🛑 **BLOCK** (`PROCESS_CRASHED`) ou déclenchement de remédiation. |
| **Processus Zombies dans le Noyau** | Fuite de descripteurs / processus parents qui ne font pas de `wait()`. | Probe `process.zombie: FAIL` détecte l'état `Z` (defunct) dans `/proc`. | ⚠️ Alerte de dégradation système. |

---

### E. Incidents Réseau, Connectivité & Résolution DNS

| Incident de Production | Symptôme Observé | Preuves & Détection Technique | Décision & Règle de Sécurité |
| :--- | :--- | :--- | :---: |
| **Panne de Connectivité Hôte / Réseau** | Machine cible injoignable ou coupure réseau. | Probe `network.host_reachable: FAIL` via ICMP ping et test d'adressabilité. | 🛑 **BLOCK** (`NETWORK_UNREACHABLE`) |
| **Port TCP Fermé / Bloqué par Firewall** | Service distant non à l'écoute ou filtré par règles iptables/security group. | Probe `network.port_reachable: FAIL` via socket TCP syn/ack. | ⚠️ Détection précise du port en échec. |
| **Panne de Résolution DNS** | Dépendance ou nom d'hôte non résolu. | Probe `network.dns_resolvable: FAIL` via `getaddrinfo` / `getent hosts`. | 🛑 **BLOCK** (Empêche les requêtes dans le vide). |

---

## 3. Matrice des 13 Situations Formelles Actuelles

| ID Situation | Description Fonctionnelle | Signature Technique | Décision Métier par Défaut |
| :--- | :--- | :--- | :---: |
| `NGINX_SERVICE_DOWN` | Nginx inactif mais sain (config, TLS, disque OK). | `systemd.service_active=FAIL`, all others=PASS | 🟢 **ALLOW** |
| `NGINX_CONFIG_INVALID` | Erreur de syntaxe dans la configuration. | `nginx.config_valid=FAIL` | 🛑 **BLOCK** |
| `NGINX_SERVICE_NOT_INSTALLED` | Service systemd absent de la machine. | `systemd.service_exists=FAIL` | 🛑 **BLOCK** |
| `TLS_CERTIFICATE_MISSING` | Fichier de certificat introuvable. | `tls.certificate_exists=FAIL` | 🛑 **BLOCK** |
| `TLS_CERTIFICATE_EXPIRED` | Certificat dont la date de fin de validité est dépassée. | `tls.certificate_valid=FAIL` | 🛑 **BLOCK** |
| `TLS_KEY_MISSING` | Fichier de clé privée introuvable. | `tls.private_key_exists=FAIL` | 🛑 **BLOCK** |
| `TLS_KEY_MISMATCH` | Clé privée ne correspondant pas à la clé publique du cert. | `tls.key_matches_certificate=FAIL` | 🛑 **BLOCK** |
| `DISK_FULL` | Espace disque inférieur au seuil minimum. | `filesystem.disk_space_available=FAIL` | 🛑 **BLOCK** |
| `DISK_PRESSURE` | Espace disque critique (>90% saturé). | `filesystem.disk_pressure=FAIL` | 🛑 **BLOCK** |
| `NETWORK_UNREACHABLE` | Hôte réseau ou IP cible non joignable. | `network.host_reachable=FAIL` | 🛑 **BLOCK** |
| `CONTAINER_STOPPED` | Conteneur Docker éteint. | `container.exists=PASS`, `container.running=FAIL` | 🟢 **ALLOW** |
| `CONTAINER_CRASH_LOOP` | Conteneur en boucle infinie de redémarrage. | `container.restarting=FAIL` | 🟢 **ALLOW** |
| `CONTAINER_UNHEALTHY` | Conteneur en cours d'exécution mais healthcheck KO. | `container.running=PASS`, `container.health=FAIL` | 🟢 **ALLOW** |
| `CONTAINER_NOT_FOUND` | Conteneur non trouvé sur l'hôte Docker. | `container.exists=FAIL` | 🛑 **BLOCK** |
| `PROCESS_CRASHED` | Processus cible introuvable dans la table OS. | `process.running=FAIL` | 🛑 **BLOCK** |
| `PROCESS_HEALTHY` | Processus nominal sans processus zombies. | `process.running=PASS`, `process.zombie=PASS` | 🟢 **NOMINAL** |

---

## 4. Modalités d'Exécution Supportées

1. **Exécution Locale** : Diagnostic direct sur la machine hôte.
2. **Exécution Distante Sans Agent (Agentless SSH)** : Diagnostic distant via SSH avec privilèges minimaux (POSIX ACLs, aucune élévation `sudo` requise).
3. **Exécution Conteneurisée (Docker)** : Diagnostic via l'API/CLI Docker locale ou distante.
4. **Exécution Confinée pour Agents IA (`CapabilitySet`)** : Contrôle strict des cibles IP/CIDR et ports que l'outil est autorisé à sonder lors de diagnostics automatisés.

---

## 5. Synthèse

À ce niveau, **EvidenceTool couvre l'ensemble des pannes d'infrastructure courantes** :
- **Couche Web & Ingress** (Nginx, Certificats SSL/TLS).
- **Couche Microservices & Conteneurs** (Docker lifecycle, healthchecks, OOM).
- **Couche Système & OS** (Services Systemd, table des Processus, saturation Disque).
- **Couche Réseau** (Reachability IP, Connectivité Ports TCP, Résolution DNS).
