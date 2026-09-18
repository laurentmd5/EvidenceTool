[English](SECURITY.md) | **Français**

# Politique de Sécurité

## Versions Prises en Charge

Actuellement, EvidenceTool est en version (`1.0.5`). Les mises à jour de sécurité sont appliquées aux branches de développement et main.

| Version | Prise en charge    |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| 0.9.x   | :white_check_mark: |
| 0.8.x   | :white_check_mark: |
| < 0.8   | :x:                |

## Signaler une Vulnérabilité

**NE CRÉEZ PAS** d'issue publique sur GitHub pour signaler une vulnérabilité de sécurité.
Cet outil interagit avec des infrastructures sensibles, incluant des clés privées et des serveurs de production via SSH. Nous prenons la sécurité avec la plus grande rigueur.

Veuillez signaler les vulnérabilités de manière privée via [GitHub Security Advisories](https://github.com/laurentmd5/EvidenceTool/security/advisories) ou en contactant directement le mainteneur à l'adresse : `mercilaurentmavoungou@gmail.com`.

Nous accuserons réception de votre rapport sous 48 heures et conviendrons d'un calendrier de divulgation coordonnée.

## Périmètre d'Intérêt

Les vulnérabilités prioritaires comprennent :
- Injections shell dans les providers (construction de commandes sous forme de chaînes de caractères au lieu de listes).
- Contournement de décisions déterministes (par exemple, forcer une décision `ALLOW` en présence d'une preuve bloquante).
- Élévation de privilèges ou fuite de secrets (ex: clés privées TLS affichées dans les journaux ou le format de sortie standard).
- Rebond SSRF ou interrogation abusive d'adresses de métadonnées cloud via le client HTTP de télémétrie.
