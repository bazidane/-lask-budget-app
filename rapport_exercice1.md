# 🛡️ Rapport de Vulnérabilités : Flask Budget App

Ce rapport détaille les résultats des scans de sécurité automatisés intégrés au pipeline CI/CD via **Semgrep** et **Snyk**.

---

## 🔍 I. Semgrep | Analyse Statique (SAST)
*Cible : `app.py`*

Le scan a détecté **8 vulnérabilités bloquantes**. L'analyse révèle des failles critiques d'injection et de mauvaises configurations de déploiement.

### 1. Injections de Code & SQL
* **Exécution de code arbitraire (`eval`)** :
    * **Description** : L'usage de `eval()` sur le paramètre `formula` permet à un attaquant d'exécuter du code Python sur le serveur.
    * **Recommandation** : Remplacer par `ast.literal_eval()` ou une logique métier stricte.
* **Injection SQL** :
    * **Description** : Construction de requêtes via f-strings (`f"SELECT...{user_id}"`).
    * **Recommandation** : Utiliser des requêtes paramétrées avec l'opérateur `?`.

### 2. Sécurité du Serveur Flask
* **Exposition publique** : L'application écoute sur `0.0.0.0` (accessible à tout le réseau).
* **Mode Debug actif** : `debug=True` expose un shell interactif en cas d'erreur, facilitant la prise de contrôle à distance.
* **Recommandation** : Désactiver le debug et restreindre l'hôte à `127.0.0.1` en environnement local.

### 3. Gestion des Secrets & Templates
* **Clé secrète codée en dur** : La `SECRET_KEY` est visible dans le code source, compromettant la signature des cookies de session.
* **Injection de Template (SSTI)** : L'utilisation de `render_template_string` avec formatage direct permet l'injection de code dans le moteur Jinja2.
* **Injection NaN** : Le casting direct en `float()` sans vérification peut provoquer des plantages ou des erreurs logiques.

---

## 📦 II. Snyk | Analyse des Dépendances (SCA)
*Cible : `requirements.txt`*

Snyk a identifié plusieurs bibliothèques obsolètes présentant des CVE (Common Vulnerabilities and Exposures) critiques.

| Composant | Version | Risque | Action Requise |
| :--- | :--- | :--- | :--- |
| **Flask** | 2.0.1 | **Information Exposure** (High) | Update vers **>= 2.2.5** |
| **Requests** | 2.25.0 | **Credential Leak** via Redirects | Update vers **>= 2.32.4** |
| **Jinja2** | 2.11.2 | **Cross-Site Scripting (XSS)** | Update vers **>= 3.1.2** |
| **urllib3** | 1.26.20 | **Denial of Service (DoS)** | Update vers **>= 2.0.0** |

> **Note technique** : La mise à jour de `requests` corrige par transitivité les failles de sécurité des sous-dépendances `idna` et `urllib3`.

---

## ✅ III. Plan de Remédiation

### 1. Sécurisation du Code
```python
# Remplacement des requêtes vulnérables
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Remplacement de eval()
import ast
result = ast.literal_eval(formula)
