# 🔎 IPanalyse - Forensic   

Application de bureau pour **analyser un CSV de connexions IP**, détecter les **adresses suspectes**, générer un **rapport HTML (mode sombre)** et, en option, un **PDF**.  
L’outil enrichit vos logs avec le **pays**, l’**état VPN/hosting**, l’**ISP/Opérateur** et calcule un **score de suspicion** paramétrable.

---

## ✨ Fonctionnalités   

- Lecture d’un CSV (`Date,IP`) avec auto-détection du séparateur.
- Lookup pays/VPN/ISP via **ip-api** (par défaut) ou **ipdata / IPQualityScore** (si clé).
- Support **IP2Proxy Lite** local (CSV) pour identifier VPN/Proxy.
- **Fenêtres suspectes** (date + heure) et **plages horaires inhabituelles**.
- **Exclusions** d’IPs par motif (ex: `92.* , 90.* , 10.0.0.*`).
- **Scoring** pondéré (hors pays, VPN/hosting, fréquence, horaires, **ISP FR vs hors FR/??**).
- Rapports **HTML** (sombre, interactif Leaflet) + **PDF**.
- **Habitudes de connexions** (tranches 30 min) affichées **hors pays principal / pays principal** côte à côte.
- UI moderne **PySide6** + **qdarktheme**; **threadé** (UI ne bloque pas).

---

## 🚀 Démarrage   

### Depuis l’exécutable (Windows)

Téléchargez `IPanalyse.exe` dispo dans les releases sur GitHub.  

### B. Depuis les sources (Python 3.10+)  

Téléchargez `IPanalyse.py` ainsi que `requirements.txt`

    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt  
    python IPanalyse.py

> Dépendances clés : `PySide6`, `qdarktheme`, `reportlab`, `matplotlib`, `certifi`.

---

## 🧭 Utilisation (pas à pas)

1. **Fichier CSV** : chargez votre fichier (`Date,IP` – l’entête “date” est ignorée automatiquement).
2. **Base IP2Proxy** : ajoutez le CSV IP2Proxy Lite pour renforcer la détection VPN/Proxy (Optionnel).  
3. **Options d’analyse** : complétez les champs (voir tableau ci-dessous).
4. **Exports** : cochez HTML et/ou PDF, choisissez le dossier de sortie.
5. **▶ Lancer l’analyse**. Le **Journal** affiche la progression; à la fin, le rapport s’ouvre.

---

## 🧩 Signification des champs (UI)

| Champ | Description | Exemple / Notes |
|---|---|---|
| **Fichier CSV** | Log à analyser (`Date,IP`). | `2024-11-15 22:54:10,92.25.15.25` |
| **Base IP2Proxy** | CSV IP2Proxy Lite local (plages IP → VPN/Proxy). | Accélère et fiabilise la détection. |
| **Dossier de sortie** | Où écrire les rapports. | `./rapports` |
| **Clé API (optionnelle)** | ip-api (sans clé), ou ipdata/IPQS (avec clé). | Mettre la clé si vous avez un compte. |
| **Plages IP exclues** | Motifs à ignorer **hors fenêtres suspectes**. | `92.* , 90.* , 10.0.0.*` (`*` ou `x` wildcard) |
| **Plages horaires inhabituelles** | Heures “sensibles” (24h). | `22:00-06:00,13:30-14:00` |
| **Plages de connexions suspectes** | **Date + heure** à inspecter finement (ignore les exclusions). | `15/11/2024 22:00-23:00; 2024-11-19 23:30-23:59` |
| **Pays principal** | Pays attendu/usuel. | `France` |
| **Poids — Hors pays** | +score si IP ≠ pays principal. | défaut: 40 |
| **Poids — IP2Proxy** | +score si IP2Proxy indique VPN/Proxy. | 30 |
| **Poids — Hosting** | +score si ip-api “hosting”. | 25 |
| **Poids — VPN/Autres** | +score si autre source indique VPN/Proxy. | 20 |
| **Poids — Unique** | +score si une seule occurrence. | 25 |
| **Poids — Peu fréquent (≤4)** | +score si faible fréquence. | 10 |
| **Poids — Inhabituelles** | +score si dans vos heures “sensibles”. | 15 |
| **Poids — ISP FR** | **-score** si FAI français reconnu. | défaut: -15 (réduit suspicion) |
| **Poids — ISP hors FR/??** | +score si FAI hors FR ou inconnu. | 15 |
| **Exporter en HTML / PDF** | Génération des rapports. | HTML : sombre & carte Leaflet. |
| **Ne pas inclure IPs d’autres pays (hors plages suspectes)** | Filtre d’affichage (après analyse). | N’affecte pas les fenêtres suspectes. |

> **Fenêtres suspectes** : l’analyse **prend tout** ce qui tombe dans ces fenêtres (les exclusions IP/pays ne s’appliquent pas), afin d’investiguer précisément ces créneaux.

---

## 🧮 Scoring (résumé)

Score sur 100 (borné), somme pondérée :
- **Hors pays principal**
- **VPN/Proxy** (IP2Proxy, Hosting ip-api, autres)
- **Fréquence** (Unique / Peu fréquent)
- **Horaires inhabituelles**
- **ISP FR** (diminue le score) / **ISP hors FR ou inconnu** (augmente le score)

Les **poids** sont réglables dans l’UI et **persistés** dans `config.json`.

---

## 📄 Rapports générés

### HTML (sombre, interactif)
- **Résumé** & KPI
- **IP suspectes** (Score, Nb, Pays, **ISP**, Raisons)
- **Fenêtres suspectes** (Horodatage, IP, Pays, VPN, **Opérateur**, Occurrences IP)
- **/24 les plus fréquents**
- **Carte** Leaflet par pays
- **Connexions horaires inhabituelles** (avec ISP)
- **IP exclues** & **Timed out**
- **Habitudes de connexions** (2 colonnes : **hors pays principal** / **pays principal**)
- **Tableau complet** (Date, IP, Pays, VPN, **Opérateur**)

### PDF
Il est vraiment moche, si vous souhaitez vraiment un format PDF, utiliser un lecteur html type chromium, et imprimer le en PDF.  

---


## 📁 Format du CSV attendu

- Colonnes minimales : `Date,IP`
- Formats de date acceptés :  
  `YYYY-MM-DD HH:MM[:SS]`, `DD/MM/YYYY HH:MM[:SS]`, ISO (`YYYY-MM-DDTHH:MM[:SS]`)
- L’entête est ignorée si la première cellule commence par `date`.

---

## ⚠️ Remarques & bonnes pratiques

- **ip-api** (par défaut) a un quota public ; utilisez une clé **ipdata/IPQS** si besoin d’un meilleur SLA.
  J'ai fait le choix d'utiliser un prestataire externe plutôt qu'une commande whois locale pour éviter de ping n'importe quoi avec votre propre IP.
- Les **timeouts** sont retentés une fois, puis listés dans le rapport.
- Les **IPv6** sont comptées mais ignorées dans l’analyse détaillée (affiché en KPI).
- Pour des **gros CSV**, préférez l’HTML (plus léger) et utilisez IP2Proxy local pour accélérer.

---

## 🛡️ Vie privée

Les IP peuvent être envoyées à un service tiers (ip-api/ipdata/IPQS) pour enrichissement.

---

## 📘 Licence

A venir
