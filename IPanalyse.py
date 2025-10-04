#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, re, csv, json, ipaddress, urllib.request, webbrowser, threading
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from bisect import bisect_right

# Qt6 (PySide6)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFileDialog, QMessageBox,
    QVBoxLayout, QHBoxLayout, QGridLayout, QGroupBox, QFormLayout,
    QLabel, QLineEdit, QComboBox, QSpinBox, QCheckBox, QPushButton,
    QProgressBar, QTextEdit
)
import qdarktheme

# ====== Report & Charts
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image as RLImage, Table, TableStyle, KeepInFrame
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# =========================
# CONSTANTES / CONFIG
# =========================
CONFIG_FILE = "config.json"
ignored_ipv6 = 0

COUNTRY_CODES = {
    "FR":"France","SE":"Suède","US":"États-Unis","DE":"Allemagne","IT":"Italie","ES":"Espagne",
    "GB":"Royaume-Uni","CA":"Canada","CN":"Chine","JP":"Japon","AU":"Australie","BR":"Brésil",
    "RU":"Russie","IN":"Inde","NL":"Pays-Bas","BE":"Belgique","CH":"Suisse","NO":"Norvège",
    "DK":"Danemark","FI":"Finlande"
}

COUNTRY_COORDS = {
    "France":[46.2276,2.2137],"Suède":[60.1282,18.6435],"États-Unis":[37.0902,-95.7129],
    "Allemagne":[51.1657,10.4515],"Italie":[41.8719,12.5674],"Espagne":[40.4637,-3.7492],
    "Royaume-Uni":[55.3781,-3.4360],"Canada":[56.1304,-106.3468],"Chine":[35.8617,104.1954],
    "Japon":[36.2048,138.2529],"Australie":[-25.2744,133.7751],"Brésil":[-14.2350,-51.9250],
    "Russie":[61.5240,105.3188],"Inde":[20.5937,78.9629],"Pays-Bas":[52.1326,5.2913],
    "Belgique":[50.5039,4.4699],"Suisse":[46.8182,8.2275],"Norvège":[60.4720,8.4689],
    "Danemark":[56.2639,9.5018],"Finlande":[61.9241,25.7482]
}

SERVICES = {
    # On demande aussi l'ISP à ip-api
    "ip-api":{"url":"http://ip-api.com/json/{ip}?fields=status,countryCode,hosting,isp,org,as,asname,query","requires_key":False},
    "ipdata":{"url":"https://api.ipdata.co/{ip}?api-key={key}","requires_key":True},
    "ipqualityscore":{"url":"https://ipqualityscore.com/api/json/ip/{key}/{ip}","requires_key":True}
}

DEFAULT_WEIGHTS = {
    "off_country": 40,
    "vpn_ip2p": 30,
    "hosting": 25,
    "vpn_other": 20,
    "unique": 25,
    "few": 10,
    "unusual": 15,
    # Nouveaux critères ISP
    "isp_fr": 5,       # ISP français
    "isp_foreign": 15    # ISP hors FR / inconnu 
}

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            pass
    return {
        "recent_files": [],
        "main_country": "France",
        "output_dir": ".",
        "export_html": True,
        "export_pdf": False,
        "exclude_other_countries": False,
        "suspect_datetime_windows": "",
        "weights": DEFAULT_WEIGHTS.copy(),
        "api_key": "",
        "ip2proxy": "",
        "unusual_ranges": "",
    }

def save_config(cfg_updates):
    cfg = load_config()
    cfg.update(cfg_updates)
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print("Erreur sauvegarde config:", e)

CONFIG = load_config()

# =========================
# IP2Proxy Lite (local)
# =========================
IP2P_RANGES = []
IP2P_STARTS = []

def ip_to_int(ip_str): return int(ipaddress.ip_address(ip_str))

def load_ip2proxy_lite_csv(path):
    global IP2P_RANGES, IP2P_STARTS
    ranges=[]
    try:
        with open(path, 'r', encoding='utf-8', newline='') as fh:
            reader=csv.reader(fh)
            for row in reader:
                if len(row)<3: 
                    continue
                try:
                    s=int(row[0]); e=int(row[1])
                except:
                    continue
                ptype=row[2].strip().upper() if row[2].strip() else "PX1"
                cname=row[3] if len(row)>3 else None
                ranges.append((s,e,ptype,cname))
        ranges.sort(key=lambda x:x[0])
        IP2P_RANGES=ranges
        IP2P_STARTS=[r[0] for r in ranges]
        return len(ranges)
    except:
        return 0

def ip2proxy_lookup(ip):
    if not IP2P_RANGES: return None,None
    ip_int=ip_to_int(ip)
    pos=bisect_right(IP2P_STARTS,ip_int)-1
    if pos>=0:
        s,e,ptype,cname=IP2P_RANGES[pos]
        if ip_int<=e:
            return ptype,cname
    return None,None

# =========================
# UTILITAIRES
# =========================
def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return True

def extract_hour_minute(date_str):
    fmts=["%Y-%m-%d %H:%M:%S","%Y-%m-%d %H:%M","%d/%m/%Y %H:%M:%S","%d/%m/%Y %H:%M"]
    for f in fmts:
        try:
            dt=datetime.strptime(date_str,f)
            return dt.hour,dt.minute
        except:
            continue
    try:
        dt=datetime.fromisoformat(date_str.replace(" ","T"))
        return dt.hour,dt.minute
    except:
        return None,None

def parse_datetime_loose(date_str):
    if not date_str: return None
    fmts = [
        "%Y-%m-%d %H:%M:%S","%Y-%m-%d %H:%M",
        "%d/%m/%Y %H:%M:%S","%d/%m/%Y %H:%M",
        "%Y-%m-%dT%H:%M:%S","%Y-%m-%dT%H:%M"
    ]
    for f in fmts:
        try:
            return datetime.strptime(date_str.strip(), f)
        except:
            continue
    try:
        return datetime.fromisoformat(date_str.strip().replace(" ","T"))
    except:
        return None

def detect_service(api_key):
    if not api_key: return "ip-api"
    elif api_key.startswith("ipd_"): return "ipdata"
    elif len(api_key)==32: return "ipqualityscore"
    else: return "ip-api"

def parse_time_to_minutes(s):
    try:
        h,m = map(int, s.split(":"))
        if 0<=h<=23 and 0<=m<=59:
            return h*60+m
    except:
        pass
    return None

def parse_unusual_ranges(entry_text):
    ranges=[]
    parts=[p.strip() for p in entry_text.split(",") if p.strip()]
    for part in parts:
        if "-" not in part: continue
        start,end=part.split("-",1)
        s=parse_time_to_minutes(start); e=parse_time_to_minutes(end)
        if s is None or e is None: continue
        wrap = e < s
        ranges.append((s,e,wrap))
    return ranges

WINDOW_REGEX = re.compile(
    r'\s*(?P<date>(\d{1,2}/\d{1,2}/\d{4})|(\d{4}-\d{2}-\d{2}))\s+'
    r'(?P<start>\d{1,2}:\d{2})\s*-\s*(?P<end>\d{1,2}:\d{2})\s*'
)
def parse_suspect_windows(text):
    windows=[]
    if not text: return windows
    parts = re.split(r'[;,|\n]+', text)
    for part in parts:
        part = part.strip()
        if not part: continue
        m = WINDOW_REGEX.fullmatch(part) or WINDOW_REGEX.search(part)
        if not m: continue
        date_str = m.group('date'); start_str = m.group('start'); end_str = m.group('end')
        if '/' in date_str:
            try: base_date = datetime.strptime(date_str, "%d/%m/%Y")
            except: continue
        else:
            try: base_date = datetime.strptime(date_str, "%Y-%m-%d")
            except: continue
        smin = parse_time_to_minutes(start_str); emin = parse_time_to_minutes(end_str)
        if smin is None or emin is None: continue
        start_dt = base_date.replace(hour=smin//60, minute=smin%60)
        end_dt   = base_date.replace(hour=emin//60, minute=emin%60)
        if end_dt < start_dt: end_dt += timedelta(days=1)
        windows.append((start_dt, end_dt))
    return windows

def within_any_window(dt, windows):
    if not dt or not windows: return False
    for s, e in windows:
        if s <= dt <= e: return True
    return False

def in_unusual(hour,minute,ranges):
    if hour is None: return False
    t=hour*60+minute
    for s,e,wrap in ranges:
        if not wrap and s<=t<=e: return True
        if wrap and (t>=s or t<=e): return True
    return False

def pattern_to_regex(pattern):
    p=pattern.strip().replace('*','x')
    parts=p.split('.'); regex_parts=[]
    for part in parts:
        if part=='' or part.lower()=='x':
            regex_parts.append(r'\d{1,3}')
        else:
            esc=re.escape(part).replace('x',r'\d{1,3}')
            regex_parts.append(esc)
    if len(parts)<4:
        prefix=r'\.'.join(regex_parts)
        return re.compile(r'^'+prefix+r'(\.|$)')
    return re.compile(r'^'+r'\.'.join(regex_parts)+r'$')

def ip_exclue(ip,exclusions,compiled):
    for pat in exclusions:
        rx=compiled.get(pat)
        if rx and rx.match(ip):
            return True
    return False

def compute_prefix_frequencies(rows):
    cnt = Counter()
    for r in rows:
        if len(r) < 2: continue
        ip = r[1]; pays = r[2] if len(r) > 2 else None
        if pays in ["N/A", "Privée", "timed out"]: continue
        if ':' in ip: continue
        parts = ip.split('.')
        if len(parts) >= 3 and all(p.isdigit() for p in parts[:3]):
            prefix = '.'.join(parts[:3]) + '.*'
            cnt[prefix] += 1
    return cnt.most_common(10)

# --- Détection ISP FR
FRENCH_ISP_PATTERNS = [
    r"\borange\b",
    r"\borange business\b",
    r"\bsfr\b",
    r"\bsoci[eé]t[eé].*fran[çc]aise.*radiot[eé]l[eé]phone",
    r"\bbouygues\b", r"\bbouygues.*telecom\b",
    r"\bfree\b", r"\bfree\s*sas\b", r"\bfree mobile\b", r"\bproxad\b", r"\biliad\b",
    r"\bla\s*poste\s*mobile\b", r"\bred(?:\s*by)?\s*sfr\b", r"\bsosh\b",
    r"\bnrj\s*mobile\b", r"\bprixtel\b", r"\bsym?a\b", r"\bley?bara\b", r"\blyca(?:mobile)?\b",
    r"\bcoriolis\b", r"\bauchan\s*telecom\b", r"\bcdiscount\s*mobile\b", r"\bnumericable\b",
    # r"\bovh\b", # optionnel
]
def is_french_isp(name: str) -> bool:
    if not name or name == "N/A":
        return False
    s = name.lower()
    for pat in FRENCH_ISP_PATTERNS:
        if re.search(pat, s):
            return True
    return False

def get_ip_info(ip,api_key=None):
    if is_private_ip(ip): 
        return "Privée","N/A","N/A"

    ptype,cname=ip2proxy_lookup(ip)
    if ptype:
        if cname and isinstance(cname, str) and cname.upper() in COUNTRY_CODES:
            country=COUNTRY_CODES[cname.upper()]
        else:
            country=cname if cname else "N/A"
        return country, f"Oui (IP2Proxy:{ptype})", "N/A"

    service=detect_service(api_key)
    url=(SERVICES[service]["url"].format(ip=ip,key=api_key)
         if SERVICES[service]["requires_key"]
         else SERVICES[service]["url"].format(ip=ip))
    pays,vpn,operateur="N/A","N/A","N/A"
    try:
        with urllib.request.urlopen(url,timeout=5) as r:
            data=json.loads(r.read().decode())
            if service=="ip-api" and data.get("status")=="success":
                code=data.get("countryCode","N/A")
                pays=COUNTRY_CODES.get(code,code)
                vpn="Oui (Hosting)" if data.get("hosting") else "Non"
                operateur = data.get("isp") or data.get("org") or data.get("asname") or data.get("as") or "N/A"
            elif service=="ipdata" and "country_code" in data:
                code=data["country_code"]
                pays=COUNTRY_CODES.get(code,code)
                vpn="Oui (ipdata)" if data.get("threat",{}).get("is_proxy") else "Non"
                operateur = (
                    (data.get("company") or {}).get("name")
                    or (data.get("asn") or {}).get("name")
                    or (data.get("carrier") or {}).get("name")
                    or "N/A"
                )
            elif service=="ipqualityscore" and "country_code" in data:
                code=data["country_code"]
                pays=COUNTRY_CODES.get(code,code)
                vpn="Oui (IPQS)" if data.get("vpn") else "Non"
                operateur = data.get("ISP") or data.get("isp") or data.get("ASN") or "N/A"
    except:
        pays,vpn,operateur="timed out","timed out","N/A"
    return pays,vpn,operateur

# =========================
# EXPORTS HTML / PDF
# =========================
def export_html(results, exclusions, timeouts, suspects, country_counts,
                habitudes_out_sorted=None, habitudes_in_sorted=None, unusual_list=None,
                prefix_freq=None, suspect_hits=None, suspect_windows_str="",
                base_dir=".", prefix="Rapport_complet", main_country="France",
                total_rows=0, excluded_count=0):
    global ignored_ipv6
    if habitudes_out_sorted is None: habitudes_out_sorted = []
    if habitudes_in_sorted  is None: habitudes_in_sorted  = []
    if unusual_list is None: unusual_list = []
    os.makedirs(base_dir, exist_ok=True)
    date_str = datetime.now().strftime("%d%m")
    filename = f"{prefix}_{date_str}.html"
    filepath = os.path.join(base_dir, filename)
    counter = 2
    while os.path.exists(filepath):
        filename = f"{prefix}_{date_str}_{counter}.html"
        filepath = os.path.join(base_dir, filename)
        counter += 1

    html = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>{filename}</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
<style>
 body {{
   font-family: 'Segoe UI', Tahoma, sans-serif;
   margin: 0; padding: 0;
   background: #0f1419; color: #e6edf3;
 }}
 a {{ color: #58a6ff; }}
 header {{
   background: #111827; color: #e6edf3; border-bottom: 1px solid #1f2937;
   padding: 20px; text-align: center; font-size: 24px;
 }}
 section {{
   background: #0b1220; margin: 20px auto; padding: 20px;
   max-width: 1100px; border-radius: 10px; border: 1px solid #1f2937;
 }}
 h2 {{
   margin-top: 0; color: #e6edf3; border-bottom: 1px solid #1f2937; padding-bottom: 6px;
 }}
 table {{
   border-collapse: collapse; width: 100%; margin-top: 15px; font-size: 14px;
 }}
 th, td {{
   border: 1px solid #1f2937; padding: 8px; text-align: left;
 }}
 th {{
   background: #111827; color: #e6edf3;
 }}
 tr:nth-child(even) {{ background: #0e1726; }}
 .badge {{
   display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 12px; font-weight: bold; color: white;
 }}
 .score-high {{ background: #ef4444; }}
 .score-mid  {{ background: #f59e0b; }}
 .score-low  {{ background: #10b981; }}
 .kpis {{
   display:grid; grid-template-columns: repeat(auto-fit, minmax(180px,1fr)); gap:10px;
 }}
 .kpi {{
   background:#0e1726; border:1px solid #1f2937; border-radius:10px; padding:12px;
 }}
 .kpi b {{ font-size:20px; color:#e6edf3; }}
 @page {{ size: A4; margin: 12mm; }}
 @media print {{
   html, body {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; background: white; color: black; }}
   header {{ box-shadow: none; }}
 }}
</style>
</head>
<body>
<header>📊 Rapport d'analyse IP – {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}</header>
"""

    # Résumé rapide
    html += "<section><h2>🧭 Résumé rapide</h2><div class='kpis'>"
    html += f"<div class='kpi'><div>Total lignes CSV</div><b>{total_rows}</b></div>"
    html += f"<div class='kpi'><div>Connexions analysées</div><b>{len(results)}</b></div>"
    html += f"<div class='kpi'><div>Pays détectés</div><b>{len(country_counts)}</b></div>"
    html += f"<div class='kpi'><div>IP suspectes</div><b>{len(suspects)}</b></div>"
    html += f"<div class='kpi'><div>IP exclues</div><b>{excluded_count}</b></div>"
    html += f"<div class='kpi'><div>Timed out</div><b>{len(timeouts)}</b></div>"
    html += f"<div class='kpi'><div>Pays principal</div><b>{main_country}</b></div>"
    html += f"<div class='kpi'><div>IPv6 ignorées</div><b>{ignored_ipv6}</b></div>"
    html += "</div></section>"

    # Suspects (avec ISP)
    html += "<section><h2>🚨 IP suspectes</h2>"
    if suspects:
        html += "<table><tr><th>IP</th><th>Score</th><th>Nb</th><th>Pays</th><th>ISP</th><th>Raisons</th></tr>"
        for s in suspects:
            cls="score-low"
            if s["score"]>=70: cls="score-high"
            elif s["score"]>=40: cls="score-mid"
            html += f"<tr><td>{s['ip']}</td><td><span class='badge {cls}'>{s['score']}</span></td><td>{s['count']}</td><td>{s['country']}</td><td>{s.get('isp','N/A')}</td><td>{'; '.join(s['reasons'])}</td></tr>"
        html += "</table>"
    else:
        html += "<p>Aucun suspect détecté.</p>"
    html += "</section>"

    # Fenêtres suspectes (avec opérateur)
    html += "<section><h2>🕵️ Connexions dans les fenêtres suspectes</h2>"
    if not suspect_windows_str.strip():
        html += "<p>Aucune fenêtre définie.</p>"
    else:
        html += f"<p><b>Fenêtres :</b> {suspect_windows_str}</p>"
        if suspect_hits:
            html += "<table><tr><th>Horodatage</th><th>IP</th><th>Pays</th><th>VPN</th><th>Opérateur</th><th>Occurrences IP</th></tr>"
            for d, ip, pays, vpn, oper, total in suspect_hits:
                html += f"<tr><td>{d}</td><td>{ip}</td><td>{pays}</td><td>{vpn}</td><td>{oper}</td><td>{total}</td></tr>"
            html += "</table>"
        else:
            html += "<p>Aucune connexion dans ces fenêtres.</p>"
    html += "</section>"

    # /24 fréquents
    html += "<section><h2>📌 Plage d'adresses IPs revenant le plus fréquemment :</h2>"
    if prefix_freq:
        html += "<table><tr><th>Plage /24</th><th>Occurrences</th></tr>"
        for pref, c in prefix_freq:
            html += f"<tr><td>{pref}</td><td>{c}</td></tr>"
        html += "</table>"
    else:
        html += "<p>Aucune plage /24 récurrente trouvée.</p>"
    html += "</section>"

    # Carte Leaflet
    html += "<section><h2>🗺️ Carte des pays détectés</h2>"
    html += "<div id='map' style='width:100%;height:480px;border-radius:8px;'></div>"
    html += "<script>var map=L.map('map').setView([20,0],2);"
    html += "L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{attribution:'© OpenStreetMap'}).addTo(map);"
    for country,count in country_counts.items():
        coord=COUNTRY_COORDS.get(country)
        if coord:
            popup=f"{country} : {count} connexion(s)"
            html+=f"L.circleMarker([{coord[0]},{coord[1]}],{{radius:8,color:'red'}}).addTo(map).bindPopup('{popup}');"
    html += "</script></section>"

    # Inhabituelles (table + ISP)
    html += "<section><h2>🌙 Connexions horaires inhabituelles</h2>"
    if unusual_list:
        html += "<table><tr><th>Horodatage</th><th>IP</th><th>Pays</th><th>ISP</th></tr>"
        for u in unusual_list:
            date_u, ip_u, pays_u, oper_u = (u + ["", "", "", ""])[:4]
            html += f"<tr><td>{date_u}</td><td>{ip_u}</td><td>{pays_u}</td><td>{oper_u}</td></tr>"
        html += "</table>"
    else:
        html += "<p>Aucune connexion inhabituelle détectée.</p>"
    html += "</section>"

    # Exclusions / timeouts
    html += "<section><h2>📍 IP exclues</h2>"
    html += ("<ul>"+"".join(f"<li>{e}</li>" for e in exclusions)+"</ul>") if exclusions else "<p>Aucune</p>"
    html += "</section>"

    html += "<section><h2>⚠️ IP 'timed out'</h2>"
    html += ("<ul>"+"".join(f"<li>{t[0]} – {t[1]}</li>" for t in timeouts)+"</ul>") if timeouts else "<p>Aucune</p>"
    html += "</section>"

    # Habitudes 2 colonnes
    html += f"<section><h2>🕰️ Habitudes de connexions hors {main_country} / {main_country} (tranches 30 min)</h2>"
    html += "<div style='display:grid;grid-template-columns:1fr 1fr;gap:16px;'>"
    html += "<div><h3>Hors {}</h3>".format(main_country)
    if habitudes_out_sorted:
        for tranche, connexions in habitudes_out_sorted:
            html += f"<p><b>{len(connexions)} connexion(s) à {tranche}</b></p><ul>"
            for c in connexions:
                html += f"<li>{c[0]} – {c[1]} ({c[2]})</li>"
            html += "</ul>"
    else:
        html += "<p>Aucune donnée disponible</p>"
    html += "</div>"
    html += "<div><h3>{}</h3>".format(main_country)
    if habitudes_in_sorted:
        for tranche, connexions in habitudes_in_sorted:
            html += f"<p><b>{len(connexions)} connexion(s) à {tranche}</b></p><ul>"
            for c in connexions:
                html += f"<li>{c[0]} – {c[1]} ({c[2]})</li>"
            html += "</ul>"
    else:
        html += "<p>Aucune donnée disponible</p>"
    html += "</div>"
    html += "</div></section>"

    # Tableau complet (avec opérateur)
    html += "<section><h2>📋 Tableau complet</h2><table><tr><th>Date</th><th>IP</th><th>Pays</th><th>VPN</th><th>Opérateur</th></tr>"
    for r in results:
        html += f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td><td>{r[4]}</td></tr>"
    html += "</table></section>"

    html += "</body></html>"

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
    webbrowser.open('file://' + os.path.realpath(filepath))
    return filepath

def generate_country_map(country_counts, filepath=None):
    if filepath is None:
        filepath = f"map_{datetime.now().strftime('%d%m%H%M%S')}.png"
    fig, ax = plt.subplots(figsize=(8,5))
    ax.set_title("Carte des connexions IP par pays")
    ax.set_xlim(-180, 180); ax.set_ylim(-90, 90)
    ax.set_xlabel("Longitude"); ax.set_ylabel("Latitude")
    ax.grid(True, linestyle="--", alpha=0.5)
    for country,count in country_counts.items():
        coord=COUNTRY_COORDS.get(country)
        if coord:
            lat, lon = coord
            ax.scatter(lon, lat, s=50+count*5, alpha=0.7)
            ax.text(lon+2, lat+2, f"{country} ({count})", fontsize=8)
    plt.savefig(filepath, bbox_inches="tight"); plt.close(fig)
    return filepath

def export_pdf(results, suspects, country_counts, main_country="France",
               total_rows=0, excluded_count=0, timeouts=None, unusual_list=None, exclusions=None,
               habitudes_out_sorted=None, habitudes_in_sorted=None, prefix_freq=None, suspect_hits=None, suspect_windows_str="",
               base_dir="."):
    if timeouts is None: timeouts = []
    if unusual_list is None: unusual_list = []
    if exclusions is None: exclusions = []
    if habitudes_out_sorted is None: habitudes_out_sorted = []
    if habitudes_in_sorted  is None: habitudes_in_sorted  = []
    if prefix_freq is None: prefix_freq = []
    if suspect_hits is None: suspect_hits = []

    os.makedirs(base_dir, exist_ok=True
    )
    filename = os.path.join(base_dir, f"Rapport_IP_{datetime.now().strftime('%d%m')}.pdf")
    doc = SimpleDocTemplate(filename, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("📊 Rapport d'analyse IP", styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Date : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", styles["Normal"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("<b>Résumé rapide :</b>", styles["Heading2"]))
    story.append(Paragraph(f"Total lignes CSV : {total_rows}", styles["Normal"]))
    story.append(Paragraph(f"Connexions analysées : {len(results)}", styles["Normal"]))
    story.append(Paragraph(f"Pays détectés : {len(country_counts)}", styles["Normal"]))
    story.append(Paragraph(f"IP suspectes : {len(suspects)}", styles["Normal"]))
    story.append(Paragraph(f"IP exclues : {excluded_count}", styles["Normal"]))
    story.append(Paragraph(f"Pays principal : {main_country}", styles["Normal"]))
    story.append(Spacer(1, 20))

    map_path = generate_country_map(country_counts, filepath=os.path.join(base_dir, "carte_pays.png"))
    story.append(Paragraph("🗺️ Carte des pays détectés :", styles["Heading2"]))
    story.append(RLImage(map_path, width=400, height=250))
    story.append(Spacer(1, 20))

    # Suspects (avec ISP)
    story.append(Paragraph("🚨 IP suspectes :", styles["Heading2"]))
    if suspects:
        data = [["IP", "Score", "Nb", "Pays", "ISP", "Raisons"]]
        for s in suspects:
            data.append([s['ip'], str(s['score']), str(s['count']), s['country'], s.get('isp','N/A'), "; ".join(s['reasons'])])
        table = Table(data, repeatRows=1, colWidths=[90,50,40,80,90,170])
        table.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0), colors.lightgrey),
            ("GRID",(0,0),(-1,-1),0.25, colors.grey),
            ("ALIGN",(0,0),(-1,-1),"CENTER"),
        ]))
        story.append(table)
    else:
        story.append(Paragraph("Aucun suspect détecté.", styles["Normal"]))
    story.append(Spacer(1, 18))

    # Fenêtres suspectes (avec opérateur)
    story.append(Paragraph("🕵️ Connexions dans les fenêtres suspectes", styles["Heading2"]))
    if not suspect_windows_str.strip():
        story.append(Paragraph("Aucune fenêtre définie.", styles["Normal"]))
    else:
        story.append(Paragraph(f"<b>Fenêtres :</b> {suspect_windows_str}", styles["Normal"]))
        if suspect_hits:
            data = [["Horodatage", "IP", "Pays", "VPN", "Opérateur", "Occ. IP"]]
            for d, ip, pays, vpn, oper, total in suspect_hits:
                data.append([d, ip, pays, vpn, oper, str(total)])
            t = Table(data, repeatRows=1, colWidths=[120,90,80,70,100,60])
            t.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0), colors.lightgrey),
                ("GRID",(0,0),(-1,-1),0.25, colors.grey),
                ("ALIGN",(5,1),(5,-1),"CENTER"),
            ]))
            story.append(t)
        else:
            story.append(Paragraph("Aucune connexion dans ces fenêtres.", styles["Normal"]))
    story.append(Spacer(1, 18))

    # /24 fréquents
    story.append(Paragraph("📌 Plage d'adresses IPs revenant le plus fréquemment :", styles["Heading2"]))
    if prefix_freq:
        data = [["Plage /24", "Occurrences"]]
        for p, c in prefix_freq:
            data.append([p, str(c)])
        t = Table(data, repeatRows=1, colWidths=[200, 100])
        t.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0), colors.lightgrey),
                ("GRID",(0,0),(-1,-1),0.25, colors.grey),
                ("ALIGN",(1,1),(1,-1),"CENTER"),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("Aucune plage /24 récurrente trouvée.", styles["Normal"]))
    story.append(Spacer(1, 20))

    # Exclusions / Timeouts
    story.append(Paragraph("📍 IP exclues :", styles["Heading2"]))
    if exclusions:
        for e in exclusions:
            story.append(Paragraph(f"- {e}", styles["Normal"]))
    else:
        story.append(Paragraph("Aucune", styles["Normal"]))
    story.append(Spacer(1, 20))

    story.append(Paragraph("⚠️ IP 'timed out' :", styles["Heading2"]))
    if timeouts:
        for tmo in timeouts:
            story.append(Paragraph(f"- {tmo[0]} – {tmo[1]}", styles["Normal"]))
    else:
        story.append(Paragraph("Aucune", styles["Normal"]))
    story.append(Spacer(1, 20))

    # Inhabituelles (table + ISP)
    story.append(Paragraph("🌙 Connexions horaires inhabituelles :", styles["Heading2"]))
    if unusual_list:
        data = [["Horodatage", "IP", "Pays", "ISP"]]
        for u in unusual_list:
            date_u, ip_u, pays_u, oper_u = (u + ["", "", "", ""])[:4]
            data.append([date_u, ip_u, pays_u, oper_u])
        t = Table(data, repeatRows=1, colWidths=[120,90,80,160])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0), colors.lightgrey),
            ("GRID",(0,0),(-1,-1),0.25, colors.grey),
            ("ALIGN",(1,1),(1,-1),"LEFT"),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("Aucune connexion inhabituelle détectée.", styles["Normal"]))
    story.append(Spacer(1, 20))

    # Habitudes 2 colonnes
    story.append(Paragraph(f"🕰️ Habitudes de connexions hors {main_country} / {main_country} (tranches 30 min) :", styles["Heading2"]))
    if not (habitudes_out_sorted or habitudes_in_sorted):
        story.append(Paragraph("Aucune donnée disponible", styles["Normal"]))
    else:
        left = []
        left.append(Paragraph(f"<b>Hors {main_country}</b>", styles["Normal"]))
        if habitudes_out_sorted:
            for tranche, connexions in habitudes_out_sorted:
                left.append(Paragraph(f"<b>{len(connexions)} connexion(s) à {tranche}</b>", styles["Normal"]))
                for c in connexions:
                    left.append(Paragraph(f"- {c[0]} – {c[1]} ({c[2]})", styles["Normal"]))
                left.append(Spacer(1, 6))
        else:
            left.append(Paragraph("Aucune donnée", styles["Normal"]))

        right = []
        right.append(Paragraph(f"<b>{main_country}</b>", styles["Normal"]))
        if habitudes_in_sorted:
            for tranche, connexions in habitudes_in_sorted:
                right.append(Paragraph(f"<b>{len(connexions)} connexion(s) à {tranche}</b>", styles["Normal"]))
                for c in connexions:
                    right.append(Paragraph(f"- {c[0]} – {c[1]} ({c[2]})", styles["Normal"]))
                right.append(Spacer(1, 6))
        else:
            right.append(Paragraph("Aucune donnée", styles["Normal"]))

        left_kif  = KeepInFrame(260, 640, left,  hAlign='LEFT')
        right_kif = KeepInFrame(260, 640, right, hAlign='LEFT')
        t = Table([[left_kif, right_kif]], colWidths=[260, 260])
        t.setStyle(TableStyle([
            ("VALIGN",(0,0),(-1,-1),"TOP"),
            ("LINEABOVE",(0,0),(-1,0), 0.25, colors.grey),
            ("LINEBELOW",(0,0),(-1,0), 0.25, colors.grey),
        ]))
        story.append(t)

    doc.build(story)
    return filename

# =========================
# WORKER THREAD (QThread)
# =========================
class AnalysisWorker(QThread):
    progress = Signal(int, int, str)   # current, total, message
    finished = Signal(dict)
    error = Signal(str)

    def __init__(self, cfg):
        super().__init__()
        self.cfg = cfg
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        try:
            payload = self._run_core()
            self.finished.emit(payload)
        except Exception as e:
            self.error.emit(str(e))

    def _run_core(self):
        csv_path     = self.cfg["csv_path"]
        api_key      = self.cfg.get("api_key") or None
        ip2p_path    = self.cfg.get("ip2p_path","").strip()
        raw_excl     = self.cfg.get("raw_exclusions","")
        unusual_txt  = self.cfg.get("unusual_ranges","").strip()
        suspect_txt  = self.cfg.get("suspect_windows","").strip()
        main_country = self.cfg.get("main_country","France")
        weights      = self.cfg.get("weights", DEFAULT_WEIGHTS.copy())
        exclude_others = self.cfg.get("exclude_others", False)

        local_ignored_ipv6 = 0

        if ip2p_path and not IP2P_RANGES:
            load_ip2proxy_lite_csv(ip2p_path)

        with open(csv_path, "r", encoding="utf-8", newline="") as f:
            sample = f.read(4096); f.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t ")
            except csv.Error:
                dialect = csv.excel
            reader = csv.reader(f, dialect)
            rows = list(reader)

        if rows and rows[0] and rows[0][0].lower().startswith("date"):
            rows = rows[1:]

        exclusions = [t.strip() for t in re.findall(r'[0-9x.*]+', raw_excl, flags=re.IGNORECASE) if t.strip()]
        compiled = {pat: pattern_to_regex(pat) for pat in exclusions}

        cache={}
        results=[]
        timeouts=[]
        unusual_list=[]
        excluded_count = 0
        ip_totals = Counter()

        ranges = parse_unusual_ranges(unusual_txt)
        suspect_windows = parse_suspect_windows(suspect_txt)
        windows_mode = len(suspect_windows) > 0
        suspect_window_hits = []

        total = len(rows)
        self.progress.emit(0, total, f"{len(exclusions)} motif(s) d'exclusion")

        for idx, row in enumerate(rows):
            if self._stop.is_set():
                return {"cancelled": True}

            if len(row) < 2:
                self.progress.emit(idx+1, total, f"Ligne {idx+1}/{total} ignorée (format)")
                continue

            date_str, ip = row[0].strip(), row[1].strip()
            dt_csv = parse_datetime_loose(date_str)
            in_window = within_any_window(dt_csv, suspect_windows) if windows_mode else False

            # IPv6
            try:
                ip_obj = ipaddress.ip_address(ip)
                if isinstance(ip_obj, ipaddress.IPv6Address):
                    local_ignored_ipv6 += 1
                    self.progress.emit(idx+1, total, f"IP {idx+1}/{total} (IPv6 ignorée)")
                    continue
            except Exception:
                self.progress.emit(idx+1, total, f"Ligne {idx+1}/{total} ignorée (IP invalide)")
                continue

            if in_window:
                # Dans la fenêtre : ignorer les exclusions IP/pays → traiter tout
                pass
            else:
                # Hors fenêtre : exclusion IP immédiate
                if ip_exclue(ip, exclusions, compiled):
                    excluded_count += 1
                    self.progress.emit(idx+1, total, f"IP {idx+1}/{total} exclue (plage)")
                    continue

            # Lookup (cache + retry timeouts)
            if ip in cache:
                pays, vpn, oper = cache[ip]
            else:
                pays, vpn, oper = get_ip_info(ip, api_key)
                if pays == "timed out":
                    pays_retry, vpn_retry, oper_retry = get_ip_info(ip, api_key)
                    if pays_retry != "timed out":
                        pays, vpn, oper = pays_retry, vpn_retry, oper_retry
                    else:
                        timeouts.append((date_str, ip))
                cache[ip] = (pays, vpn, oper)

            # Exclusion par pays HORS fenêtre ?
            if (not in_window) and exclude_others and (pays not in ["N/A", "Privée", "timed out"]) and (pays != main_country):
                self.progress.emit(idx+1, total, f"IP {idx+1}/{total} filtrée (pays ≠ {main_country})")
                continue

            ip_totals[ip] += 1
            results.append([date_str, ip, pays, vpn, oper])
            if in_window:
                suspect_window_hits.append([date_str, ip, pays, vpn, oper])

            h, m = extract_hour_minute(date_str)
            if ranges and in_unusual(h, m, ranges):
                unusual_list.append([date_str, ip, pays, oper])

            self.progress.emit(idx+1, total, f"IP {idx+1}/{total} traitées…")

        # Post-traitement
        def compute_score(ip, rows, unusual_ranges, main_country, weights):
            nb = len(rows); score = 0; reasons = []
            rep_country = next((r[2] for r in rows if r[2] not in ["N/A","Privée","timed out"]), None)
            rep_oper = next((r[4] for r in rows if len(r)>4 and r[4] and r[4] != "N/A"), None)

            if rep_country and rep_country != main_country:
                score += weights.get("off_country", DEFAULT_WEIGHTS["off_country"]); reasons.append(f"Hors {main_country}")

            vpn_hits = [r[3] for r in rows if isinstance(r[3], str) and "Oui" in r[3]]
            if any("IP2Proxy" in v for v in vpn_hits):
                score += weights.get("vpn_ip2p", DEFAULT_WEIGHTS["vpn_ip2p"]); reasons.append("Proxy/VPN (IP2Proxy)")
            elif any("Hosting" in v for v in vpn_hits):
                score += weights.get("hosting", DEFAULT_WEIGHTS["hosting"]); reasons.append("Hosting (ip-api)")
            elif vpn_hits:
                score += weights.get("vpn_other", DEFAULT_WEIGHTS["vpn_other"]); reasons.append("VPN/Proxy")

            if nb == 1:
                score += weights.get("unique", DEFAULT_WEIGHTS["unique"]); reasons.append("Unique")
            elif nb <= 4:
                score += weights.get("few", DEFAULT_WEIGHTS["few"]); reasons.append("Peu fréquent")

            unusual_hits = 0
            for r in rows:
                h, m = extract_hour_minute(r[0])
                if in_unusual(h, m, unusual_ranges): unusual_hits += 1
            if unusual_hits > 0:
                score += weights.get("unusual", DEFAULT_WEIGHTS["unusual"]); reasons.append(f"{unusual_hits} horaires inhabituels")

            # ISP FR / hors FR
            if rep_oper and is_french_isp(rep_oper):
                score += weights.get("isp_fr", DEFAULT_WEIGHTS["isp_fr"]); reasons.append("ISP FR")
            else:
                score += weights.get("isp_foreign", DEFAULT_WEIGHTS["isp_foreign"]); reasons.append("ISP hors FR/??")

            if score < 0: score = 0
            if score > 100: score = 100
            return score, reasons, rep_country, rep_oper

        grouped=defaultdict(list)
        for r in results: grouped[r[1]].append(r)

        suspects=[]
        for ip,group in grouped.items():
            valids=[g for g in group if g[2] not in ["N/A","Privée","timed out"]]
            if not valids: continue
            score, reasons, country, oper = compute_score(ip, valids, ranges, main_country, weights)
            suspects.append({
                "ip": ip, "score": score, "reasons": reasons, "count": len(valids),
                "country": country or "N/A", "isp": oper or "N/A"
            })
        suspects.sort(key=lambda x:x["score"],reverse=True)

        country_counts = Counter([r[2] for r in results if r[2] not in ["N/A","Privée","timed out"]])

        # Habitudes 30 min : deux colonnes (hors / dans pays principal)
        valid_rows = [r for r in results if r[2] not in ["N/A","Privée","timed out"]]
        hab_out = defaultdict(list)
        hab_in  = defaultdict(list)
        for r in valid_rows:
            h,m = extract_hour_minute(r[0])
            if h is None: 
                continue
            start_min = 0 if m<30 else 30
            end_min = start_min+29
            key=f"{h:02d}h{start_min:02d}-{h:02d}h{end_min:02d}"
            if r[2] == main_country:
                hab_in[key].append(r)
            else:
                hab_out[key].append(r)
        habitudes_out_sorted = sorted(hab_out.items(), key=lambda x: len(x[1]), reverse=True)
        habitudes_in_sorted  = sorted(hab_in.items(),  key=lambda x: len(x[1]), reverse=True)

        prefix_freq = compute_prefix_frequencies(results)

        suspect_hits = []
        for d, ip, pays, vpn, oper in suspect_window_hits:
            total_for_ip = ip_totals.get(ip, 0)
            suspect_hits.append([d, ip, pays, vpn, oper, total_for_ip])
        try:
            suspect_hits.sort(key=lambda x: parse_datetime_loose(x[0]) or datetime.min)
        except:
            pass

        return {
            "cancelled": False,
            "results": results,
            "suspects": suspects,
            "country_counts": country_counts,
            "habitudes_out_sorted": habitudes_out_sorted,
            "habitudes_in_sorted": habitudes_in_sorted,
            "unusual_list": unusual_list,
            "timeouts": timeouts,
            "excluded_count": excluded_count,
            "prefix_freq": prefix_freq,
            "suspect_hits": suspect_hits,
            "suspect_windows_str": suspect_txt,
            "main_country": main_country,
            "weights": weights,
            "ip_totals": ip_totals,
            "exclusions_list": exclusions,
            "ignored_ipv6": local_ignored_ipv6,
        }

# =========================
# UI PySide6
# =========================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔎 Analyseur IP Suspects — Qt Edition")
        self.resize(1280, 850)
        self.showMaximized()  # plein écran pratique ; F11 toggle ci-dessous
        self.worker = None

        # --- racine
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setSpacing(10)

        # --- bandeau titre
        title = QLabel("🔎 Analyseur d'adresses IP (CSV)")
        title.setStyleSheet("font-size:22px; font-weight:700;")
        root.addWidget(title)

        # --- fichiers
        gb_files = QGroupBox("Fichiers")
        fl = QGridLayout(gb_files)
        self.csv_path = QLineEdit(); self.csv_path.setPlaceholderText("Chemin du CSV…")
        btn_csv = QPushButton("📂 Choisir CSV")
        btn_csv.clicked.connect(self.pick_csv)
        self.ip2p = QLineEdit(CONFIG.get("ip2proxy","")); self.ip2p.setPlaceholderText("Base IP2Proxy (CSV)…")
        btn_ip2p = QPushButton("📂 IP2Proxy…"); btn_ip2p.clicked.connect(self.pick_ip2p)
        self.out_dir = QLineEdit(CONFIG.get("output_dir","."))
        btn_out = QPushButton("📁 Dossier de sortie…"); btn_out.clicked.connect(self.pick_out_dir)

        fl.addWidget(QLabel("Fichier CSV :"), 0,0); fl.addWidget(self.csv_path,0,1); fl.addWidget(btn_csv,0,2)
        fl.addWidget(QLabel("Base IP2Proxy :"),1,0); fl.addWidget(self.ip2p,1,1); fl.addWidget(btn_ip2p,1,2)
        fl.addWidget(QLabel("Dossier de sortie :"),2,0); fl.addWidget(self.out_dir,2,1); fl.addWidget(btn_out,2,2)
        root.addWidget(gb_files)

        # --- options
        gb_opts = QGroupBox("Options d'analyse")
        form = QFormLayout(gb_opts)
        self.api_key = QLineEdit(CONFIG.get("api_key",""))
        self.exclusions = QLineEdit(); self.exclusions.setPlaceholderText("Ex: 92.* , 90.* , 10.0.0.*")
        self.unusual = QLineEdit(CONFIG.get("unusual_ranges","")); self.unusual.setPlaceholderText("Ex: 22:00-06:00,13:30-14:00")
        self.suspect = QLineEdit(CONFIG.get("suspect_datetime_windows","")); self.suspect.setPlaceholderText("Ex: 15/11/2024 22:00-23:00; 19/11/2024 23:30-23:59")

        all_countries = sorted(set(list(COUNTRY_COORDS.keys()) + list(COUNTRY_CODES.values())))
        self.main_country = QComboBox(); self.main_country.addItems(all_countries)
        idx = self.main_country.findText(CONFIG.get("main_country","France"))
        if idx >= 0: self.main_country.setCurrentIndex(idx)

        # poids (inclut maintenant les 2 curseurs ISP)
        w = CONFIG.get("weights", DEFAULT_WEIGHTS.copy())

        self.w_off = QSpinBox(); self.w_off.setRange(0,100); self.w_off.setValue(w.get("off_country",DEFAULT_WEIGHTS["off_country"]))
        self.w_ip2p = QSpinBox(); self.w_ip2p.setRange(0,100); self.w_ip2p.setValue(w.get("vpn_ip2p",DEFAULT_WEIGHTS["vpn_ip2p"]))
        self.w_host = QSpinBox(); self.w_host.setRange(0,100); self.w_host.setValue(w.get("hosting",DEFAULT_WEIGHTS["hosting"]))
        self.w_oth = QSpinBox(); self.w_oth.setRange(0,100); self.w_oth.setValue(w.get("vpn_other",DEFAULT_WEIGHTS["vpn_other"]))
        self.w_uni = QSpinBox(); self.w_uni.setRange(0,100); self.w_uni.setValue(w.get("unique",DEFAULT_WEIGHTS["unique"]))
        self.w_few = QSpinBox(); self.w_few.setRange(0,100); self.w_few.setValue(w.get("few",DEFAULT_WEIGHTS["few"]))
        self.w_unu = QSpinBox(); self.w_unu.setRange(0,100); self.w_unu.setValue(w.get("unusual",DEFAULT_WEIGHTS["unusual"]))

        # ➕ Nouveaux curseurs
        self.w_isp_fr = QSpinBox(); self.w_isp_fr.setRange(-100,100); self.w_isp_fr.setValue(w.get("isp_fr",DEFAULT_WEIGHTS["isp_fr"]))
        self.w_isp_fr.setToolTip("Impact si l'ISP est reconnu français (score peut diminuer)")
        self.w_isp_foreign = QSpinBox(); self.w_isp_foreign.setRange(-100,100); self.w_isp_foreign.setValue(w.get("isp_foreign",DEFAULT_WEIGHTS["isp_foreign"]))
        self.w_isp_foreign.setToolTip("Impact si l'ISP est hors France ou inconnu (score augmente)")

        # export
        self.chk_html = QCheckBox("Exporter en HTML"); self.chk_html.setChecked(CONFIG.get("export_html",True))
        self.chk_pdf  = QCheckBox("Exporter en PDF");  self.chk_pdf.setChecked(CONFIG.get("export_pdf",True))
        self.chk_excl_others = QCheckBox("Ne pas inclure les IPs provenant d'autres pays (hors plages suspectes)"); 
        self.chk_excl_others.setChecked(CONFIG.get("exclude_other_countries",False))

        form.addRow("Clé API (optionnelle) :", self.api_key)
        form.addRow("Plages IP exclues :", self.exclusions)
        form.addRow("Plages horaires inhabituelles :", self.unusual)
        form.addRow("Plages de connexions suspectes :", self.suspect)
        form.addRow("Pays principal :", self.main_country)

        # Grille des poids
        grid_weights = QGridLayout(); wg = QWidget(); wg.setLayout(grid_weights)

        # ligne 0
        grid_weights.addWidget(QLabel("Hors pays"),0,0); grid_weights.addWidget(self.w_off,0,1)
        grid_weights.addWidget(QLabel("IP2Proxy"),0,2); grid_weights.addWidget(self.w_ip2p,0,3)
        grid_weights.addWidget(QLabel("Hosting"),0,4);  grid_weights.addWidget(self.w_host,0,5)
        # ligne 1
        grid_weights.addWidget(QLabel("VPN"),1,0); grid_weights.addWidget(self.w_oth,1,1)
        grid_weights.addWidget(QLabel("Unique"),1,2);     grid_weights.addWidget(self.w_uni,1,3)
        grid_weights.addWidget(QLabel("Peu fréquent"),1,4); grid_weights.addWidget(self.w_few,1,5)
        # ligne 2
        grid_weights.addWidget(QLabel("Inhabituelles"),2,0); grid_weights.addWidget(self.w_unu,2,1)
        grid_weights.addWidget(QLabel("ISP FR"),2,2);        grid_weights.addWidget(self.w_isp_fr,2,3)
        grid_weights.addWidget(QLabel("ISP hors FR/NA"),2,4);grid_weights.addWidget(self.w_isp_foreign,2,5)

        form.addRow("Poids du scoring :", wg)

        row = QWidget(); hl = QHBoxLayout(row); hl.setContentsMargins(0,0,0,0)
        hl.addWidget(self.chk_html); hl.addWidget(self.chk_pdf); hl.addWidget(self.chk_excl_others); hl.addStretch(1)
        form.addRow("Exports & filtre :", row)
        root.addWidget(gb_opts)

        # --- actions
        act = QWidget(); hl2 = QHBoxLayout(act)
        self.btn_run = QPushButton("▶ Lancer l'analyse"); self.btn_run.clicked.connect(self.start_analysis)
        self.btn_cancel = QPushButton("✖ Annuler"); self.btn_cancel.setEnabled(False); self.btn_cancel.clicked.connect(self.cancel_analysis)
        hl2.addWidget(self.btn_run); hl2.addWidget(self.btn_cancel); hl2.addStretch(1)
        root.addWidget(act)

        # --- progression & log
        self.progress = QProgressBar(); self.progress.setRange(0,100); self.progress.setValue(0)
        root.addWidget(self.progress)
        self.log = QTextEdit(); self.log.setReadOnly(True); self.log.setPlaceholderText("Journal…")
        root.addWidget(self.log, 1)

        # Raccourcis plein écran
        self.shortcut_fullscreen = self.addAction("F11")
        self.shortcut_fullscreen.setShortcut("F11")
        self.shortcut_fullscreen.triggered.connect(self.toggle_fullscreen)

    def toggle_fullscreen(self):
        if self.isFullScreen(): self.showMaximized()
        else: self.showFullScreen()

    # ----------- pickers
    def pick_csv(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choisir un CSV", "", "CSV (*.csv);;Tous fichiers (*)")
        if path:
            self.csv_path.setText(path)
            hist = CONFIG.get("recent_files", [])
            if path in hist: hist.remove(path)
            hist.insert(0, path)
            CONFIG["recent_files"] = hist[:5]
            save_config({"recent_files": CONFIG["recent_files"]})

    def pick_ip2p(self):
        path, _ = QFileDialog.getOpenFileName(self, "Base IP2Proxy (CSV)", "", "CSV (*.csv *.CSV);;Tous fichiers (*)")
        if path: self.ip2p.setText(path)

    def pick_out_dir(self):
        path = QFileDialog.getExistingDirectory(self, "Choisir un dossier de sortie", self.out_dir.text() or ".")
        if path: self.out_dir.setText(path)

    # ----------- analyse
    def start_analysis(self):
        if not self.csv_path.text().strip():
            QMessageBox.warning(self, "Aucun fichier", "Veuillez choisir un CSV d'abord.")
            return

        weights = {
            "off_country": self.w_off.value(),
            "vpn_ip2p":    self.w_ip2p.value(),
            "hosting":     self.w_host.value(),
            "vpn_other":   self.w_oth.value(),
            "unique":      self.w_uni.value(),
            "few":         self.w_few.value(),
            "unusual":     self.w_unu.value(),
            "isp_fr":      self.w_isp_fr.value(),
            "isp_foreign": self.w_isp_foreign.value(),
        }
        cfg = {
            "csv_path": self.csv_path.text().strip(),
            "api_key": self.api_key.text().strip() or None,
            "ip2p_path": self.ip2p.text().strip(),
            "raw_exclusions": self.exclusions.text().strip(),
            "unusual_ranges": self.unusual.text().strip(),
            "suspect_windows": self.suspect.text().strip(),
            "main_country": self.main_country.currentText().strip() or "France",
            "weights": weights,
            "exclude_others": self.chk_excl_others.isChecked(),
        }
        self._want_html = self.chk_html.isChecked()
        self._want_pdf  = self.chk_pdf.isChecked()
        self._out_dir   = self.out_dir.text().strip() or "."

        # UI state
        self.btn_run.setEnabled(False); self.btn_cancel.setEnabled(True)
        self.progress.setValue(0); self.log.clear()
        self.log.append("Démarrage de l'analyse…")

        # lancer le worker
        self.worker = AnalysisWorker(cfg)
        self.worker.progress.connect(self.on_progress)
        self.worker.error.connect(self.on_error)
        self.worker.finished.connect(self.on_finished)
        self.worker.start()

    def cancel_analysis(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.log.append("⏸ Annulation demandée…")

    # ----------- slots
    def on_progress(self, cur, total, msg):
        pct = 0 if total == 0 else int(cur * 100 / total)
        self.progress.setValue(pct)
        self.log.append(msg)

    def on_error(self, err):
        self.btn_run.setEnabled(True); self.btn_cancel.setEnabled(False)
        QMessageBox.critical(self, "Erreur pendant l'analyse", err)

    def on_finished(self, data):
        global ignored_ipv6
        self.btn_run.setEnabled(True); self.btn_cancel.setEnabled(False)

        if data.get("cancelled"):
            self.log.append("Analyse annulée.")
            QMessageBox.information(self, "Analyse annulée", "Le traitement a été interrompu.")
            return

        # payload
        results = data["results"]
        suspects = data["suspects"]
        country_counts = data["country_counts"]
        habitudes_out_sorted = data["habitudes_out_sorted"]
        habitudes_in_sorted  = data["habitudes_in_sorted"]
        unusual_list = data["unusual_list"]
        timeouts = data["timeouts"]
        excluded_count = data["excluded_count"]
        prefix_freq = data["prefix_freq"]
        suspect_hits = data["suspect_hits"]
        suspect_windows_str = data["suspect_windows_str"]
        main_country = data["main_country"]
        exclusions = data["exclusions_list"]
        ignored_ipv6 = data.get("ignored_ipv6", 0)

        generated = []

        if self._want_html:
            html_path = export_html(
                results, exclusions, timeouts, suspects, country_counts,
                habitudes_out_sorted=habitudes_out_sorted,
                habitudes_in_sorted=habitudes_in_sorted,
                unusual_list=unusual_list,
                prefix_freq=prefix_freq,
                suspect_hits=suspect_hits, suspect_windows_str=suspect_windows_str,
                base_dir=self._out_dir, prefix="Rapport_complet", main_country=main_country,
                total_rows=len(results), excluded_count=excluded_count
            )
            generated.append(f"HTML : {html_path}")

        if self._want_pdf:
            pdf_path = export_pdf(
                results, suspects, country_counts, main_country=main_country,
                total_rows=len(results), excluded_count=excluded_count,
                timeouts=timeouts, unusual_list=unusual_list, exclusions=exclusions,
                habitudes_out_sorted=habitudes_out_sorted, habitudes_in_sorted=habitudes_in_sorted,
                prefix_freq=prefix_freq,
                suspect_hits=suspect_hits, suspect_windows_str=suspect_windows_str,
                base_dir=self._out_dir
            )
            generated.append(f"PDF : {pdf_path}")

        if generated:
            QMessageBox.information(self, "Terminé ✅", "Rapports générés :\n\n" + "\n".join(generated))
        else:
            QMessageBox.warning(self, "Aucun export", "Veuillez cocher au moins un format (HTML ou PDF).")

        # save config (inclut désormais les poids ISP)
        save_config({
            "api_key": self.api_key.text().strip(),
            "ip2proxy": self.ip2p.text().strip(),
            "unusual_ranges": self.unusual.text().strip(),
            "main_country": self.main_country.currentText().strip() or "France",
            "weights": {
                "off_country": self.w_off.value(),
                "vpn_ip2p":    self.w_ip2p.value(),
                "hosting":     self.w_host.value(),
                "vpn_other":   self.w_oth.value(),
                "unique":      self.w_uni.value(),
                "few":         self.w_few.value(),
                "unusual":     self.w_unu.value(),
                "isp_fr":      self.w_isp_fr.value(),
                "isp_foreign": self.w_isp_foreign.value(),
            },
            "output_dir": self._out_dir,
            "export_html": self._want_html,
            "export_pdf": self._want_pdf,
            "exclude_other_countries": self.chk_excl_others.isChecked(),
            "suspect_datetime_windows": self.suspect.text().strip()
        })

# =========================
# main
# =========================
def main():
    app = QApplication([])
    # Mode sombre (Qt6)
    app.setStyleSheet(qdarktheme.load_stylesheet("dark"))
    w = MainWindow()
    w.show()
    app.exec()

if __name__ == "__main__":
    main()
