# experiment_runner.py

import requests
import urllib3
import time
import json
import csv
import math
import subprocess
import sqlite3
import os
import threading
from datetime import datetime
from requests.auth import HTTPBasicAuth
from netmiko import ConnectHandler
from dotenv import load_dotenv

load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# إعدادات الاتصال بالبنية التحتية
# ============================================================
WAZUH_IP       = os.getenv("WAZUH_IP", "10.10.10.10")
INDEXER_PORT   = int(os.getenv("INDEXER_PORT", 9200))
WAZUH_USER     = os.getenv("WAZUH_USER", "")
WAZUH_PASS     = os.getenv("WAZUH_PASS", "")
INDEXER_URL    = f"https://{WAZUH_IP}:{INDEXER_PORT}/wazuh-alerts-*/_search"
OLLAMA_URL     = os.getenv("LLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL   = os.getenv("LLAMA_MODEL", "tinyllama")
VT_API_KEY     = os.getenv("VIRUSTOTAL_API_KEY", "")

KALI_IP        = os.getenv("KALI_IP", "192.168.52.128")   # عنوان جهاز Kali Linux
TARGET_IP      = os.getenv("UBUNTU_TARGET_HOST", "10.0.0.20")        # عنوان Ubuntu Target
ROUTER_IP      = os.getenv("ROUTER_HOST", "192.168.52.254")   # عنوان الموجّه R1
ROUTER_USER    = os.getenv("ROUTER_USER", "")
ROUTER_PASS    = os.getenv("ROUTER_PASS", "")

NUM_RUNS       = 5    # عدد مرات تنفيذ كل سيناريو
POLL_INTERVAL  = 1    # فاصل الاستطلاع بالثواني
MAX_WAIT       = 120  # أقصى وقت انتظار للتنبيه بالثواني
RESULTS_DIR    = "experiment_results"
RESULTS_FILE   = f"{RESULTS_DIR}/all_scenarios_results.json"
CSV_FILE       = f"{RESULTS_DIR}/summary_statistics.csv"

os.makedirs(RESULTS_DIR, exist_ok=True)

# ============================================================
# تعريف السيناريوهات التسعة
# ============================================================
SCENARIOS = {
    1: {
        "name": "SSH Brute-Force (VMware Target)",
        "description": "هجوم تخمين كلمة مرور SSH باستخدام Hydra على الهدف الافتراضي",
        "attack_command": [
            "ssh", f"{KALI_IP}",
            "-o", "StrictHostKeyChecking=no",
            "hydra -l wazuh-user -P /usr/share/wordlists/rockyou.txt "
            f"ssh://{TARGET_IP} -t 16 -f"
        ],
        "trigger_locally": True,
        "local_trigger": f"hydra -l wazuh-user -P /usr/share/wordlists/rockyou.txt "
                         f"ssh://{TARGET_IP} -t 16 -f",
        "expected_rule_keywords": ["brute", "authentication", "multiple"],
        "expected_attack_type":   "Brute-Force Attack",
        "has_acl":   True,
        "has_vt":    True,
        "has_tarpit": False,
        "cooldown":  90
    },
    2: {
        "name": "External Brute-Force on Router (Cisco IOS)",
        "description": "هجوم تخمين على SSH الموجّه الرئيسي R1",
        "local_trigger": f"hydra -l admin -P /usr/share/wordlists/rockyou.txt "
                         f"ssh://{ROUTER_IP} -t 4 -f",
        "trigger_locally": True,
        "expected_rule_keywords": ["cisco", "router", "login"],
        "expected_attack_type":   "Brute-Force Attack",
        "has_acl":   True,
        "has_vt":    True,
        "has_tarpit": True,
        "cooldown":  90
    },
    3: {
        "name": "Legitimate Admin Access (Safe-list)",
        "description": "دخول مشروع من IP موثوق - اختبار عدم الحجب (TN)",
        "local_trigger": f"ssh admin@{ROUTER_IP} 'show running-config' && "
                         f"ssh admin@{ROUTER_IP} 'conf t'",
        "trigger_locally": True,
        "expected_rule_keywords": ["login", "success", "configuration"],
        "expected_attack_type":   "Successful Authentication",
        "has_acl":   False,
        "has_vt":    False,
        "has_tarpit": False,
        "expected_fp": False,
        "cooldown":  60
    },
    4: {
        "name": "Internal Attack - webterm-1",
        "description": "هجوم داخلي متدرّج من webterm-1 حتى الحجب الدائم",
        "local_trigger": "ssh -p 22 192.168.10.1 'for i in 1 2 3; do "
                         "ssh wronguser@10.0.0.20; done'",
        "trigger_locally": True,
        "expected_rule_keywords": ["syslog", "password", "missed", "failed"],
        "expected_attack_type":   "Authentication Failure (Possible Typo)",
        "has_acl":   True,
        "has_vt":    True,
        "has_tarpit": True,
        "progressive": True,
        "attempts_to_block": 3,
        "cooldown":  90
    },
    5: {
        "name": "Port Scanning - Nmap Aggressive",
        "description": "فحص شامل للمنافذ باستخدام nmap -A -v",
        "local_trigger": f"nmap -A -v {TARGET_IP}",
        "trigger_locally": True,
        "expected_rule_keywords": ["suricata", "scan", "recon", "inbound"],
        "expected_attack_type":   "Reconnaissance / Port Scanning",
        "has_acl":   True,
        "has_vt":    True,
        "has_tarpit": True,
        "tarpit_port": 3306,
        "cooldown":  60
    },
    6: {
        "name": "Gradual Attack - webterm1 Progressive Blocking",
        "description": "هجوم تصاعدي بثلاث مراحل حتى الحجب الدائم",
        "local_trigger": "for i in 1 2 3; do ssh wronguser@10.0.0.20; "
                         "sleep 5; done",
        "trigger_locally": True,
        "expected_rule_keywords": ["syslog", "password", "failed"],
        "expected_attack_type":   "Authentication Failure (Possible Typo)",
        "has_acl":   True,
        "has_vt":    False,
        "has_tarpit": False,
        "progressive": True,
        "attempts_to_block": 3,
        "cooldown":  90
    },
    7: {
        "name": "FIM - /etc/passwd Modification",
        "description": "حقن مستخدم ذو UID 0 في /etc/passwd عبر Kali",
        "local_trigger": (
            f"ssh hassan@{TARGET_IP} -p 2222 "
            "'sudo bash -c \\'echo \"attacker:x:0:0::/home/attacker:"
            "/bin/bash\" >> /etc/passwd\\''"
        ),
        "trigger_locally": True,
        "expected_rule_keywords": ["integrity", "checksum", "passwd", "fim"],
        "expected_attack_type":   "General Security Threat",
        "has_acl":   False,
        "has_vt":    False,
        "has_fim":   True,
        "fim_path":  "/etc/passwd",
        "cooldown":  60
    },
    8: {
        "name": "CIS Benchmark Deviation - PermitRootLogin",
        "description": "تفعيل PermitRootLogin في sshd_config ثم المعالجة التلقائية",
        "local_trigger": (
            f"ssh hassan@{TARGET_IP} -p 2222 "
            "'sudo sed -i \\'s/PermitRootLogin no/PermitRootLogin yes/g\\' "
            "/etc/ssh/sshd_config && sudo systemctl restart sshd'"
        ),
        "trigger_locally": True,
        "expected_rule_keywords": ["syscheck", "sshd_config", "integrity"],
        "expected_attack_type":   "General Security Threat",
        "has_acl":   False,
        "has_vt":    False,
        "has_cis_remediation": True,
        "cooldown":  60
    },
    9: {
        "name": "Malware Drop - EICAR String",
        "description": "إسقاط ملف EICAR في /etc/iker والتحقق عبر VirusTotal",
        "local_trigger": (
            f"ssh hassan@{TARGET_IP} -p 2222 "
            "'echo -n \\'X5O!P%@AP[4\\\\PZX54(P^)7CC)7}EICAR-STANDARD"
            "-ANTIVIRUS-TEST-FILE!H+H*\\' > /tmp/iker && "
            "sudo mv /tmp/iker /etc/iker'"
        ),
        "trigger_locally": True,
        "expected_rule_keywords": ["fim", "added", "new file", "integrity"],
        "expected_attack_type":   "Malware Infection / Backdoor",
        "has_acl":   False,
        "has_vt":    True,
        "has_fim":   True,
        "fim_path":  "/etc/iker",
        "cooldown":  60
    }
}

# ============================================================
# دوال القياس الأساسية
# ============================================================

def get_latest_alert_timestamp():
    """يُعيد أحدث طابع زمني لتنبيه في Wazuh Indexer"""
    query = {
        "size": 1,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"range": {"rule.level": {"gte": 3}}}
    }
    try:
        r = requests.get(
            INDEXER_URL,
            auth=HTTPBasicAuth(WAZUH_USER, WAZUH_PASS),
            json=query, verify=False, timeout=5
        )
        hits = r.json().get("hits", {}).get("hits", [])
        if hits:
            return hits[0]["_source"].get("@timestamp", "")
    except Exception:
        pass
    return ""


def wait_for_new_alert(baseline_timestamp, keywords, timeout=MAX_WAIT):
    """
    ينتظر ظهور تنبيه جديد يحتوي على الكلمات المفتاحية المطلوبة
    يُعيد: (التنبيه، زمن الكشف بالثواني) أو (None, None)
    """
    start = time.time()
    while time.time() - start < timeout:
        query = {
            "size": 10,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"rule.level": {"gte": 3}}},
                        {"range": {"@timestamp": {"gt": baseline_timestamp}}}
                    ]
                }
            }
        }
        try:
            r = requests.get(
                INDEXER_URL,
                auth=HTTPBasicAuth(WAZUH_USER, WAZUH_PASS),
                json=query, verify=False, timeout=5
            )
            hits = r.json().get("hits", {}).get("hits", [])
            for hit in hits:
                desc = hit["_source"].get("rule", {}).get("description", "").lower()
                if any(kw.lower() in desc for kw in keywords):
                    elapsed = time.time() - start
                    return hit["_source"], round(elapsed, 2)
        except Exception:
            pass
        time.sleep(POLL_INTERVAL)
    return None, None


def measure_llm_latency(alert_source):
    """يقيس زمن استدلال TinyLlama لتنبيه معيّن"""
    rule_desc = alert_source.get("rule", {}).get("description", "No description")
    level     = alert_source.get("rule", {}).get("level", 0)
    log       = alert_source.get("full_log", "")[:300]

    prompt = (
        f"<|system|>\nYou are a SOC analyst. Analyze this alert concisely.\n"
        f"<|user|>\nRule: {rule_desc}\nLevel: {level}/15\nLog: {log}\n"
        f"<|assistant|>\nAnalysis: "
    )
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"num_predict": 120, "temperature": 0.1}
    }
    t0 = time.time()
    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=30)
        response_text = r.json().get("response", "").strip()
    except Exception:
        response_text = "LLM Timeout"
    t_llm = round(time.time() - t0, 2)
    return t_llm, response_text


def measure_vt_latency(ip="45.45.45.30"):
    """يقيس زمن استعلام VirusTotal"""
    url     = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    t0 = time.time()
    try:
        r = requests.get(url, headers=headers, timeout=10)
        score = 0
        if r.status_code == 200:
            stats     = r.json().get("data", {}).get("attributes", {}) \
                                .get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total     = sum(stats.values())
            score     = int((malicious / total) * 100) if total > 0 else 0
    except Exception:
        score = -1
    t_vt = round(time.time() - t0, 2)
    return t_vt, score


def measure_acl_latency(attacker_ip="45.45.45.30", permanent=False):
    """يقيس زمن تطبيق قاعدة ACL على الموجّه عبر Netmiko"""
    cisco = {
        "device_type": "cisco_ios",
        "host":        ROUTER_IP,
        "username":    ROUTER_USER,
        "password":    ROUTER_PASS,
        "timeout":     30,
        "global_delay_factor": 2
    }
    t0 = time.time()
    success = False
    try:
        conn = ConnectHandler(**cisco)
        try:
            last_octet = int(attacker_ip.split(".")[-1])
        except Exception:
            last_octet = 10
        seq = 10 + (last_octet % 100)

        commands = [
            "ip access-list extended AI_BLOCK_LIST",
            f"{seq} deny ip host {attacker_ip} any",
            "99999 permit ip any any", "exit",
            "interface FastEthernet0/0", "ip access-group AI_BLOCK_LIST in",
            "interface FastEthernet2/0", "ip access-group AI_BLOCK_LIST in",
            "interface FastEthernet3/0", "ip access-group AI_BLOCK_LIST in",
            "exit"
        ]
        conn.send_config_set(commands, cmd_verify=False)
        conn.disconnect()
        success = True

        # إزالة القاعدة بعد القياس إذا لم يكن الحجب دائماً
        if not permanent:
            time.sleep(2)
            conn2 = ConnectHandler(**cisco)
            undo = [
                "ip access-list extended AI_BLOCK_LIST",
                f"no deny ip host {attacker_ip} any", "exit"
            ]
            conn2.send_config_set(undo, cmd_verify=False)
            conn2.disconnect()
    except Exception as e:
        print(f"    [ACL Error] {e}")

    t_acl = round(time.time() - t0, 2)
    return t_acl, success


def trigger_attack(scenario):
    """يُشغّل أمر الهجوم محلياً بدون انتظار الاكتمال"""
    cmd = scenario.get("local_trigger", "")
    if not cmd:
        return
    try:
        subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except Exception as e:
        print(f"    [Attack Trigger Warning] {e}")


def cleanup_between_runs(scenario_id, run_num):
    """تنظيف الحالة بين التشغيلات المتتالية"""
    print(f"    [Cleanup] Waiting {SCENARIOS[scenario_id]['cooldown']}s "
          f"before run {run_num + 1}...")

    # إعادة PermitRootLogin إلى no بعد سيناريو 8
    if scenario_id == 8:
        try:
            subprocess.run(
                f"ssh hassan@{TARGET_IP} -p 2222 "
                "'sudo sed -i \\'s/PermitRootLogin yes/"
                "PermitRootLogin no/g\\' /etc/ssh/sshd_config && "
                "sudo systemctl restart sshd'",
                shell=True, timeout=15,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except Exception:
            pass

    # حذف ملف EICAR إذا بقي بعد سيناريو 9
    if scenario_id == 9:
        try:
            subprocess.run(
                f"ssh hassan@{TARGET_IP} -p 2222 "
                "'sudo rm -f /etc/iker /tmp/iker'",
                shell=True, timeout=10,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except Exception:
            pass

    # إزالة المستخدم المحقون بعد سيناريو 7
    if scenario_id == 7:
        try:
            subprocess.run(
                f"ssh hassan@{TARGET_IP} -p 2222 "
                "'sudo sed -i \\'/attacker/d\\' /etc/passwd'",
                shell=True, timeout=10,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except Exception:
            pass

    time.sleep(SCENARIOS[scenario_id]["cooldown"])


# ============================================================
# دوال الإحصاء
# ============================================================

def calc_mean(values):
    return round(sum(values) / len(values), 2) if values else 0.0


def calc_std(values, mean):
    if len(values) < 2:
        return 0.0
    variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
    return round(math.sqrt(variance), 2)


def compute_statistics(runs_data, metric_key):
    """يحسب μ و σ لمقياس معيّن عبر جميع التشغيلات"""
    values = [r[metric_key] for r in runs_data if r.get(metric_key) is not None]
    if not values:
        return {"mean": None, "std": None, "values": []}
    mu    = calc_mean(values)
    sigma = calc_std(values, mu)
    return {"mean": mu, "std": sigma, "values": values}


# ============================================================
# تنفيذ سيناريو واحد — 5 تشغيلات
# ============================================================

def run_scenario(scenario_id):
    scenario = SCENARIOS[scenario_id]
    print(f"\n{'='*60}")
    print(f"[SCENARIO {scenario_id}] {scenario['name']}")
    print(f"الوصف: {scenario['description']}")
    print(f"{'='*60}")

    runs_data = []

    for run in range(NUM_RUNS):
        print(f"\n  --- التشغيل {run + 1}/{NUM_RUNS} ---")
        run_result = {
            "run":       run + 1,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "t_detect":  None,
            "t_llm":     None,
            "t_vt":      None,
            "t_acl":     None,
            "t_e2e":     None,
            "detected":  False,
            "fp_generated": False,
            "acl_success":  False,
            "vt_score":     None,
            "llm_response": "",
            "alert_level":  None,
            "alert_rule":   ""
        }

        # 1) تسجيل طابع زمني أساسي
        baseline_ts = get_latest_alert_timestamp()
        print(f"  [*] Baseline timestamp: {baseline_ts}")

        # 2) تشغيل الهجوم
        t_attack_start = time.time()
        print(f"  [*] Triggering attack: {scenario['local_trigger'][:60]}...")
        trigger_attack(scenario)

        # 3) انتظار التنبيه وقياس T_detect
        print(f"  [*] Waiting for Wazuh alert (keywords: "
              f"{scenario['expected_rule_keywords']})...")
        alert_source, t_detect = wait_for_new_alert(
            baseline_ts,
            scenario["expected_rule_keywords"],
            timeout=MAX_WAIT
        )

        if alert_source is None:
            print(f"  [!] No alert detected within {MAX_WAIT}s — "
                  f"marking as missed")
            runs_data.append(run_result)
            if run < NUM_RUNS - 1:
                cleanup_between_runs(scenario_id, run)
            continue

        run_result["detected"]    = True
        run_result["t_detect"]    = t_detect
        run_result["alert_level"] = alert_source.get("rule", {}).get("level")
        run_result["alert_rule"]  = alert_source.get("rule", {}) \
                                                 .get("description", "")
        print(f"  [+] Alert detected in {t_detect}s | "
              f"Level: {run_result['alert_level']} | "
              f"Rule: {run_result['alert_rule'][:50]}")

        # التحقق من الإنذار الكاذب (سيناريو 3)
        if scenario_id == 3:
            run_result["fp_generated"] = False
            print(f"  [+] Safe-list scenario: no block expected (TN)")

        # 4) قياس T_LLM
        print(f"  [*] Measuring TinyLlama inference latency...")
        t_llm, llm_text = measure_llm_latency(alert_source)
        run_result["t_llm"]         = t_llm
        run_result["llm_response"]  = llm_text[:100]
        print(f"  [+] LLM responded in {t_llm}s")

        # 5) قياس T_VT (إذا ينطبق على السيناريو)
        if scenario.get("has_vt"):
            print(f"  [*] Querying VirusTotal...")
            attacker_ip = "45.45.45.30" if scenario_id in [2] else "192.168.52.128"
            t_vt, vt_score = measure_vt_latency(attacker_ip)
            run_result["t_vt"]      = t_vt
            run_result["vt_score"]  = vt_score
            print(f"  [+] VirusTotal responded in {t_vt}s | Score: {vt_score}%")

        # 6) قياس T_ACL (إذا ينطبق)
        if scenario.get("has_acl") and scenario_id != 3:
            print(f"  [*] Measuring ACL application latency on Router R1...")
            test_ip = "45.45.45.99" if scenario_id == 2 else "192.168.52.200"
            t_acl, acl_ok = measure_acl_latency(
                attacker_ip=test_ip,
                permanent=False
            )
            run_result["t_acl"]        = t_acl
            run_result["acl_success"]  = acl_ok
            print(f"  [+] ACL applied in {t_acl}s | Success: {acl_ok}")

        # 7) حساب T_e2e
        components = [
            run_result.get("t_detect") or 0,
            run_result.get("t_llm")    or 0,
            run_result.get("t_vt")     or 0,
            run_result.get("t_acl")    or 0
        ]
        run_result["t_e2e"] = round(sum(components), 2)
        print(f"  [+] T_e2e = {run_result['t_e2e']}s")

        runs_data.append(run_result)

        # 8) تنظيف بين التشغيلات
        if run < NUM_RUNS - 1:
            cleanup_between_runs(scenario_id, run)

    # ============================================================
    # حساب الإحصاءات النهائية للسيناريو
    # ============================================================
    print(f"\n  [STATS] Computing μ and σ for Scenario {scenario_id}...")

    metrics = ["t_detect", "t_llm", "t_vt", "t_acl", "t_e2e"]
    stats   = {}
    for m in metrics:
        stats[m] = compute_statistics(runs_data, m)

    detection_rate = sum(1 for r in runs_data if r["detected"]) / NUM_RUNS
    fp_rate        = sum(1 for r in runs_data if r.get("fp_generated")) / NUM_RUNS

    scenario_result = {
        "scenario_id":      scenario_id,
        "scenario_name":    scenario["name"],
        "num_runs":         NUM_RUNS,
        "detection_rate":   round(detection_rate, 2),
        "false_positive_rate": round(fp_rate, 2),
        "statistics":       stats,
        "runs":             runs_data
    }

    # طباعة ملخص
    print(f"\n  ┌─ ملخص إحصائيات السيناريو {scenario_id} ────────────────────┐")
    print(f"  │  معدل الكشف       : {detection_rate*100:.0f}%"
          f" ({sum(1 for r in runs_data if r['detected'])}/{NUM_RUNS})")
    print(f"  │  T_detect : μ={stats['t_detect']['mean']}s  "
          f"σ={stats['t_detect']['std']}s")
    print(f"  │  T_LLM    : μ={stats['t_llm']['mean']}s  "
          f"σ={stats['t_llm']['std']}s")
    if stats["t_vt"]["mean"]:
        print(f"  │  T_VT     : μ={stats['t_vt']['mean']}s  "
              f"σ={stats['t_vt']['std']}s")
    if stats["t_acl"]["mean"]:
        print(f"  │  T_ACL    : μ={stats['t_acl']['mean']}s  "
              f"σ={stats['t_acl']['std']}s")
    print(f"  │  T_e2e    : μ={stats['t_e2e']['mean']}s  "
          f"σ={stats['t_e2e']['std']}s")
    print(f"  └───────────────────────────────────────────────────────┘")

    return scenario_result


# ============================================================
# حفظ النتائج
# ============================================================

def save_results_json(all_results):
    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)
    print(f"\n[+] النتائج الكاملة محفوظة في: {RESULTS_FILE}")


def save_results_csv(all_results):
    rows = []
    for sr in all_results:
        sid   = sr["scenario_id"]
        sname = sr["scenario_name"]
        stats = sr["statistics"]
        rows.append({
            "scenario_id":       sid,
            "scenario_name":     sname,
            "detection_rate":    sr["detection_rate"],
            "fp_rate":           sr["false_positive_rate"],
            "t_detect_mean":     stats["t_detect"]["mean"],
            "t_detect_std":      stats["t_detect"]["std"],
            "t_llm_mean":        stats["t_llm"]["mean"],
            "t_llm_std":         stats["t_llm"]["std"],
            "t_vt_mean":         stats["t_vt"]["mean"],
            "t_vt_std":          stats["t_vt"]["std"],
            "t_acl_mean":        stats["t_acl"]["mean"],
            "t_acl_std":         stats["t_acl"]["std"],
            "t_e2e_mean":        stats["t_e2e"]["mean"],
            "t_e2e_std":         stats["t_e2e"]["std"],
        })

    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"[+] ملف CSV للإحصاءات محفوظ في: {CSV_FILE}")


def save_per_scenario_csv(scenario_result):
    """يحفظ ملف CSV مستقل لكل سيناريو بكل تشغيلاته"""
    sid      = scenario_result["scenario_id"]
    filename = f"{RESULTS_DIR}/scenario_{sid}_runs.csv"
    runs     = scenario_result["runs"]
    if not runs:
        return

    fieldnames = list(runs[0].keys())
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(runs)
    print(f"  [+] بيانات التشغيلات محفوظة في: {filename}")


# ============================================================
# طباعة الجدول النهائي (مطابق لجداول الرسالة)
# ============================================================

def print_final_table(all_results):
    print("\n\n" + "="*75)
    print("  الجدول النهائي الشامل — مقاييس الأداء عبر السيناريوهات التسعة")
    print("="*75)
    header = (
        f"{'#':<3} {'السيناريو':<35} "
        f"{'T_detect μ±σ':<16} {'T_e2e μ±σ':<15} {'DR':>5} {'FPR':>5}"
    )
    print(header)
    print("-"*75)

    total_tp  = 0
    total_tn  = 0
    total_fp  = 0
    total_fn  = 0

    for sr in all_results:
        sid   = sr["scenario_id"]
        stats = sr["statistics"]
        dr    = sr["detection_rate"]
        fpr   = sr["false_positive_rate"]

        td_str = (
            f"{stats['t_detect']['mean']}±{stats['t_detect']['std']}"
            if stats["t_detect"]["mean"] else "N/A"
        )
        e2e_str = (
            f"{stats['t_e2e']['mean']}±{stats['t_e2e']['std']}"
            if stats["t_e2e"]["mean"] else "N/A"
        )

        # تصنيف TP/TN/FP/FN
        if sid == 3:
            result_label = "TN"
            total_tn    += 1
        elif dr == 1.0 and fpr == 0.0:
            result_label = "TP"
            total_tp    += 1
        elif dr < 1.0:
            result_label = "FN"
            total_fn    += 1
        else:
            result_label = "FP"
            total_fp    += 1

        name_short = sr["scenario_name"][:33]
        print(
            f"{sid:<3} {name_short:<35} "
            f"{td_str:<16} {e2e_str:<15} "
            f"{dr*100:>4.0f}% {fpr*100:>4.0f}%   [{result_label}]"
        )

    print("-"*75)

    # المقاييس الإجمالية
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0
    recall    = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 1.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)

    print(f"\n  الإجمالي: TP={total_tp}  TN={total_tn}  FP={total_fp}  FN={total_fn}")
    print(f"  Precision = {precision:.2f}   Recall = {recall:.2f}   F1 = {f1:.2f}")
    print("="*75)


# ============================================================
# نقطة الدخول الرئيسية
# ============================================================

def main():
    print("\n" + "="*60)
    print("  AI-Driven SOC Pipeline — Experimental Evaluation Runner")
    print(f"  {NUM_RUNS} runs per scenario × 9 scenarios")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    # اختياري: تشغيل سيناريوهات محددة فقط
    # scenarios_to_run = [1, 2, 3]
    scenarios_to_run = list(SCENARIOS.keys())  # الكل

    all_results = []

    for sid in scenarios_to_run:
        scenario_result = run_scenario(sid)
        save_per_scenario_csv(scenario_result)
        all_results.append(scenario_result)

        # حفظ تدريجي بعد كل سيناريو
        save_results_json(all_results)

    # الحفظ النهائي
    save_results_json(all_results)
    save_results_csv(all_results)
    print_final_table(all_results)

    print(f"\n[DONE] اكتمل التقييم في: "
          f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[DONE] الملفات المحفوظة في مجلد: {RESULTS_DIR}/")


if __name__ == "__main__":
    main()
