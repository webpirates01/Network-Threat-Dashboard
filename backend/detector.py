from parser import load_logs
from datetime import datetime, timedelta

WINDOW_MINUTES  = 5    # time window for analysis
BRUTE_THRESHOLD = 5    # failed logins from same IP
SCAN_THRESHOLD  = 10   # unique ports from same IP
EXFIL_BYTES     = 200000  # bytes threshold

def get_severity(rule):
    return {"brute_force": "critical", "port_scan": "high", "exfil": "medium"}.get(rule, "low")

def detect():
    df = load_logs()
    if df.empty:
        return []

    cutoff = datetime.now() - timedelta(minutes=WINDOW_MINUTES)
    recent = df[df["timestamp"] >= cutoff].copy()
    alerts = []

    # Rule 1 — Brute force: many FAILED logins from same IP
    failed = recent[recent["status"] == "FAILED"]
    brute  = failed.groupby("src_ip").size()
    for ip, count in brute[brute >= BRUTE_THRESHOLD].items():
        alerts.append({
            "type":     "brute_force",
            "src_ip":   ip,
            "detail":   f"{count} failed logins in {WINDOW_MINUTES} min",
            "severity": get_severity("brute_force"),
            "time":     str(datetime.now().strftime("%H:%M:%S")),
        })

    # Rule 2 — Port scan: one IP hitting many different ports
    port_counts = recent.groupby("src_ip")["dst_port"].nunique()
    for ip, count in port_counts[port_counts >= SCAN_THRESHOLD].items():
        alerts.append({
            "type":     "port_scan",
            "src_ip":   ip,
            "detail":   f"{count} unique ports scanned",
            "severity": get_severity("port_scan"),
            "time":     str(datetime.now().strftime("%H:%M:%S")),
        })

    # Rule 3 — Data exfil: huge outbound transfer
    big = recent[recent["bytes"] >= EXFIL_BYTES]
    for _, row in big.iterrows():
        alerts.append({
            "type":     "exfil",
            "src_ip":   row["src_ip"],
            "detail":   f"{row['bytes']:,} bytes transferred",
            "severity": get_severity("exfil"),
            "time":     str(row["timestamp"].strftime("%H:%M:%S")),
        })

    return alerts

def get_stats():
    df = load_logs()
    if df.empty:
        return {}
    alerts = detect()
    return {
        "total_logs":    len(df),
        "total_alerts":  len(alerts),
        "critical":      sum(1 for a in alerts if a["severity"] == "critical"),
        "unique_ips":    int(df["src_ip"].nunique()),
    }

def get_traffic():
    df = load_logs()
    if df.empty:
        return []
    df["minute"] = df["timestamp"].dt.strftime("%H:%M")
    grouped = df.groupby("minute").size().reset_index(name="count")
    return grouped.tail(20).to_dict(orient="records")