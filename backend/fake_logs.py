import csv, random, time, os
from datetime import datetime

LOG_FILE = "data/logs.csv"
FIELDS = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "bytes", "status"]

NORMAL_IPS   = [f"192.168.1.{i}" for i in range(10, 50)]
ATTACK_IPS   = ["10.0.0.99", "172.16.0.5", "203.0.113.7"]
PORTS        = [80, 443, 22, 3306, 8080, 53, 25]
PROTOCOLS    = ["TCP", "UDP", "ICMP"]

def random_log(attack=False):
    src = random.choice(ATTACK_IPS if attack else NORMAL_IPS)
    port = random.randint(1, 1024) if attack else random.choice(PORTS)
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip":    src,
        "dst_ip":    f"10.0.0.{random.randint(1,10)}",
        "dst_port":  port,
        "protocol":  random.choice(PROTOCOLS),
        "bytes":     random.randint(50000, 900000) if attack else random.randint(100, 5000),
        "status":    random.choice(["FAILED", "BLOCKED"]) if attack else "OK",
    }

def generate(n=200):
    os.makedirs("data", exist_ok=True)
    with open(LOG_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        for i in range(n):
            writer.writerow(random_log(attack=(i % 15 == 0)))

def stream_live():
    """Append one new log every second (run in background thread)."""
    while True:
        with open(LOG_FILE, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDS)
            writer.writerow(random_log(attack=random.random() < 0.1))
        time.sleep(1)

if __name__ == "__main__":
    generate()
    print("Generated 200 seed logs → data/logs.csv")