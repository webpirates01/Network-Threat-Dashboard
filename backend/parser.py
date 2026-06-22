import pandas as pd

LOG_FILE = "data/logs.csv"

def load_logs():
    try:
        df = pd.read_csv(LOG_FILE, parse_dates=["timestamp"])
        return df
    except Exception:
        return pd.DataFrame()