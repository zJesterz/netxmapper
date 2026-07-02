from pysnmp.hlapi.asyncio import *
import asyncio
import pandas as pd
import numpy as np
import os
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import joblib
from sklearn.preprocessing import StandardScaler

SWITCH_IPS = ["192.168.1.21", "192.168.1.22", "192.168.1.23"]
COMMUNITY = "christ"
PORT = 161

DATA_FILE = "network_data.csv"
MODEL_FILE = "isolation_forest_model.pkl"

OIDS = {
    "ifName": "1.3.6.1.2.1.31.1.1.1.1",
    "ifSpeed": "1.3.6.1.2.1.2.2.1.5",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    "ifInOctets": "1.3.6.1.2.1.2.2.1.10",
    "ifOutOctets": "1.3.6.1.2.1.2.2.1.16",
    "ifInUcastPkts": "1.3.6.1.2.1.2.2.1.11",
    "ifOutUcastPkts": "1.3.6.1.2.1.2.2.1.17",
    "ifInNUcastPkts": "1.3.6.1.2.1.2.2.1.12",
    "ifOutNUcastPkts": "1.3.6.1.2.1.2.2.1.18",
    "ifInDiscards": "1.3.6.1.2.1.2.2.1.13",
    "ifOutDiscards": "1.3.6.1.2.1.2.2.1.19",
    "ifInErrors": "1.3.6.1.2.1.2.2.1.14",
    "ifOutErrors": "1.3.6.1.2.1.2.2.1.20"
}


async def snmp_walk(target_ip, community, oid):
    results = {}
    async for (errorIndication, errorStatus, errorIndex, varBinds) in walkCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        UdpTransportTarget((target_ip, PORT)),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False
    ):
        if errorIndication:
            print(f"SNMP Error for {target_ip}: {errorIndication}")
            return None
        elif errorStatus:
            print(f"SNMP Error for {target_ip}: {errorStatus.prettyPrint()}")
            return None
        else:
            for varBind in varBinds:
                oid_str = str(varBind[0])
                val = varBind[1]
                results[oid_str] = val
    return results


def oid_suffix(full_oid, column_oid):
    f = tuple(int(x) for x in full_oid.strip('.').split('.'))
    c = tuple(int(x) for x in column_oid.strip('.').split('.'))
    return f[len(c):]


async def get_performance_data(switch_list, community):
    all_data = []
    metrics_to_poll = {
        "ifName": OIDS["ifName"],
        "ifSpeed": OIDS["ifSpeed"],
        "ifOperStatus": OIDS["ifOperStatus"],
        "InOctets": OIDS["ifInOctets"],
        "OutOctets": OIDS["ifOutOctets"],
        "InUcastPkts": OIDS["ifInUcastPkts"],
        "OutUcastPkts": OIDS["ifOutUcastPkts"],
        "InNUcastPkts": OIDS["ifInNUcastPkts"],
        "OutNUcastPkts": OIDS["ifOutNUcastPkts"],
        "InDiscards": OIDS["ifInDiscards"],
        "OutDiscards": OIDS["ifOutDiscards"],
        "InErrors": OIDS["ifInErrors"],
        "OutErrors": OIDS["ifOutErrors"]
    }

    for ip in switch_list:
        switch_metrics = {}
        for metric_name, oid in metrics_to_poll.items():
            raw_results = await snmp_walk(ip, community, oid)
            if raw_results is None:
                continue
            for full_oid, value in raw_results.items():
                interface_index = oid_suffix(full_oid, oid)[-1]
                if interface_index not in switch_metrics:
                    switch_metrics[interface_index] = {'Switch': ip, 'InterfaceID': interface_index}
                switch_metrics[interface_index][metric_name] = int(value) if str(value).isdigit() else str(value)
        all_data.extend(list(switch_metrics.values()))

    if not all_data:
        return pd.DataFrame()

    df = pd.DataFrame(all_data)

    num_cols = ['InOctets', 'OutOctets', 'InUcastPkts', 'OutUcastPkts',
                'InNUcastPkts', 'OutNUcastPkts', 'InDiscards', 'OutDiscards',
                'InErrors', 'OutErrors', 'ifSpeed']
    for col in num_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    df['TotalPackets'] = df['InUcastPkts'] + df['OutUcastPkts'] + df['InNUcastPkts'] + df['OutNUcastPkts']
    df['ErrorRate%'] = ((df['InErrors'] + df['OutErrors']) / df['TotalPackets'].replace(0, 1)) * 100
    df['DiscardRate%'] = ((df['InDiscards'] + df['OutDiscards']) / df['TotalPackets'].replace(0, 1)) * 100
    df['ifSpeed'] = df['ifSpeed'].replace(0, np.nan)
    df['Utilization%'] = ((df['InOctets'] + df['OutOctets']) * 8 / df['ifSpeed']) * 100
    df = df.dropna(subset=['Utilization%'])

    df['Timestamp'] = pd.Timestamp.now()

    return df


def save_to_csv(df, filename=DATA_FILE):
    if os.path.exists(filename):
        df.to_csv(filename, mode='a', header=False, index=False)
    else:
        df.to_csv(filename, index=False)


def prepare_features(df, scaler=None, fit_scaler=False):
    X = df[['ErrorRate%', 'DiscardRate%', 'Utilization%']].copy()
    if fit_scaler:
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        return X_scaled, scaler
    else:
        X_scaled = scaler.transform(X)
        return X_scaled, scaler


def train_isolation_forest(data_file=DATA_FILE, model_file=MODEL_FILE):
    df = pd.read_csv(data_file)
    X, scaler = prepare_features(df, fit_scaler=True)
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(X)
    joblib.dump({"model": model, "scaler": scaler}, model_file)
    print("Isolation Forest model trained and saved.")
    return model, scaler


def load_model(model_file=MODEL_FILE):
    if os.path.exists(model_file):
        obj = joblib.load(model_file)
        return obj["model"], obj["scaler"]
    return None, None


def detect_anomalies(df, model, scaler):
    X, _ = prepare_features(df, scaler=scaler, fit_scaler=False)
    df['Anomaly'] = model.predict(X)
    return df


def plot_anomalies(df):
    anomalies = df[df['Anomaly'] == -1]
    plt.figure(figsize=(10, 6))
    plt.scatter(df['Timestamp'], df['Utilization%'], label='Normal', alpha=0.5)
    plt.scatter(anomalies['Timestamp'], anomalies['Utilization%'], color='red', label='Anomaly')
    plt.xlabel('Time')
    plt.ylabel('Utilization%')
    plt.legend()
    plt.show()


async def main_loop():
    while True:
        df = await get_performance_data(SWITCH_IPS, COMMUNITY)
        if df.empty:
            print("No data collected.")
        else:
            save_to_csv(df)
            model, scaler = load_model()

            if model is None or scaler is None:
                if os.path.exists(DATA_FILE):
                    existing_data = pd.read_csv(DATA_FILE)
                    if len(existing_data) >= 500:
                        print("Training model with collected baseline data...")
                        model, scaler = train_isolation_forest()
                    else:
                        print(f"Model not found. Need at least 500 samples. Current: {len(existing_data)}")
                else:
                    print("Model not found. Train it after collecting baseline data.")

            if model and scaler:
                df_anomaly = detect_anomalies(df, model, scaler)
                print(df_anomaly[['Switch', 'InterfaceID', 'Utilization%', 'ErrorRate%', 'DiscardRate%', 'Anomaly']])
                plot_anomalies(df_anomaly)

        print("Sleeping 5 minutes...")
        await asyncio.sleep(300)


if __name__ == "__main__":
    asyncio.run(main_loop())
