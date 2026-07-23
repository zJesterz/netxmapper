import pandas as pd
import os
import hashlib
import subprocess


MANUAL_CHASSIS_MAP = {
    "00:17:7c:6b:2d:2a": "192.168.1.22",
}


def get_local_ips():
    ips = set()
    try:
        result = subprocess.run(
            ["ipconfig"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "IPv4" in line and ":" in line:
                ip = line.split(":")[-1].strip()
                if ip:
                    ips.add(ip)
    except Exception:
        pass
    return ips


def normalize_mac(mac):
    return mac.strip().lower().replace("-", ":")


def main():
    local_ips = get_local_ips()
    print(f"Local machine IPs detected: {local_ips}")

    summary = pd.read_csv("switch_summary.csv")
    summary["Status"] = summary["Status"].astype(str).str.strip().str.lower()
    summary = summary[~summary["IP"].isin(local_ips)]

    chassis_to_ip = {}
    sysname_to_ip = {}
    for _, row in summary.iterrows():
        ip = str(row["IP"]).strip()
        chassis = str(row.get("Local Chassis ID", "")).strip()
        if chassis.lower() not in ("", "nan", "none"):
            chassis_to_ip[normalize_mac(chassis)] = ip
        sysname = str(row.get("Local SysName", "")).strip()
        if sysname.lower() not in ("", "nan", "none"):
            sysname_to_ip[sysname.lower()] = ip

    arp_mac_to_ip = {}
    if os.path.exists("arp_mappings.csv") and os.path.getsize("arp_mappings.csv") > 5:
        arp_df = pd.read_csv("arp_mappings.csv")
        for _, row in arp_df.iterrows():
            mac = normalize_mac(str(row["MAC"]).strip())
            ip = str(row["IP"]).strip()
            arp_mac_to_ip[mac] = ip
        print(f"Loaded {len(arp_mac_to_ip)} ARP MAC -> IP mappings")

    lldp = pd.read_csv("lldp_neighbors.csv")

    network_connections = []
    unresolved = {}

    for _, row in lldp.iterrows():
        local_ip = str(row["Local IP"]).strip()
        neighbor_chassis = str(row["Neighbor Chassis ID"]).strip()
        neighbor_port = str(row.get("Neighbor Port", "")).strip()
        neighbor_sysname = str(row.get("Neighbor SysName", "")).strip()
        neighbor_mgmt = str(row.get("Neighbor Management IP", "")).strip()
        nm = normalize_mac(neighbor_chassis)

        resolved_ip = chassis_to_ip.get(nm)
        if not resolved_ip:
            resolved_ip = MANUAL_CHASSIS_MAP.get(nm)
        if not resolved_ip and neighbor_mgmt.lower() not in ("", "nan", "none"):
            resolved_ip = neighbor_mgmt
        if not resolved_ip and neighbor_sysname.lower() not in ("", "nan", "none"):
            resolved_ip = sysname_to_ip.get(neighbor_sysname.lower())
        if not resolved_ip:
            resolved_ip = arp_mac_to_ip.get(nm)

        if not resolved_ip:
            resolved_ip = "unknown"
            if nm not in unresolved:
                unresolved[nm] = {
                    "chassis": neighbor_chassis,
                    "sysname": neighbor_sysname,
                    "connected_from": [],
                    "ports": [],
                }
            unresolved[nm]["connected_from"].append(local_ip)
            unresolved[nm]["ports"].append(neighbor_port)

        network_connections.append([local_ip, "", resolved_ip, neighbor_port])

    if unresolved:
        print("\n=== Unresolved Neighbor Chassis IDs ===")
        print("Add these to MANUAL_CHASSIS_MAP in Topology.py:\n")
        for mac, info in unresolved.items():
            print(f'    "{mac}": "<IP_ADDRESS>",')
            print(f"        # {info['chassis']} (sysName: {info['sysname'] or 'N/A'})")
            print(f"        # Connected from: {', '.join(info['connected_from'])}")
            print(f"        # Ports: {', '.join(info['ports'])}")
        print()

    df_network = pd.DataFrame(
        network_connections,
        columns=["Local IP", "Local Port", "Neighbor IP", "Neighbor Port"]
    )

    df_network = df_network[df_network["Neighbor IP"].str.lower() != "unknown"]

    if not df_network.empty:
        df_network["pair_key"] = df_network.apply(
            lambda r: "-".join(sorted([r["Local IP"], r["Neighbor IP"]])), axis=1)
        df_network["port_key"] = df_network.apply(
            lambda r: "-".join(sorted([r["Local Port"], r["Neighbor Port"]])), axis=1)
        df_network = df_network.drop_duplicates(subset=["pair_key", "port_key"]).drop(
            columns=["pair_key", "port_key"]
        )

    def hash_df(df):
        df_sorted = df.sort_index(axis=1).sort_values(by=list(df.columns))
        return hashlib.md5(pd.util.hash_pandas_object(df_sorted, index=False).values.tobytes()).hexdigest()

    csv_file = "network_connections.csv"
    new_hash = hash_df(df_network)

    if os.path.exists(csv_file):
        existing_df = pd.read_csv(csv_file).astype(str).apply(lambda x: x.str.strip())
        old_hash = hash_df(existing_df)
        if new_hash == old_hash:
            print("No changes in network connections. CSV not updated.")
        else:
            df_network.to_csv(csv_file, index=False)
            print("Network connections changed. CSV overwritten with latest snapshot.")
    else:
        df_network.to_csv(csv_file, index=False)
        print("CSV did not exist. Created new CSV.")

    print("\n=== Network Connections ===")
    if df_network.empty:
        print("(no resolved connections)")
    else:
        print(df_network.to_string(index=False))

    devices_df = summary[["IP", "Status", "Local Chassis ID", "Local SysName"]].copy()
    devices_df.to_csv("devices.csv", index=False)
    print("\nDevices exported to devices.csv")


if __name__ == "__main__":
    main()
