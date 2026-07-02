from pysnmp.hlapi.asyncio import *
import asyncio
import pandas as pd
import os
import hashlib

COMMUNITY = "christ"
PORT = 161

OIDS = {
    "lldpRemChassisId": "1.0.8802.1.1.2.1.4.1.1.5",
    "lldpRemPortId": "1.0.8802.1.1.2.1.4.1.1.7",
    "lldpLocPortId": "1.0.8802.1.1.2.1.3.7.1.3",
}


async def snmp_walk(target, oid):
    results = {}
    async for (errorIndication, errorStatus, errorIndex, varBinds) in walkCmd(
        SnmpEngine(),
        CommunityData(COMMUNITY, mpModel=1),
        UdpTransportTarget((target, PORT), timeout=1, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False
    ):
        if errorIndication:
            print(f"[{target}] SNMP Error: {errorIndication}")
            break
        elif errorStatus:
            print(f"[{target}] SNMP Error: {errorStatus.prettyPrint()}")
            break
        else:
            for varBind in varBinds:
                results[str(varBind[0])] = varBind[1]
    return results


def oid_suffix(full_oid, column_oid):
    f = tuple(map(int, full_oid.strip('.').split('.')))
    c = tuple(map(int, column_oid.strip('.').split('.')))
    return f[len(c):]


def mac_bytes_to_str(octets):
    try:
        b = bytes(octets) if isinstance(octets, (bytearray,)) else bytes(octets.asNumbers())
        return ':'.join(f'{x:02x}' for x in b).lower()
    except Exception:
        return str(octets).lower()


def normalize_chassis(val):
    if isinstance(val, (bytes, bytearray)):
        return mac_bytes_to_str(val)
    s = str(val).strip().lower().replace("-", ":")
    parts = s.split(":")
    if all(len(p) == 2 and all(c in "0123456789abcdef" for c in p) for p in parts) and len(parts) == 6:
        return s
    try:
        ascii_chars = [chr(int(p, 16)) for p in parts if len(p) == 2]
        ascii_str = "".join(ascii_chars)
        return ascii_str.replace("-", ":").lower()
    except ValueError:
        return s


async def main():
    chassis_df = pd.read_csv("chassis_ids.csv")
    chassis_df["Status"] = chassis_df["Status"].astype(str).str.strip().str.lower()

    mac_to_ip = {}
    for _, row in chassis_df.iterrows():
        chassis = str(row["Chassis ID"]).strip().lower().replace("-", ":")
        if chassis in ["", "nan", None]:
            continue
        mac_to_ip[chassis] = row["IP"]

    network_connections = []
    active_devices = chassis_df[chassis_df["Status"] == "active"]

    if active_devices.empty:
        print("No active devices found in chassis_ids.csv. Exiting...")
        return

    print("\nActive devices to scan:")
    print(active_devices["IP"].tolist())

    for local_ip in active_devices["IP"]:
        print(f"Fetching LLDP info from {local_ip} ...")

        lldp_chassis = await snmp_walk(local_ip, OIDS["lldpRemChassisId"])
        lldp_rport = await snmp_walk(local_ip, OIDS["lldpRemPortId"])
        lldp_lportid = await snmp_walk(local_ip, OIDS["lldpLocPortId"])

        lldp = {}
        for foid, val in lldp_chassis.items():
            idx = oid_suffix(foid, OIDS["lldpRemChassisId"])
            norm_mac = normalize_chassis(val)
            lldp.setdefault(idx, {})["Neighbor Chassis"] = norm_mac

        for foid, val in lldp_rport.items():
            idx = oid_suffix(foid, OIDS["lldpRemPortId"])
            lldp.setdefault(idx, {})["Neighbor Port"] = str(val)

        local_ports = {oid_suffix(foid, OIDS["lldpLocPortId"]): str(val)
                       for foid, val in lldp_lportid.items()}

        for (timeMark, local_port, rem_idx), v in lldp.items():
            lport = local_ports.get((local_port,), f"LocalPort{local_port}")
            neighbor_mac = v.get("Neighbor Chassis", "unknown").replace("-", ":").lower()
            neighbor_ip = mac_to_ip.get(neighbor_mac, "unknown")
            neighbor_port = v.get("Neighbor Port", "unknown")
            network_connections.append([local_ip, lport, neighbor_ip, neighbor_port])

    df_network = pd.DataFrame(
        network_connections,
        columns=["Local IP", "Local Port", "Neighbor IP", "Neighbor Port"]
    ).astype(str).apply(lambda x: x.str.strip())

    df_network = df_network[df_network["Neighbor IP"].str.lower() != "unknown"]

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

    print("\n=== Final Network Connections ===")
    print(df_network)


if __name__ == "__main__":
    asyncio.run(main())
