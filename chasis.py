from pysnmp.hlapi.asyncio import *
import asyncio
import pandas as pd
import ipaddress
import os

COMMUNITY = "christ"
PORT = 161
BATCH_SIZE = 50

SUBNET = input("Enter subnet (ex: 192.168.1.0/24): ")

OIDS = {
    "lldpLocChassisId": "1.0.8802.1.1.2.1.3.2.0"
}


async def snmp_get(target, oid):
    errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
        SnmpEngine(),
        CommunityData(COMMUNITY, mpModel=1),
        UdpTransportTarget((target, PORT), timeout=1, retries=1),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )
    if errorIndication or errorStatus:
        return None
    for varBind in varBinds:
        return varBind[1]
    return None


def mac_bytes_to_str(octets):
    try:
        b = bytes(octets) if isinstance(octets, (bytearray,)) else bytes(octets.asNumbers())
        return ':'.join(f'{x:02x}' for x in b)
    except Exception:
        return str(octets)


async def scan_ip(ip):
    chassis_id = await snmp_get(ip, OIDS["lldpLocChassisId"])
    chassis_str = mac_bytes_to_str(chassis_id) if chassis_id else None
    status = "active" if chassis_str else "inactive"
    print(f"{ip} --> {status}")
    return {"IP": ip, "Chassis ID": chassis_str, "Status": status}


async def main():
    ip_list = [str(ip) for ip in ipaddress.IPv4Network(SUBNET)]
    print(f"\nScanning {len(ip_list)} IPs...\n")
    results = []
    for i in range(0, len(ip_list), BATCH_SIZE):
        batch = ip_list[i:i + BATCH_SIZE]
        batch_results = await asyncio.gather(*[scan_ip(ip) for ip in batch])
        results.extend(batch_results)

    new_df = pd.DataFrame(results)
    CSV_FILE = "chassis_ids.csv"

    if os.path.exists(CSV_FILE):
        print("\nCSV exists -> Updating existing status and chassis data...\n")
        old_df = pd.read_csv(CSV_FILE)
        merged_df = old_df.merge(new_df, on="IP", how="outer", suffixes=("_old", "_new"))
        merged_df["Chassis ID"] = merged_df.apply(
            lambda row: row["Chassis ID_new"] if pd.notna(row["Chassis ID_new"]) else row["Chassis ID_old"],
            axis=1
        )
        merged_df["Status"] = merged_df["Status_new"].combine_first(merged_df["Status_old"])
        merged_df = merged_df[["IP", "Chassis ID", "Status"]]
        merged_df.to_csv(CSV_FILE, index=False)
        print("CSV Updated Successfully")
    else:
        print("\nCSV not found - creating new one...\n")
        new_df.to_csv(CSV_FILE, index=False)
        print("CSV Created Successfully")

    print("\n=== Final Chassis Table ===")
    print(pd.read_csv(CSV_FILE))


if __name__ == "__main__":
    asyncio.run(main())
