from pysnmp.hlapi.asyncio import *
import asyncio
import pandas as pd
import subprocess
import platform
import ipaddress

COMMUNITY = "christ"
PORT = 161
BATCH_SIZE = 50

# --- Config: list your switch management IPs here (optional) ---
# Leave empty to be prompted, with an option to auto-discover via subnet scan.
SWITCH_IPS = []

# LLDP local + remote table OIDs
OID_LOC_CHASSIS_ID = "1.0.8802.1.1.2.1.3.2.0"
OID_LOC_SYS_NAME = "1.0.8802.1.1.2.1.3.3.0"

OID_REM_CHASSIS_ID = "1.0.8802.1.1.2.1.4.1.1.5"
OID_REM_PORT_ID = "1.0.8802.1.1.2.1.4.1.1.7"
OID_REM_PORT_DESC = "1.0.8802.1.1.2.1.4.1.1.8"
OID_REM_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.9"

# lldpRemManAddrTable: carries the neighbor's advertised management IP.
# Unlike other LLDP columns, the address itself is embedded IN THE OID
# INDEX, not the returned value — see parse_management_ip() below.
OID_REM_MAN_ADDR_IF_SUBTYPE = "1.0.8802.1.1.2.1.4.2.1.2"

# ARP table OID: ipNetToMediaPhysAddress -- maps IP -> MAC on active switches.
# Indexed by (ifIndex, ipAddress), so the full OID is:
#   1.3.6.1.2.1.4.22.1.2.<ifIndex>.<a>.<b>.<c>.<d>  (for IPv4)
# Value is the MAC address as raw bytes.
OID_ARP_MAC = "1.3.6.1.2.1.4.22.1.2"


def ping_ip(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        result = subprocess.run(
            ["ping", param, "1", "-w", "2000", ip],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def octets_to_str(value):
    """Best-effort conversion of an OctetString to a readable string.
    Falls back to a MAC-style hex string if it looks like raw bytes,
    otherwise returns the printable string as-is."""
    try:
        raw = value.asOctets()
    except Exception:
        return str(value)

    # Try to decode as printable ASCII first (sysName, some chassis IDs are strings)
    try:
        text = raw.decode("utf-8")
        if text.isprintable():
            return text
    except Exception:
        pass

    # Fall back to MAC-style hex
    return ':'.join(f'{b:02x}' for b in raw)


async def get_single(target, oid):
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


async def walk_column(target, base_oid, max_rows=200):
    """Walks an SNMP table column by repeatedly calling nextCmd,
    since this pysnmp version's nextCmd returns one row per call
    rather than being an async generator.

    IMPORTANT: OIDs are compared as numeric tuples, not strings.
    pysnmp resolves the leading '1' to its MIB symbolic name 'iso'
    when stringified (e.g. 'iso.0.8802...' instead of '1.0.8802...'),
    which silently broke string-prefix matching against base_oid."""
    results = {}
    snmpEngine = SnmpEngine()
    base_tuple = tuple(int(x) for x in base_oid.split("."))
    current_oid = ObjectIdentity(base_oid)

    for _ in range(max_rows):
        errorIndication, errorStatus, errorIndex, varBinds = await nextCmd(
            snmpEngine,
            CommunityData(COMMUNITY, mpModel=1),
            UdpTransportTarget((target, PORT), timeout=1, retries=1),
            ContextData(),
            ObjectType(current_oid),
            lexicographicMode=False
        )

        if errorIndication or errorStatus:
            break
        if not varBinds:
            break

        # nextCmd's varBinds is a 2D structure: a tuple of rows, and each
        # row is a sequence of ObjectType (one per OID requested). Since
        # we only request one OID, varBinds[0] is the ROW (containing one
        # ObjectType), not the ObjectType itself — need one more level in.
        row = varBinds[0]
        try:
            varBind = row[0]
            pair = list(varBind)
        except Exception:
            break

        if len(pair) < 2:
            break

        oid, value = pair[0], pair[1]
        oid_tuple = tuple(oid)

        if oid_tuple[:len(base_tuple)] != base_tuple:
            break

        suffix = ".".join(str(x) for x in oid_tuple[len(base_tuple):])
        results[suffix] = value
        current_oid = ObjectIdentity(oid)

    return results


async def raw_lldp_dump(ip, base_oid="1.0.8802.1.1.2", max_rows=500):
    """Debug helper: walks the entire LLDP MIB subtree on a device and
    prints every OID/value pair found. Use this to sanity-check whether
    a switch has ANY LLDP data at all, independent of our table-parsing
    logic (acts like a mini snmpwalk when snmpwalk isn't available)."""
    print(f"\n--- Raw LLDP subtree dump for {ip} (base {base_oid}) ---")
    snmpEngine = SnmpEngine()
    current_oid = ObjectIdentity(base_oid)
    count = 0

    for _ in range(max_rows):
        errorIndication, errorStatus, errorIndex, varBinds = await nextCmd(
            snmpEngine,
            CommunityData(COMMUNITY, mpModel=1),
            UdpTransportTarget((ip, PORT), timeout=1, retries=1),
            ContextData(),
            ObjectType(current_oid),
            lexicographicMode=False
        )

        if errorIndication:
            print(f"  errorIndication: {errorIndication}")
            break
        if errorStatus:
            print(f"  errorStatus: {errorStatus.prettyPrint()}")
            break
        if not varBinds:
            print("  (no varBinds returned)")
            break

        varBind = varBinds[0]
        try:
            pair = list(varBind)
        except Exception as e:
            print(f"  couldn't unpack varBind: {e}")
            break

        if len(pair) < 2:
            print("  malformed row, stopping")
            break

        oid, value = pair[0], pair[1]
        oid_str = str(oid)

        if not oid_str.startswith(base_oid + "."):
            print(f"  walked past LLDP subtree at {oid_str}, stopping")
            break

        print(f"  {oid_str} = {value.prettyPrint()}")
        count += 1
        current_oid = ObjectIdentity(oid)

    if count == 0:
        print("  ZERO entries found under the LLDP subtree on this device.")
    else:
        print(f"  {count} total entries found.")
    print("--- end dump ---\n")


def parse_management_ip(suffix):
    """Parses a lldpRemManAddrTable index suffix to extract an embedded
    IPv4 address, if present.

    Index format per LLDP-MIB: timeMark.localPort.remIndex.addrSubtype.addrLen.<addr octets>
    For IPv4: addrSubtype=1, addrLen=4, followed by the 4 IP octets — the
    address itself lives in the OID index, not the returned value.

    Returns (base_suffix, ip_string_or_None). base_suffix is
    'timeMark.localPort.remIndex', used to join against the other
    lldpRemTable columns which share that same prefix.
    """
    parts = suffix.split(".")
    if len(parts) < 5:
        return suffix, None

    base_suffix = ".".join(parts[:3])
    addr_subtype = parts[3]
    addr_len = int(parts[4])

    if addr_subtype == "1" and addr_len == 4 and len(parts) >= 5 + addr_len:
        ip_octets = parts[5:5 + addr_len]
        return base_suffix, ".".join(ip_octets)

    return base_suffix, None


async def get_arp_mappings(switch_ips, max_entries=2000):
    """Walks the ARP table on each active switch and returns a dict of
    {normalized_mac: ip} mappings. This lets us resolve the MAC/chassis ID
    of SNMP-disabled switches — their IP is known from ping, their MAC is
    known from other switches' ARP tables, and their chassis ID (same as
    the bridge MAC) appears in other switches' LLDP tables. The chain is:

        active_switch.LLDP[neighbor_chassis] == MAC
        active_switch.ARP[MAC] == silent_ip
        ∴ neighbor_chassis == silent_ip

    Index format of ipNetToMediaPhysAddress:
        1.3.6.1.2.1.4.22.1.2.<ifIndex>.<a>.<b>.<c>.<d>
    The last 4 suffix parts are the IPv4 address octets."""
    mac_to_ip = {}
    for sw_ip in switch_ips:
        entries = await walk_column(sw_ip, OID_ARP_MAC, max_rows=max_entries)
        for suffix, value in entries.items():
            parts = suffix.split(".")
            if len(parts) < 5:
                continue
            ip_addr = ".".join(parts[-4:])
            mac = octets_to_str(value)
            mac_to_ip[mac] = ip_addr
    return mac_to_ip


async def get_lldp_neighbors(ip):
    """Returns local chassis/sysname plus a list of remote neighbor dicts."""
    loc_chassis = await get_single(ip, OID_LOC_CHASSIS_ID)
    loc_sysname = await get_single(ip, OID_LOC_SYS_NAME)

    rem_chassis = await walk_column(ip, OID_REM_CHASSIS_ID)
    rem_port = await walk_column(ip, OID_REM_PORT_ID)
    rem_port_desc = await walk_column(ip, OID_REM_PORT_DESC)
    rem_sysname = await walk_column(ip, OID_REM_SYS_NAME)
    rem_man_addr_raw = await walk_column(ip, OID_REM_MAN_ADDR_IF_SUBTYPE)

    # Management IPs are keyed by 'timeMark.localPort.remIndex' (base_suffix),
    # since the full suffix on this table also encodes the address itself.
    rem_man_ip = {}
    for full_suffix in rem_man_addr_raw:
        base_suffix, parsed_ip = parse_management_ip(full_suffix)
        if parsed_ip:
            rem_man_ip[base_suffix] = parsed_ip

    neighbors = []
    for suffix in rem_chassis:
        neighbors.append({
            "Local IP": ip,
            "Local SysName": octets_to_str(loc_sysname) if loc_sysname else None,
            "Neighbor Chassis ID": octets_to_str(rem_chassis[suffix]),
            "Neighbor Management IP": rem_man_ip.get(suffix),
            "Neighbor Port": octets_to_str(rem_port[suffix]) if suffix in rem_port else None,
            "Neighbor Port Desc": octets_to_str(rem_port_desc[suffix]) if suffix in rem_port_desc else None,
            "Neighbor SysName": octets_to_str(rem_sysname[suffix]) if suffix in rem_sysname else None,
        })

    return {
        "ip": ip,
        "local_chassis_id": octets_to_str(loc_chassis) if loc_chassis else None,
        "local_sysname": octets_to_str(loc_sysname) if loc_sysname else None,
        "neighbors": neighbors,
    }


async def scan_switch(ip):
    if not ping_ip(ip):
        print(f"{ip} --> unreachable (ping failed)")
        return {"ip": ip, "status": "unreachable", "data": None}

    data = await get_lldp_neighbors(ip)

    if data["local_chassis_id"] is None and not data["neighbors"]:
        print(f"{ip} --> reachable, but SNMP/LLDP not responding")
        return {"ip": ip, "status": "snmp_disabled", "data": data}

    print(f"{ip} --> active, {len(data['neighbors'])} LLDP neighbor(s) found")
    return {"ip": ip, "status": "active", "data": data}


async def discover_switches(subnet):
    """Ping-sweeps a subnet. Returns two lists:
    - snmp_ips: hosts that respond to SNMP lldpLocChassisId (queryable directly)
    - silent_ips: hosts that are alive/pingable but don't respond to SNMP
      (e.g. your SNMP-disabled switch) — kept instead of discarded, since
      they may still show up as a neighbor in another switch's LLDP table."""
    ip_list = [str(ip) for ip in ipaddress.IPv4Network(subnet)]
    print(f"\nPinging {len(ip_list)} addresses in {subnet}...\n")

    snmp_ips = []
    silent_ips = []

    for i in range(0, len(ip_list), BATCH_SIZE):
        batch = ip_list[i:i + BATCH_SIZE]
        alive_flags = await asyncio.gather(
            *[asyncio.to_thread(ping_ip, ip) for ip in batch]
        )
        alive_ips = [ip for ip, alive in zip(batch, alive_flags) if alive]

        if not alive_ips:
            continue

        chassis_results = await asyncio.gather(
            *[get_single(ip, OID_LOC_CHASSIS_ID) for ip in alive_ips]
        )

        for ip, chassis in zip(alive_ips, chassis_results):
            if chassis is not None:
                print(f"{ip} --> responds to SNMP/LLDP, treating as a switch")
                snmp_ips.append(ip)
            else:
                print(f"{ip} --> alive, but no SNMP/LLDP response (keeping as candidate)")
                silent_ips.append(ip)

    return snmp_ips, silent_ips


async def main():
    switch_ips = SWITCH_IPS
    silent_ips = []

    if not switch_ips:
        mode = input("Do you know the switch IPs? (y/n): ").strip().lower()
        if mode == "y":
            raw = input("Enter switch IPs, comma-separated (ex: 192.168.1.1,192.168.1.2,192.168.1.3): ")
            switch_ips = [ip.strip() for ip in raw.split(",") if ip.strip()]
        else:
            subnet = input("Enter subnet to scan (ex: 192.168.1.0/24): ").strip()
            switch_ips, silent_ips = await discover_switches(subnet)
            if not switch_ips and not silent_ips:
                print("\nNo live hosts found in that subnet. Check the range and try again.")
                return
            print(f"\nDiscovered {len(switch_ips)} SNMP-responsive switch(es): {switch_ips}")
            if silent_ips:
                print(f"Found {len(silent_ips)} alive-but-SNMP-silent host(s), keeping as candidates: {silent_ips}")
            print()

    print(f"\nQuerying {len(switch_ips)} switch(es) for LLDP data...\n")

    debug = input("Also run a raw LLDP subtree dump for debugging? (y/n): ").strip().lower()
    if debug == "y":
        for ip in switch_ips:
            await raw_lldp_dump(ip)

    results = await asyncio.gather(*[scan_switch(ip) for ip in switch_ips])

    all_neighbors = []
    summary_rows = []

    for r in results:
        summary_rows.append({
            "IP": r["ip"],
            "Status": r["status"],
            "Local Chassis ID": r["data"]["local_chassis_id"] if r["data"] else None,
            "Local SysName": r["data"]["local_sysname"] if r["data"] else None,
            "Neighbors Found": len(r["data"]["neighbors"]) if r["data"] else 0,
        })
        if r["data"]:
            all_neighbors.extend(r["data"]["neighbors"])

    # Fold in alive-but-SNMP-silent hosts discovered during a subnet sweep,
    # so they don't disappear from the report entirely.
    for ip in silent_ips:
        summary_rows.append({
            "IP": ip,
            "Status": "alive_snmp_silent",
            "Local Chassis ID": None,
            "Local SysName": None,
            "Neighbors Found": 0,
        })

    print("\nQuerying ARP tables on active switches to resolve MAC -> IP mappings...")
    arp_mappings = await get_arp_mappings(switch_ips)
    if arp_mappings:
        print(f"  Found {len(arp_mappings)} MAC -> IP entries")

    arp_df = pd.DataFrame([
        {"MAC": mac, "IP": ip} for mac, ip in arp_mappings.items()
    ])
    arp_df.to_csv("arp_mappings.csv", index=False)
    if arp_mappings:
        print(f"  Saved arp_mappings.csv")

    summary_df = pd.DataFrame(summary_rows)
    neighbors_df = pd.DataFrame(all_neighbors)

    summary_df.to_csv("switch_summary.csv", index=False)
    neighbors_df.to_csv("lldp_neighbors.csv", index=False)

    print("\n=== Switch Summary ===")
    print(summary_df.to_string(index=False))

    print("\n=== LLDP Neighbor Map ===")
    if neighbors_df.empty:
        print("No neighbor relationships discovered.")
    else:
        print(neighbors_df.to_string(index=False))

    if silent_ips:
        print("\n=== SNMP-Silent Hosts (from subnet sweep) ===")
        print("These responded to ping but not SNMP. Check if their SysName/Chassis")
        print("ID appears in the neighbor map above from the other switches —")
        print("that's how you confirm their position in the topology.")
        for ip in silent_ips:
            print(f"  - {ip}")

    print("\nSaved: switch_summary.csv, lldp_neighbors.csv")
    print("\nTip: if the SNMP-disabled switch appears as a 'Neighbor Chassis ID' or")
    print("'Neighbor SysName' in the table above from the other two switches,")
    print("that confirms its position in the topology even without direct SNMP access.")


if __name__ == "__main__":
    asyncio.run(main())