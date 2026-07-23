import pandas as pd
import dash
from dash import html, Input, Output
import dash_cytoscape as cyto

# Load device statuses
devices_df = pd.read_csv("devices.csv")
status_map = {}
sysname_map = {}
chassis_map = {}
for _, row in devices_df.iterrows():
    ip = str(row["IP"]).strip()
    status = str(row["Status"]).strip().lower()
    # Normalize: treat alive_snmp_silent same as snmp_disabled for styling
    if status == "alive_snmp_silent":
        status = "snmp_disabled"
    status_map[ip] = status
    sysname = str(row.get("Local SysName", "")).strip()
    if sysname.lower() not in ("", "nan", "none"):
        sysname_map[ip] = sysname
    chassis = str(row.get("Local Chassis ID", "")).strip()
    if chassis.lower() not in ("", "nan", "none"):
        chassis_map[ip] = chassis

# Load network connections
df = pd.read_csv("network_connections.csv")

# Build Cytoscape elements
elements = []
edges = []   # store edges for sidebar logic

# Nodes — ALL devices from devices.csv, color-coded by status
for ip, status in status_map.items():
    cls = status if status in ("active", "snmp_disabled", "unreachable") else "active"
    elements.append({
        "data": {
            "id": ip,
            "label": ip,
            "status": status
        },
        "classes": cls
    })

# Edges (store port info)
for _, row in df.iterrows():
    source = str(row["Local IP"]).strip()
    target = str(row["Neighbor IP"]).strip()
    lp = str(row["Local Port"]).strip()
    np = str(row["Neighbor Port"]).strip()

    edge_data = {
        "source": source,
        "target": target,
        "label": f"{lp} ↔ {np}",
        "local_port": lp,
        "neighbor_port": np
    }

    edges.append(edge_data)

    elements.append({
        "data": edge_data,
        "classes": "edge"
    })

# App
app = dash.Dash(__name__)
server = app.server

# Modern layout
app.layout = html.Div([

    # HEADER
    html.Div([
        html.H2("Network Topology Viewer", style={
            'color': 'white',
            "margin": "0",
            "font-weight": "600"
        }),
        html.Button("Auto-Fit", id="fit-btn", style={
            "padding": "8px 16px",
            "background": "#0066ff",
            "color": "white",
            "border-radius": "6px",
            "border": "none",
            "cursor": "pointer",
            "font-size": "14px",
            "font-weight": "600"
        })
    ], style={
        "display": "flex",
        "justify-content": "space-between",
        "align-items": "center",
        "padding": "15px 25px",
        "background": "#111",
        "border-bottom": "1px solid #222",
        "box-shadow": "0 2px 6px rgba(0,0,0,0.4)"
    }),

    # MAIN CONTENT
    html.Div([

        # GRAPH
        cyto.Cytoscape(
            id='network',
            elements=elements,
            layout={'name': 'cose'},
            style={
                'width': '75%',
                'height': '92vh',
                'background': '#0d0d0d'
            },
            zoomingEnabled=True,
            panningEnabled=True,
            autoungrabify=False,
            stylesheet=[

                # ACTIVE NODE
                {
                    "selector": ".active",
                    "style": {
                        "background-color": "#3A7BD5",
                        "label": "data(label)",
                        "font-size": "9px",
                        "color": "white",
                        "text-wrap": "wrap",
                        "text-max-width": "45px",
                        "text-valign": "center",
                        "text-halign": "center",
                        "width": "30px",
                        "height": "30px",
                        "shape": "ellipse",
                        "border-width": 1,
                        "border-color": "#d9e6ff",
                        "shadow-color": "#4da3ff",
                        "shadow-blur": 20,
                        "shadow-opacity": 0.6
                    }
                },

                # SNMP DISABLED NODE
                {
                    "selector": ".snmp_disabled",
                    "style": {
                        "background-color": "#E67E22",
                        "label": "data(label)",
                        "font-size": "9px",
                        "color": "white",
                        "text-wrap": "wrap",
                        "text-max-width": "45px",
                        "text-valign": "center",
                        "text-halign": "center",
                        "width": "30px",
                        "height": "30px",
                        "shape": "ellipse",
                        "border-width": 2,
                        "border-color": "#f39c12",
                        "border-style": "dashed",
                        "shadow-color": "#e67e22",
                        "shadow-blur": 15,
                        "shadow-opacity": 0.4
                    }
                },

                # UNREACHABLE NODE
                {
                    "selector": ".unreachable",
                    "style": {
                        "background-color": "#444",
                        "label": "data(label)",
                        "font-size": "9px",
                        "color": "#999",
                        "text-wrap": "wrap",
                        "text-max-width": "45px",
                        "text-valign": "center",
                        "text-halign": "center",
                        "width": "30px",
                        "height": "30px",
                        "shape": "ellipse",
                        "border-width": 2,
                        "border-color": "#e74c3c",
                        "shadow-color": "#e74c3c",
                        "shadow-blur": 10,
                        "shadow-opacity": 0.3
                    }
                },

                # MODERN EDGE STYLE
                {
                    "selector": ".edge",
                    "style": {
                        "curve-style": "bezier",
                        "line-color": "#999",
                        "target-arrow-shape": "triangle",
                        "target-arrow-color": "#888",
                        "width": 1.8,
                        "label": "data(label)",
                        "font-size": "7px",
                        "color": "#e6e6e6",
                        "text-background-color": "#222",
                        "text-background-opacity": 0.7,
                        "text-background-padding": "2px"
                    }
                },

                # SELECTED NODE
                {
                    "selector": "node:selected",
                    "style": {
                        "border-width": 3,
                        "border-color": "#00e5ff",
                        "shadow-color": "#00e5ff",
                        "shadow-blur": 25,
                    }
                }
            ]
        ),

        # SIDEBAR
        html.Div(id="sidebar", style={
            "width": "25%",
            "background": "#141414",
            "color": "white",
            "padding": "25px",
            "font-size": "14px",
            "border-left": "1px solid #222"
        })
    ], style={"display": "flex"})
])


# CALLBACK: show node details in sidebar
@app.callback(
    Output("sidebar", "children"),
    Input("network", "tapNodeData")
)
def display_node_data(node):
    if not node:
        return html.Div([
            html.H3("No Device Selected", style={"color": "#888"}),
            html.P("Click a node to view details.")
        ])

    node_ip = node["id"]
    status = node.get("status", "unknown")

    status_colors = {
        "active": "#3A7BD5",
        "snmp_disabled": "#E67E22",
        "unreachable": "#e74c3c"
    }
    status_color = status_colors.get(status, "#888")

    status_labels = {
        "active": "Active (SNMP OK)",
        "snmp_disabled": "SNMP Disabled",
        "unreachable": "Unreachable"
    }
    status_label = status_labels.get(status, status)

    # Find all connected ports
    connections = []
    for e in edges:
        if e["source"] == node_ip:
            connections.append({
                "neighbor": e["target"],
                "local_port": e["local_port"],
                "neighbor_port": e["neighbor_port"]
            })
        elif e["target"] == node_ip:
            connections.append({
                "neighbor": e["source"],
                "local_port": e["neighbor_port"],
                "neighbor_port": e["local_port"]
            })

    # Build display list
    port_blocks = []
    for c in connections:
        port_blocks.append(
            html.Div([
                html.P(f"Connected to: {c['neighbor']}", style={"font-weight": "600"}),
                html.P(f"Local Port: {c['local_port']}"),
                html.P(f"Neighbor Port: {c['neighbor_port']}"),
                html.Hr(style={"border-color": "#333"})
            ])
        )

    sysname = sysname_map.get(node_ip, "")
    chassis = chassis_map.get(node_ip, "")

    info_blocks = [
        html.P(f"IP Address: {node_ip}"),
        html.P([
            "Status: ",
            html.Span(status_label, style={"color": status_color, "font-weight": "600"})
        ]),
    ]
    if sysname:
        info_blocks.append(html.P(f"Name: {sysname}"))
    if chassis:
        info_blocks.append(html.P(f"Chassis ID: {chassis}"))

    info_blocks.append(html.Br())
    info_blocks.append(html.H4("LLDP Connections"))

    if port_blocks:
        info_blocks.append(html.Div(port_blocks))
    else:
        info_blocks.append(html.P("No LLDP connections found.", style={"color": "#666"}))

    return html.Div([
        html.H3("Device Information", style={"margin-bottom": "10px"}),
        html.Hr(style={"border-color": "#333"}),
        *info_blocks,
    ])


# CALLBACK: Auto-fit view
@app.callback(
    Output("network", "layout"),
    Input("fit-btn", "n_clicks"),
    prevent_initial_call=True
)
def fit_graph(n):
    return {"name": "preset", "fit": True}


if __name__ == '__main__':
    app.run(debug=True)