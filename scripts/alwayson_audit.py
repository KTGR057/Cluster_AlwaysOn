#!/usr/bin/env python3
"""Read-only vSphere audit for SQL Server Always On VM clusters."""
import argparse
import datetime as dt
import html
import json
import os
import ssl
import sys
from pathlib import Path

import yaml

try:
    from pyVmomi import vim, vmodl
    from pyVim import connect
except ImportError:
    vim = None
    vmodl = None
    connect = None

VCENTERS = {
    "vCenter_BTA": ("10.10.170.159", "dhcibogdc"),
    "vCenter_MDE": ("10.10.144.159", "dhcimdedc"),
}


def prop(obj, path, default=None):
    value = obj
    for part in path.split("."):
        value = getattr(value, part, None)
        if value is None:
            return default
    return value


def mib(value):
    return round(value / (1024 ** 2), 1) if value is not None else None


def reservation_percent(vm):
    memory = prop(vm, "config.memorySizeMB", 0) or 0
    reservation = prop(vm, "config.memoryAllocation.reservation", 0) or 0
    return round(reservation / memory * 100, 1) if memory else 0


def backing_type(backing):
    thin = getattr(backing, "thinProvisioned", None)
    eagerly_scrubbed = getattr(backing, "eagerlyScrub", None)
    if thin is True:
        return "Thin"
    if eagerly_scrubbed is True:
        return "Thick Eager Zeroed"
    if thin is False:
        return "Thick Lazy Zeroed"
    return "Unknown"


def datastore_policy(device):
    profiles = getattr(device, "profile", None) or []
    for profile in profiles:
        profile_id = getattr(profile, "profileId", None)
        if profile_id:
            return profile_id
    return "Unspecified"


def network_vlan(network):
    port_config = prop(network, "config.defaultPortConfig", None)
    vlan_spec = prop(port_config, "vlan", None)
    vlan_id = getattr(vlan_spec, "vlanId", None)
    if vlan_id is not None:
        return vlan_id
    if vlan_spec is not None:
        return type(vlan_spec).__name__.replace("Spec", "")
    return "See vCenter"


def vm_snapshot(vm):
    config = vm.config
    devices = list(config.hardware.device) if config and config.hardware else []
    disks = []
    controllers = []
    networks = []
    for device in devices:
        if isinstance(device, vim.vm.device.VirtualSCSIController):
            controllers.append({
                "label": device.deviceInfo.label if device.deviceInfo else str(device.key),
                "type": type(device).__name__.replace("Virtual", ""),
                "bus_number": device.busNumber,
            })
        elif isinstance(device, vim.vm.device.VirtualDisk):
            backing = device.backing
            disks.append({
                "label": device.deviceInfo.label if device.deviceInfo else str(device.key),
                "capacity_gb": round(device.capacityInKB / (1024 ** 2), 2),
                "controller_key": device.controllerKey,
                "provisioning": backing_type(backing),
                "datastore": prop(backing, "datastore.name", "Unknown"),
                "storage_policy": datastore_policy(device),
            })
        elif isinstance(device, vim.vm.device.VirtualEthernetCard):
            backing = device.backing
            network = prop(backing, "network", None)
            networks.append({
                "label": device.deviceInfo.label if device.deviceInfo else str(device.key),
                "adapter": type(device).__name__.replace("Virtual", ""),
                "network": prop(backing, "network.name", None) or getattr(backing, "deviceName", "Unknown"),
                "vlan": network_vlan(network),
            })
    controller_names = {device.key: (device.deviceInfo.label if device.deviceInfo else str(device.key))
                        for device in devices if isinstance(device, vim.vm.device.VirtualSCSIController)}
    for disk in disks:
        disk["controller"] = controller_names.get(disk["controller_key"], "Unknown")
    return {
        "name": vm.name,
        "moid": vm._moId,
        "power_state": str(vm.runtime.powerState),
        "host": prop(vm, "runtime.host.name", "Unknown"),
        "cpu": {
            "vcpus": config.hardware.numCPU,
            "sockets": config.hardware.numCoresPerSocket and config.hardware.numCPU // config.hardware.numCoresPerSocket,
            "cores_per_socket": config.hardware.numCoresPerSocket,
            "reservation_mhz": prop(config, "cpuAllocation.reservation", 0),
            "limit_mhz": prop(config, "cpuAllocation.limit", -1),
        },
        "memory": {
            "assigned_mb": config.hardware.memoryMB,
            "reservation_mb": prop(config, "memoryAllocation.reservation", 0),
            "reservation_percent": reservation_percent(vm),
            "limit_mb": prop(config, "memoryAllocation.limit", -1),
        },
        "disks": disks,
        "controllers": controllers,
        "networks": networks,
    }


def infer_vcenter(name):
    upper_name = name.upper()
    if upper_name.startswith("BOP") or upper_name.startswith("SERV-BTA"):
        return "vCenter_BTA"
    if upper_name.startswith("MEP") or upper_name.startswith("SERV-MDE"):
        return "vCenter_MDE"
    raise RuntimeError("No se pudo inferir el vCenter para la VM %s; agregue vcenter al nodo" % name)


def all_objects(content, vim_type):
    view = content.viewManager.CreateContainerView(content.rootFolder, [vim_type], True)
    try:
        return list(view.view)
    finally:
        view.Destroy()


def find_vm(content, name):
    matches = [vm for vm in all_objects(content, vim.VirtualMachine) if vm.name == name]
    if not matches:
        matches = [vm for vm in all_objects(content, vim.VirtualMachine) if vm.name.casefold() == name.casefold()]
    if not matches:
        raise RuntimeError("VM no encontrada: %s" % name)
    if len(matches) > 1:
        raise RuntimeError("Nombre de VM ambiguo: %s" % name)
    return matches[0]


def drs_findings(content, node_names):
    node_set = set(node_names)
    findings = []
    clusters = all_objects(content, vim.ClusterComputeResource)
    for cluster in clusters:
        rules = prop(cluster, "configurationEx.rule", []) or []
        for rule in rules:
            members = [prop(vm, "name") for vm in (getattr(rule, "vm", None) or [])]
            overlap = sorted(node_set.intersection(members))
            if len(overlap) >= 2:
                enabled = getattr(rule, "enabled", True)
                mandatory = getattr(rule, "mandatory", False)
                if isinstance(rule, vim.cluster.DrsVmHostRule):
                    continue
                findings.append({
                    "severity": "INFO" if enabled else "HIGH",
                    "message": "Regla DRS de anti-afinidad encontrada" if enabled else "Regla DRS de anti-afinidad deshabilitada",
                    "rule": getattr(rule, "name", "Unnamed"),
                    "cluster": cluster.name,
                    "nodes": overlap,
                    "mandatory": mandatory,
                })
    if not any(item.get("nodes") == sorted(node_set) for item in findings):
        findings.append({"severity": "HIGH", "message": "No se encontro una regla DRS de anti-afinidad para todos los nodos del cluster", "nodes": sorted(node_set)})
    return findings


def add_finding(findings, severity, message, parameter, actual=None, expected=None):
    findings.append({"severity": severity, "parameter": parameter, "message": message, "actual": actual, "expected": expected})


def compare_cluster(cluster, vms, drs):
    findings = list(drs)
    names = [vm["name"] for vm in vms]
    for field in ("vcpus", "sockets", "cores_per_socket"):
        values = [vm["cpu"][field] for vm in vms]
        if len(set(values)) > 1:
            add_finding(findings, "MEDIUM", "Configuracion de CPU asimetrica", "cpu." + field, dict(zip(names, values)), "igual en todos los nodos")
    for field in ("assigned_mb", "reservation_percent", "limit_mb"):
        values = [vm["memory"][field] for vm in vms]
        if field == "reservation_percent" and any(value < 100 for value in values):
            add_finding(findings, "HIGH", "La memoria no tiene reserva del 100%", "memory.reservation_percent", dict(zip(names, values)), 100)
        elif field == "limit_mb" and any(value not in (-1, None) for value in values):
            add_finding(findings, "HIGH", "Existe limite de memoria; puede provocar contention", "memory.limit_mb", dict(zip(names, values)), "unlimited")
        elif len(set(values)) > 1:
            add_finding(findings, "MEDIUM", "Configuracion de memoria asimetrica", "memory." + field, dict(zip(names, values)), "igual en todos los nodos")
    for vm in vms:
        for disk in vm["disks"]:
            if disk["provisioning"] != "Thick Eager Zeroed":
                add_finding(findings, "MEDIUM", "Disco no es Thick Eager Zeroed", "%s.provisioning" % vm["name"], disk["provisioning"], "Thick Eager Zeroed")
        if not vm["controllers"] or any("ParaVirtual" not in controller["type"] for controller in vm["controllers"]):
            add_finding(findings, "MEDIUM", "Revisar controladores: se recomienda PVSCSI para SQL Server", vm["name"] + ".controllers", vm["controllers"], "PVSCSI")
        for network in vm["networks"]:
            if network["adapter"] != "Vmxnet3":
                add_finding(findings, "MEDIUM", "Adaptador de red distinto de VMXNET3", vm["name"] + ".network.adapter", network["adapter"], "Vmxnet3")
    host_identities = {(vm.get("vcenter", "unknown"), vm["host"]) for vm in vms}
    hosts = {"%s/%s" % identity for identity in host_identities}
    if len(hosts) < len(vms):
        add_finding(findings, "HIGH", "Dos o mas nodos comparten host fisico", "runtime.host", dict(zip(names, ["%s/%s" % (vm.get("vcenter", "unknown"), vm["host"]) for vm in vms])), "hosts distintos")
    return {"name": cluster["name"], "nodes": vms, "findings": findings, "performance": {"physical_hosts": sorted(hosts), "node_count": len(vms)}}


def mock_vm(name, index):
    """Create representative data so the comparison can run without vCenter."""
    return {
        "name": name,
        "moid": "offline-%s" % index,
        "power_state": "poweredOn",
        "host": "esxi-offline-%d" % (index % 2 + 1),
        "cpu": {"vcpus": 8 if index == 1 else 4, "sockets": 1, "cores_per_socket": 4, "reservation_mhz": 0, "limit_mhz": -1},
        "memory": {"assigned_mb": 32768, "reservation_mb": 16384 if index == 1 else 32768, "reservation_percent": 50 if index == 1 else 100, "limit_mb": -1},
        "disks": [{"label": "Hard disk 1", "capacity_gb": 100, "controller_key": 1000, "controller": "SCSI controller 0", "provisioning": "Thin", "datastore": "DS-OFFLINE", "storage_policy": "Unspecified"}],
        "controllers": [{"label": "SCSI controller 0", "type": "ParaVirtualSCSIController", "bus_number": 0}],
        "networks": [{"label": "Network adapter 1", "adapter": "Vmxnet3", "network": "VLAN-OFFLINE", "vlan": 100}],
    }


def normalize_config(config):
    clusters = []
    for item in config.get("clusters", []):
        name = item.get("name") or item.get("nombre")
        nodes = item.get("nodes") or item.get("nodos")
        if not name or not isinstance(nodes, list) or len(nodes) < 2:
            raise RuntimeError("Cada cluster requiere nombre y al menos dos nodos")
        normalized_nodes = []
        for node in nodes:
            if isinstance(node, dict):
                node_name = node.get("name") or node.get("nombre")
                node_vcenter = node.get("vcenter") or node.get("vCenter")
            else:
                node_name = str(node).strip()
                node_vcenter = None
            if not node_name:
                raise RuntimeError("El cluster %s contiene un nodo sin nombre" % name)
            normalized_nodes.append({"name": node_name.strip(), "vcenter": node_vcenter or infer_vcenter(node_name.strip())})
        clusters.append({
            "name": str(name).strip(),
            "nodes": normalized_nodes,
            "label": item.get("label") or item.get("etiqueta") or str(name).strip(),
            "vcenter_cluster": item.get("vcenter_cluster") or item.get("cluster_vcenter"),
        })
    if not clusters:
        raise RuntimeError("El inventario debe contener una lista no vacia en clusters")
    return {"clusters": clusters}


def offline_report(config):
    results = []
    for cluster in config["clusters"]:
        vms = [mock_vm(node["name"], index) for index, node in enumerate(cluster["nodes"], 1)]
        drs = [{"severity": "HIGH", "message": "Modo offline: no se valido la regla DRS contra vCenter", "nodes": [node["name"] for node in cluster["nodes"]]}]
        results.append(compare_cluster(cluster, vms, drs))
    return {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "vcenter": None, "mode": "offline", "clusters": results}


def html_report(report):
    rows = []
    for cluster in report["clusters"]:
        rows.append("<h2>%s</h2><table><tr><th>Nodo</th><th>vCenter</th><th>Host</th><th>vCPU</th><th>Memoria</th><th>Reserva</th><th>Discos</th><th>Red</th></tr>" % html.escape(cluster["name"]))
        for vm in cluster["nodes"]:
            disks = ", ".join(d["provisioning"] for d in vm["disks"])
            networks = ", ".join(n["adapter"] + " / " + str(n["network"]) for n in vm["networks"])
            rows.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s MB</td><td>%s%%</td><td>%s</td><td>%s</td></tr>" % tuple(html.escape(str(x)) for x in [vm["name"], vm.get("vcenter", "offline"), vm["host"], vm["cpu"]["vcpus"], vm["memory"]["assigned_mb"], vm["memory"]["reservation_percent"], disks, networks]))
        rows.append("</table><h3>Hallazgos y recomendaciones</h3><ul>")
        for finding in cluster["findings"]:
            rows.append("<li class='%s'><b>%s</b>: %s</li>" % (finding["severity"].lower(), html.escape(finding["severity"]), html.escape(finding["message"])))
        rows.append("</ul>")
    generated = html.escape(report["generated_at"])
    return "<!doctype html><html lang='es'><head><meta charset='utf-8'><title>Auditoria Always On</title><style>body{font:14px sans-serif;margin:2rem;color:#17202a}table{border-collapse:collapse;width:100%%;margin-bottom:1rem}th,td{border:1px solid #ccd;padding:.5rem;text-align:left}th{background:#e8eef2}.high{color:#a00}.medium{color:#a65d00}.info{color:#246b3b}h1{color:#163b53}</style></head><body><h1>Auditoria SQL Server Always On</h1><p>Generado: %s</p>%s</body></html>" % (generated, "".join(rows))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output-dir", default="artifacts")
    parser.add_argument("--offline", action="store_true", help="No conecta a vCenter; usa datos sinteticos")
    args = parser.parse_args()
    config = normalize_config(yaml.safe_load(Path(args.input).read_text(encoding="utf-8")) or {})
    if args.offline:
        report = offline_report(config)
        write_report(report, args.output_dir)
        return
    user = os.environ.get("VCENTER_USER")
    password = os.environ.get("VCENTER_PASS")
    if not all((user, password)):
        raise RuntimeError("VCENTER_USER y VCENTER_PASS son obligatorios")
    configured_hosts = {
        "vCenter_BTA": os.environ.get("VCENTER_BTA_HOST"),
        "vCenter_MDE": os.environ.get("VCENTER_MDE_HOST"),
    }
    required_vcenters = sorted({node["vcenter"] for cluster in config["clusters"] for node in cluster["nodes"]})
    hosts = {name: configured_hosts.get(name) or VCENTERS.get(name, (None, None))[0] for name in required_vcenters}
    if any(not value for value in hosts.values()):
        raise RuntimeError("Falta la direccion de uno de los vCenter requeridos: %s" % hosts)
    context = ssl.create_default_context() if os.environ.get("VCENTER_VALIDATE_CERTS", "false").lower() == "true" else ssl._create_unverified_context()
    if connect is None:
        raise RuntimeError("pyVmomi es obligatorio en modo VCENTER")
    services = {name: connect.SmartConnect(host=host, user=user, pwd=password, sslContext=context) for name, host in hosts.items()}
    try:
        contents = {name: service.RetrieveContent() for name, service in services.items()}
        results = []
        for cluster in config["clusters"]:
            vms = []
            findings = []
            for node in cluster["nodes"]:
                snapshot = vm_snapshot(find_vm(contents[node["vcenter"]], node["name"]))
                snapshot["vcenter"] = node["vcenter"]
                vms.append(snapshot)
            for vcenter, content in contents.items():
                vcenter_nodes = [node["name"] for node in cluster["nodes"] if node["vcenter"] == vcenter]
                if vcenter_nodes:
                    findings.extend(drs_findings(content, vcenter_nodes))
            results.append(compare_cluster(cluster, vms, findings))
        report = {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "vcenters": hosts, "mode": "vcenter", "clusters": results}
    finally:
        for service in services.values():
            connect.Disconnect(service)
    write_report(report, args.output_dir)


def write_report(report, output_dir):
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    (output / ("alwayson-audit-%s.json" % stamp)).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    (output / ("alwayson-audit-%s.html" % stamp)).write_text(html_report(report), encoding="utf-8")
    print("Auditoria completada en modo %s: %d cluster(s), %d hallazgo(s)" % (report["mode"] if report.get("mode") else "vcenter", len(report["clusters"]), sum(len(c["findings"]) for c in report["clusters"])))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, yaml.YAMLError) as error:
        print("ERROR: %s" % error, file=sys.stderr)
        sys.exit(1)
