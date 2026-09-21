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
    return "No expuesto por API"


def network_mtu(network):
    """Read MTU from a distributed switch or portgroup when vSphere exposes it."""
    switch = prop(network, "config.distributedVirtualSwitch", None)
    return (
        prop(switch, "config.maxMtu", None)
        or prop(switch, "summary.config.maxMtu", None)
        or prop(network, "config.maxMtu", None)
        or prop(network, "config.defaultPortConfig.maxMtu", None)
        or "No expuesto por API"
    )


def allocation_value(allocation, field, unlimited=-1):
    value = getattr(allocation, field, None)
    return unlimited if value is None else value


def resolve_network(content, backing):
    network = prop(backing, "network", None)
    if network is not None or content is None:
        return network
    portgroup_key = prop(backing, "port.portgroupKey", None)
    if not portgroup_key:
        return None
    for portgroup in all_objects(content, vim.dvs.DistributedVirtualPortgroup):
        if getattr(portgroup, "key", None) == portgroup_key:
            return portgroup
    return None


def vm_snapshot(vm, content=None):
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
            network = resolve_network(content, backing)
            networks.append({
                "label": device.deviceInfo.label if device.deviceInfo else str(device.key),
                "adapter": type(device).__name__.replace("Virtual", ""),
                "network": prop(network, "name", None) or getattr(backing, "deviceName", "Unknown"),
                "vlan": network_vlan(network),
                "mtu": network_mtu(network),
            })
    controller_names = {device.key: (device.deviceInfo.label if device.deviceInfo else str(device.key))
                        for device in devices if isinstance(device, vim.vm.device.VirtualSCSIController)}
    for disk in disks:
        disk["controller"] = controller_names.get(disk["controller_key"], "Unknown")
    assigned_memory = config.hardware.memoryMB
    reserved_memory = allocation_value(config.memoryAllocation, "reservation", 0)
    reservation_delta = max(assigned_memory - reserved_memory, 0)
    return {
        "name": vm.name,
        "moid": vm._moId,
        "power_state": str(vm.runtime.powerState),
        "host": prop(vm, "runtime.host.name", "Unknown"),
        "cpu": {
            "vcpus": config.hardware.numCPU,
            "sockets": config.hardware.numCoresPerSocket and config.hardware.numCPU // config.hardware.numCoresPerSocket,
            "cores_per_socket": config.hardware.numCoresPerSocket,
            "reservation_mhz": allocation_value(config.cpuAllocation, "reservation", 0),
            "limit_mhz": allocation_value(config.cpuAllocation, "limit"),
            "hot_add": bool(getattr(config, "cpuHotAddEnabled", False)),
        },
        "memory": {
            "assigned_mb": assigned_memory,
            "reservation_mb": reserved_memory,
            "reservation_percent": round(reserved_memory / assigned_memory * 100, 1) if assigned_memory else 0,
            "reservation_delta_mb": reservation_delta,
            "reservation_status": "100% LOCKED" if reservation_delta == 0 else "PARTIAL",
            "limit_mb": allocation_value(config.memoryAllocation, "limit"),
            "hot_add": bool(getattr(config, "memoryHotAddEnabled", False)),
        },
        "platform": {
            "virtual_hardware": getattr(config, "version", "Unknown"),
            "tools_version": prop(vm, "guest.toolsVersion", "Unknown"),
            "tools_status": prop(vm, "guest.toolsVersionStatus2", "Unknown"),
            "time_sync": "Not exposed by vSphere API; verify guest NTP/domain",
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
    if len(node_set) < 2:
        return [{
            "severity": "INFO",
            "parameter": "drs.anti_affinity",
            "message": "La regla DRS no puede validarse entre vCenter; esta sede contiene un solo nodo del grupo.",
            "nodes": sorted(node_set),
            "remediation": "Validar la anti-afinidad en el diseño entre sitios y mantener una regla DRS para los nodos que compartan vCenter.",
        }]
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
                    "parameter": "drs.anti_affinity",
                    "message": "Regla DRS de anti-afinidad encontrada" if enabled else "Regla DRS de anti-afinidad deshabilitada",
                    "rule": getattr(rule, "name", "Unnamed"),
                    "cluster": cluster.name,
                    "nodes": overlap,
                    "mandatory": mandatory,
                })
    if not any(item.get("nodes") == sorted(node_set) for item in findings):
        findings.append({"severity": "HIGH", "parameter": "drs.anti_affinity", "message": "No se encontro una regla DRS de anti-afinidad para todos los nodos del cluster", "nodes": sorted(node_set), "remediation": "Crear regla DRS VM-VM Separate Virtual Machines con todos los nodos del grupo."})
    return findings


def add_finding(findings, severity, message, parameter, actual=None, expected=None):
    remediations = {
        "cpu.hot_add": "PowerCLI: Get-VM VM | Set-VM -CpuHotAddEnabled:$false -Confirm:$false",
        "memory.hot_add": "PowerCLI: Get-VM VM | Set-VM -MemoryHotAddEnabled:$false -Confirm:$false",
        "memory.reservation_percent": "Activar Reserve all guest memory (All locked), dejando Memory Reservation igual a la RAM asignada y Memory Limit = Unlimited.",
        "cpu.limit_mhz": "Configurar CPU Limit = Unlimited y conservar Reservation = 0 salvo estandar aprobado.",
        "memory.limit_mb": "Configurar Memory Limit = Unlimited en la configuracion de la VM.",
        "storage.provisioning": "Migrar el VMDK a Thick Eager Zeroed durante una ventana de mantenimiento.",
        "storage.controllers": "Agregar controladoras PVSCSI/NVMe separadas para SO, datos, logs y TempDB; validar dependencias SQL.",
        "network.adapter": "PowerCLI: Get-VM VM | Get-NetworkAdapter | Set-NetworkAdapter -Type Vmxnet3 -Confirm:$false",
        "network.mtu": "Consultar el vDS/portgroup y configurar MTU extremo a extremo en portgroup, vDS, uplinks y red de replicacion; validar jumbo frames.",
        "platform.virtual_hardware": "Actualizar VMware Tools y hardware virtual en una ventana controlada, validando compatibilidad del guest.",
        "platform.tools": "Actualizar/reparar VMware Tools y confirmar estado toolsOk/toolsOld.",
        "platform.time_sync": "Configurar NTP en el guest o sincronizacion de dominio; no mezclar VMware Tools periodic sync con NTP activo.",
        "drs.anti_affinity": "Crear regla DRS VM-VM Separate Virtual Machines con todos los nodos del grupo.",
        "storage.datastore_affinity": "Ubicar los nodos en datastores/failure domains fisicos distintos o documentar la excepcion.",
    }
    findings.append({"severity": severity, "parameter": parameter, "message": message, "actual": actual, "expected": expected, "remediation": remediations.get(parameter, "Revisar la recomendacion y aplicar el cambio mediante Change Management.")})


def compare_cluster(cluster, vms, drs):
    findings = list(drs)
    names = [vm["name"] for vm in vms]
    for field in ("vcpus", "sockets", "cores_per_socket"):
        values = [vm["cpu"][field] for vm in vms]
        if len(set(values)) > 1:
            add_finding(findings, "MEDIUM", "Configuracion de CPU asimetrica", "cpu." + field, dict(zip(names, values)), "igual en todos los nodos")
    if any(vm["cpu"]["hot_add"] for vm in vms):
        add_finding(findings, "HIGH", "CPU Hot-Add habilitado; puede alterar la topologia vNUMA", "cpu.hot_add", dict(zip(names, [vm["cpu"]["hot_add"] for vm in vms])), False)
    if any(vm["cpu"]["limit_mhz"] not in (-1, 0, None) for vm in vms):
        add_finding(findings, "HIGH", "Existe limite de CPU", "cpu.limit_mhz", dict(zip(names, [vm["cpu"]["limit_mhz"] for vm in vms])), "unlimited")
    for field in ("assigned_mb", "reservation_percent", "limit_mb"):
        values = [vm["memory"][field] for vm in vms]
        if field == "reservation_percent" and any(vm["memory"]["reservation_delta_mb"] > 0 for vm in vms):
            add_finding(findings, "HIGH", "La memoria no tiene reserva estricta del 100% (Reserve all guest memory)", "memory.reservation_percent", {vm["name"]: {"assigned_mb": vm["memory"]["assigned_mb"], "reservation_mb": vm["memory"]["reservation_mb"], "delta_mb": vm["memory"]["reservation_delta_mb"], "status": vm["memory"]["reservation_status"]} for vm in vms}, "reservation_mb igual a assigned_mb; 100% LOCKED")
        elif field == "limit_mb" and any(value not in (-1, None) for value in values):
            add_finding(findings, "HIGH", "Existe limite de memoria; puede provocar contention", "memory.limit_mb", dict(zip(names, values)), "unlimited")
        elif len(set(values)) > 1:
            add_finding(findings, "MEDIUM", "Configuracion de memoria asimetrica", "memory." + field, dict(zip(names, values)), "igual en todos los nodos")
    if any(vm["memory"]["hot_add"] for vm in vms):
        add_finding(findings, "HIGH", "Memory Hot-Add habilitado", "memory.hot_add", dict(zip(names, [vm["memory"]["hot_add"] for vm in vms])), False)
    for vm in vms:
        for disk in vm["disks"]:
            if disk["provisioning"] != "Thick Eager Zeroed":
                add_finding(findings, "MEDIUM", "Disco no es Thick Eager Zeroed", "storage.provisioning", {vm["name"]: disk["provisioning"]}, "Thick Eager Zeroed")
        if not vm["controllers"] or any(not ("ParaSCSI" in controller["type"] or "ParaVirtual" in controller["type"] or "NVMe" in controller["type"]) for controller in vm["controllers"]):
            add_finding(findings, "MEDIUM", "Controladora distinta de PVSCSI/NVMe", "storage.controllers", {vm["name"]: vm["controllers"]}, "PVSCSI o NVMe")
        for network in vm["networks"]:
            if network["adapter"] != "Vmxnet3":
                add_finding(findings, "MEDIUM", "Adaptador de red distinto de VMXNET3", "network.adapter", {vm["name"]: network["adapter"]}, "Vmxnet3")
            if network["mtu"] in ("Unknown", "No expuesto por API"):
                add_finding(findings, "MEDIUM", "El MTU no esta expuesto en el objeto de red consultado", "network.mtu", {vm["name"]: network["mtu"]}, "9000 para replicacion si la red lo soporta")
    datastore_sets = {vm["name"]: sorted({disk["datastore"] for disk in vm["disks"]}) for vm in vms}
    if len({tuple(value) for value in datastore_sets.values()}) == 1 and len(vms) > 1:
        add_finding(findings, "HIGH", "Los nodos comparten la misma ubicacion de datastore", "storage.datastore_affinity", datastore_sets, "datastores/failure domains distintos")
    platform_versions = [vm["platform"]["virtual_hardware"] for vm in vms]
    if len(set(platform_versions)) > 1:
        add_finding(findings, "MEDIUM", "Version de hardware virtual inconsistente", "platform.virtual_hardware", dict(zip(names, platform_versions)), "igual en todos los nodos")
    if any(vm["platform"]["tools_status"] not in ("toolsOk", "guestToolsCurrent", "Unknown") for vm in vms):
        add_finding(findings, "MEDIUM", "Estado de VMware Tools requiere revision", "platform.tools", dict(zip(names, [vm["platform"]["tools_status"] for vm in vms])), "toolsOk/toolsCurrent")
    tools_versions = [vm["platform"]["tools_version"] for vm in vms]
    if len(set(tools_versions)) > 1 and "Unknown" not in tools_versions:
        add_finding(findings, "MEDIUM", "Version de VMware Tools inconsistente entre nodos", "platform.tools", dict(zip(names, tools_versions)), "misma version compatible en todos los nodos")
    controller_buses = {vm["name"]: sorted(controller["bus_number"] for controller in vm["controllers"]) for vm in vms}
    if any(len(buses) < 2 for buses in controller_buses.values()):
        add_finding(findings, "MEDIUM", "La VM no tiene multiples controladoras para separar SO, datos, logs y TempDB", "storage.controllers", controller_buses, "al menos 2; idealmente separar cargas en 0/1/2/3")
    host_identities = {(vm.get("vcenter", "unknown"), vm["host"]) for vm in vms}
    hosts = {"%s/%s" % identity for identity in host_identities}
    if len(hosts) < len(vms):
        add_finding(findings, "HIGH", "Dos o mas nodos comparten host fisico", "runtime.host", dict(zip(names, ["%s/%s" % (vm.get("vcenter", "unknown"), vm["host"]) for vm in vms])), "hosts distintos")
    critical = sum(item["severity"] == "HIGH" for item in findings)
    warning = sum(item["severity"] == "MEDIUM" for item in findings)
    score = max(0, 100 - (critical * 20) - (warning * 8))
    return {"name": cluster["name"], "nodes": vms, "findings": findings, "performance": {"physical_hosts": sorted(hosts), "node_count": len(vms), "score": score, "status": "RED" if critical else ("YELLOW" if warning else "GREEN")}}


def mock_vm(name, index):
    """Create representative data so the comparison can run without vCenter."""
    return {
        "name": name,
        "moid": "offline-%s" % index,
        "power_state": "poweredOn",
        "host": "esxi-offline-%d" % (index % 2 + 1),
        "cpu": {"vcpus": 8 if index == 1 else 4, "sockets": 1, "cores_per_socket": 4, "reservation_mhz": 0, "limit_mhz": -1, "hot_add": False},
        "memory": {"assigned_mb": 32768, "reservation_mb": 16384 if index == 1 else 32768, "reservation_percent": 50 if index == 1 else 100, "reservation_delta_mb": 16384 if index == 1 else 0, "reservation_status": "PARTIAL" if index == 1 else "100% LOCKED", "limit_mb": -1, "hot_add": False},
        "disks": [{"label": "Hard disk 1", "capacity_gb": 100, "controller_key": 1000, "controller": "SCSI controller 0", "provisioning": "Thin", "datastore": "DS-OFFLINE", "storage_policy": "Unspecified"}],
        "controllers": [{"label": "SCSI controller 0", "type": "ParaVirtualSCSIController", "bus_number": 0}],
        "networks": [{"label": "Network adapter 1", "adapter": "Vmxnet3", "network": "VLAN-OFFLINE", "vlan": 100, "mtu": 9000}],
        "platform": {"virtual_hardware": "vmx-21", "tools_version": "offline", "tools_status": "Unknown", "time_sync": "Not evaluated in offline mode"},
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
    cluster_count = len(report["clusters"])
    finding_count = sum(len(cluster["findings"]) for cluster in report["clusters"])
    critical_count = sum(sum(item.get("severity") == "HIGH" for item in cluster["findings"]) for cluster in report["clusters"])
    warning_count = sum(sum(item.get("severity") == "MEDIUM" for item in cluster["findings"]) for cluster in report["clusters"])
    scores = [cluster["performance"]["score"] for cluster in report["clusters"]]
    global_score = round(sum(scores) / len(scores)) if scores else 0
    global_status = "RED" if critical_count else ("YELLOW" if warning_count else "GREEN")
    for cluster in report["clusters"]:
        performance = cluster["performance"]
        node_count = len(cluster["nodes"])
        node_cards = []
        for vm in cluster["nodes"]:
            disks = ", ".join(d["provisioning"] for d in vm["disks"])
            networks = ", ".join(n["adapter"] + " / " + str(n["network"]) for n in vm["networks"])
            node_cards.append("<article class='node-card'><div class='node-heading'><div><span class='eyebrow'>Nodo</span><h3>%s</h3></div><span class='site'>%s</span></div><div class='node-grid'><div><span>Host ESXi</span><strong>%s</strong></div><div><span>CPU</span><strong>%s vCPU</strong></div><div><span>RAM asignada</span><strong>%s GB</strong></div><div><span>Reserva RAM</span><strong>%s MB (%s%%)</strong></div><div><span>Estado reserva</span><strong>%s</strong></div><div><span>Hardware</span><strong>%s</strong></div><div><span>Tools</span><strong>%s</strong></div></div><div class='node-footer'><span>Discos: %s</span><span>Red: %s</span></div></article>" % tuple(html.escape(str(x)) for x in [vm["name"], vm.get("vcenter", "offline"), vm["host"], vm["cpu"]["vcpus"], round(vm["memory"]["assigned_mb"] / 1024, 1), vm["memory"]["reservation_mb"], vm["memory"]["reservation_percent"], vm["memory"]["reservation_status"], vm["platform"]["virtual_hardware"], vm["platform"]["tools_status"], disks or "No informado", networks or "No informado"]))
        rows.append("<section class='cluster-section'><div class='cluster-header'><div><span class='eyebrow'>Cluster Always On</span><h2>%s</h2><p>%s nodos · %s host(s) fisico(s)</p></div><div class='score-ring %s'><strong>%s</strong><span>/100</span><small>%s</small></div></div><div class='node-cards'>%s</div><h3 class='section-title'>Matriz de hallazgos y remediacion</h3><div class='finding-list'>" % (html.escape(cluster["name"]), node_count, len(performance["physical_hosts"]), performance["status"].lower(), performance["score"], performance["status"], "".join(node_cards)))
        for finding in cluster["findings"]:
            severity = finding.get("severity", "INFO")
            rows.append("<article class='finding %s'><div class='finding-top'><span class='severity'>%s</span><span class='parameter'>%s</span></div><h4>%s</h4><div class='finding-values'><div><span>Actual</span><strong>%s</strong></div><div><span>Esperado</span><strong>%s</strong></div></div><p><b>Remediacion:</b> %s</p></article>" % tuple(html.escape(str(x)) for x in [severity.lower(), severity, finding.get("parameter", ""), finding.get("message", ""), finding.get("actual", ""), finding.get("expected", ""), finding.get("remediation", "Revisar manualmente")]))
        rows.append("</div></section>")
    generated = html.escape(report["generated_at"])
    return ("""<!doctype html><html lang='es'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Auditoria Always On</title><style>
:root{--ink:#17212b;--muted:#687582;--line:#dbe3e8;--paper:#f4f7f8;--white:#fff;--navy:#12344d;--red:#c43d3d;--red-bg:#fff1f1;--amber:#a66b00;--amber-bg:#fff8e6;--green:#28784b;--green-bg:#eaf7ef;--shadow:0 12px 28px rgba(18,52,77,.08)}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:14px/1.5 Inter,Segoe UI,Arial,sans-serif}main{max-width:1440px;margin:0 auto;padding:34px 28px 60px}.hero{background:var(--navy);color:#fff;border-radius:14px;padding:32px 36px;box-shadow:var(--shadow);display:flex;justify-content:space-between;gap:28px;align-items:flex-end}.eyebrow{text-transform:uppercase;letter-spacing:.12em;font-size:11px;font-weight:700;color:#7892a4}.hero .eyebrow{color:#9db7c8}.hero h1{font-size:32px;line-height:1.1;margin:7px 0 10px;font-weight:700}.hero p{margin:0;color:#c7d7e1}.hero-meta{text-align:right;color:#c7d7e1}.hero-meta strong{display:block;color:#fff;font-size:16px}.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:22px 0}.metric{background:var(--white);border:1px solid var(--line);border-radius:10px;padding:18px 20px;box-shadow:var(--shadow)}.metric span{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}.metric strong{display:block;font-size:29px;margin-top:5px;color:var(--navy)}.metric.red strong{color:var(--red)}.metric.yellow strong{color:var(--amber)}.metric.green strong{color:var(--green)}.cluster-section{background:var(--white);border:1px solid var(--line);border-radius:12px;padding:24px;margin:20px 0;box-shadow:var(--shadow)}.cluster-header{display:flex;justify-content:space-between;align-items:center;gap:20px;border-bottom:1px solid var(--line);padding-bottom:18px}.cluster-header h2{margin:4px 0;font-size:24px;color:var(--navy)}.cluster-header p{margin:0;color:var(--muted)}.score-ring{width:92px;height:92px;border:7px solid var(--line);border-radius:50%;display:flex;flex-wrap:wrap;align-content:center;justify-content:center;line-height:1}.score-ring strong{font-size:25px}.score-ring span{font-size:11px;color:var(--muted);align-self:center;margin-left:2px}.score-ring small{width:100%;text-align:center;font-size:10px;font-weight:700;letter-spacing:.1em;margin-top:5px}.score-ring.red{border-color:#edb1b1;color:var(--red)}.score-ring.yellow{border-color:#efd58e;color:var(--amber)}.score-ring.green{border-color:#a8d9ba;color:var(--green)}.node-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;padding:20px 0}.node-card{border:1px solid var(--line);border-radius:9px;padding:17px;background:#fbfcfd}.node-heading{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:1px solid var(--line);padding-bottom:12px}.node-heading h3{margin:3px 0 0;font-size:18px;color:var(--navy)}.site{font-size:11px;background:#e7f0f5;color:var(--navy);border-radius:4px;padding:4px 7px;font-weight:700}.node-grid{display:grid;grid-template-columns:1fr 1fr;gap:13px;margin:16px 0}.node-grid span,.finding-values span{display:block;color:var(--muted);font-size:11px}.node-grid strong{display:block;font-size:14px;margin-top:2px}.node-footer{border-top:1px solid var(--line);padding-top:11px;color:var(--muted);font-size:12px;display:grid;gap:4px}.section-title{font-size:17px;color:var(--navy);margin:6px 0 13px}.finding-list{display:grid;gap:10px}.finding{border:1px solid var(--line);border-left:4px solid var(--line);border-radius:7px;padding:13px 15px;background:#fff}.finding.high{border-left-color:var(--red);background:var(--red-bg)}.finding.medium{border-left-color:#d9a52d;background:var(--amber-bg)}.finding.info{border-left-color:var(--green);background:var(--green-bg)}.finding-top{display:flex;justify-content:space-between;gap:12px;align-items:center}.severity{font-size:10px;font-weight:800;letter-spacing:.1em}.parameter{font:11px Consolas,monospace;color:var(--muted)}.finding h4{margin:7px 0;font-size:14px}.finding-values{display:grid;grid-template-columns:1fr 1fr;gap:15px;margin:10px 0}.finding-values strong{display:block;word-break:break-word;font-size:12px}.finding p{margin:8px 0 0;color:#485762;font-size:12px}.footer{color:var(--muted);font-size:12px;text-align:right;margin-top:18px}@media(max-width:760px){main{padding:16px 12px 40px}.hero{display:block;padding:24px}.hero h1{font-size:26px}.hero-meta{text-align:left;margin-top:18px}.summary{grid-template-columns:1fr 1fr}.cluster-section{padding:17px}.cluster-header{align-items:flex-start}.score-ring{flex:0 0 82px;width:82px;height:82px}.finding-values{grid-template-columns:1fr}.node-cards{grid-template-columns:1fr}}@media(max-width:420px){.summary{grid-template-columns:1fr}.cluster-header h2{font-size:20px}}
</style></head><body><main><header class='hero'><div><span class='eyebrow'>Informe de infraestructura critica</span><h1>Auditoria SQL Server Always On</h1><p>Evaluacion de homologacion, disponibilidad y rendimiento en VMware vSphere.</p></div><div class='hero-meta'><span>Generado</span><strong>%s</strong><span>Modo: %s</span></div></header><section class='summary'><div class='metric %s'><span>Score global</span><strong>%s/100</strong></div><div class='metric'><span>Clusters auditados</span><strong>%s</strong></div><div class='metric red'><span>Riesgos criticos</span><strong>%s</strong></div><div class='metric yellow'><span>Advertencias</span><strong>%s</strong></div></section>%s<footer class='footer'>Fuente: vCenter y configuracion declarada del inventario Always On.</footer></main></body></html>""".replace("%", "%%").replace("%%s", "%s") % (generated, html.escape(report.get("mode", "vCenter")), global_status.lower(), global_score, cluster_count, critical_count, warning_count, "".join(rows)))


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
                snapshot = vm_snapshot(find_vm(contents[node["vcenter"]], node["name"]), contents[node["vcenter"]])
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
