#!/usr/bin/env python3
"""Read-only vSphere audit for SQL Server Always On VM clusters."""
import argparse
import datetime as dt
import html
import json
import os
import re
import ssl
import sys
from collections import Counter
from pathlib import Path
from zoneinfo import ZoneInfo

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

# Los vCenter y servidores auditados estan en Colombia; se fija la zona horaria
# explicitamente para que el reporte no dependa de la TZ del contenedor/agente
# donde se ejecute el pipeline (por defecto suele quedar en UTC).
REPORT_TIMEZONE = ZoneInfo(os.environ.get("REPORT_TIMEZONE", "America/Bogota"))


def now_local():
    return dt.datetime.now(REPORT_TIMEZONE)

# Baseline supplied for the physical hosts: 2 sockets x 32 physical cores.
HOST_NUMA_CORES = 32
HOST_TOTAL_CORES = 64


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


def short_type_name(obj):
    """pyVmomi __name__ is the fully qualified vmodl name (e.g. 'vim.vm.device.VirtualVmxnet3');
    keep only the last segment so 'Virtual'/'Spec' stripping and equality checks work as intended."""
    return type(obj).__name__.rsplit(".", 1)[-1]


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
        return short_type_name(vlan_spec).replace("Spec", "")
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


def cpu_recommendation(vm):
    vcpus = vm["cpu"]["vcpus"]
    current = "%s socket(s) x %s core(s)" % (vm["cpu"]["sockets"], vm["cpu"]["cores_per_socket"])
    if vcpus <= HOST_NUMA_CORES:
        recommended_sockets = 1
        recommended_cores = vcpus
        topology_status = "ALINEADA" if (vm["cpu"]["sockets"], vm["cpu"]["cores_per_socket"]) == (recommended_sockets, recommended_cores) else "AJUSTAR"
        message = "Actual %s; recomendado 1 socket x %s cores para permanecer dentro de un nodo NUMA de %s cores." % (current, recommended_cores, HOST_NUMA_CORES)
    elif vcpus <= HOST_TOTAL_CORES:
        recommended_sockets = 2
        recommended_cores = (vcpus + 1) // 2
        topology_status = "ALINEADA" if (vm["cpu"]["sockets"], vm["cpu"]["cores_per_socket"]) == (recommended_sockets, recommended_cores) else "AJUSTAR"
        message = "Actual %s; recomendado %s sockets x %s cores, distribuido sobre los dos nodos NUMA de %s cores." % (current, recommended_sockets, recommended_cores, HOST_NUMA_CORES)
    else:
        recommended_sockets = None
        recommended_cores = None
        topology_status = "REVISAR"
        message = "%s vCPU supera los %s cores fisicos conocidos del host; requiere diseno NUMA especifico." % (vcpus, HOST_TOTAL_CORES)
    if vm["cpu"]["hot_add"]:
        topology_status = "AJUSTAR"
        message += " CPU Hot-Plug debe estar deshabilitado."
    return {
        "current": current,
        "recommended_sockets": recommended_sockets,
        "recommended_cores_per_socket": recommended_cores,
        "status": topology_status,
        "message": message,
        "host_baseline": "2 sockets x 32 cores; %s cores fisicos; HT no se usa para dimensionar vNUMA" % HOST_TOTAL_CORES,
    }


def shares_snapshot(allocation):
    shares = getattr(allocation, "shares", None)
    level = str(getattr(shares, "level", "normal") or "normal").lower()
    shares_value = getattr(shares, "shares", None)
    return {"level": level, "shares": shares_value}


def normalize_os_name(value):
    if not value:
        return "Unknown"
    return " ".join(str(value).lower().replace("microsoft", "").split())


def os_snapshot(vm, config):
    configured = getattr(config, "guestFullName", None) or "Unknown"
    tools_reported = prop(vm, "guest.guestFullName", None) or "Unknown"
    configured_key = normalize_os_name(configured)
    tools_key = normalize_os_name(tools_reported)
    if "unknown" in (configured_key, tools_key):
        status = "NO_CONCLUSIVO"
        recommendation = "Verificar VMware Tools y actualizar el inventario del sistema operativo en vCenter."
    elif configured_key == tools_key:
        status = "COINCIDE"
        recommendation = "No requiere ajuste; mantener VMware Tools actualizado y el inventario sincronizado."
    else:
        status = "DIFIERE"
        recommendation = "Confirmar el OS real dentro del guest, actualizar VMware Tools y corregir el Guest OS configurado en vCenter si corresponde."
    return {
        "configured": configured,
        "tools_reported": tools_reported,
        "status": status,
        "recommendation": recommendation,
    }


def latency_sensitivity_snapshot(config):
    latency = getattr(config, "latencySensitivity", None)
    level = str(getattr(latency, "level", "normal") or "normal").lower()
    return {"level": level}


_PORTGROUP_INDEX_CACHE = {}


def portgroup_index(content):
    """Cache dvPortgroups per vCenter content so we don't rescan the whole inventory per NIC."""
    key = id(content)
    index = _PORTGROUP_INDEX_CACHE.get(key)
    if index is None:
        index = {getattr(pg, "key", None): pg for pg in all_objects(content, vim.dvs.DistributedVirtualPortgroup)}
        _PORTGROUP_INDEX_CACHE[key] = index
    return index


def resolve_network(content, backing):
    network = prop(backing, "network", None)
    if network is not None or content is None:
        return network
    portgroup_key = prop(backing, "port.portgroupKey", None)
    if not portgroup_key:
        return None
    return portgroup_index(content).get(portgroup_key)


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
                "type": short_type_name(device).replace("Virtual", ""),
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
                "adapter": short_type_name(device).replace("Virtual", ""),
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
    snapshot_info = getattr(vm, "snapshot", None)
    has_snapshots = bool(getattr(snapshot_info, "rootSnapshotList", None))
    return {
        "name": vm.name,
        "moid": vm._moId,
        "power_state": str(vm.runtime.powerState),
        "host": prop(vm, "runtime.host.name", "Unknown"),
        "vsphere_cluster": prop(vm, "runtime.host.parent.name", "Unknown"),
        "has_snapshots": has_snapshots,
        "latency_sensitivity": latency_sensitivity_snapshot(config),
        "cpu": {
            "vcpus": config.hardware.numCPU,
            "sockets": config.hardware.numCoresPerSocket and config.hardware.numCPU // config.hardware.numCoresPerSocket,
            "cores_per_socket": config.hardware.numCoresPerSocket,
            "reservation_mhz": allocation_value(config.cpuAllocation, "reservation", 0),
            "limit_mhz": allocation_value(config.cpuAllocation, "limit"),
            "hot_add": bool(getattr(config, "cpuHotAddEnabled", False)),
            "shares": shares_snapshot(config.cpuAllocation),
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
        "os": os_snapshot(vm, config),
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


_VM_INDEX_CACHE = {}
_CLUSTER_INDEX_CACHE = {}


def vm_index(content):
    """Cache VMs per vCenter content so each node lookup doesn't rescan the whole inventory."""
    key = id(content)
    index = _VM_INDEX_CACHE.get(key)
    if index is None:
        exact = {}
        by_fold = {}
        for vm in all_objects(content, vim.VirtualMachine):
            exact.setdefault(vm.name, []).append(vm)
            by_fold.setdefault(vm.name.casefold(), []).append(vm)
        index = (exact, by_fold)
        _VM_INDEX_CACHE[key] = index
    return index


def cluster_index(content):
    key = id(content)
    index = _CLUSTER_INDEX_CACHE.get(key)
    if index is None:
        index = all_objects(content, vim.ClusterComputeResource)
        _CLUSTER_INDEX_CACHE[key] = index
    return index


def find_vm(content, name):
    exact, by_fold = vm_index(content)
    matches = exact.get(name) or by_fold.get(name.casefold(), [])
    if not matches:
        raise RuntimeError("VM no encontrada: %s" % name)
    if len(matches) > 1:
        raise RuntimeError("Nombre de VM ambiguo: %s" % name)
    return matches[0]


def drs_findings(content, node_names):
    node_set = set(node_names)
    findings = []
    vm_objects = {name: find_vm(content, name) for name in node_set}
    nodes_by_cluster = {}
    for name, vm in vm_objects.items():
        cluster_name = prop(vm, "runtime.host.parent.name", "Unknown")
        nodes_by_cluster.setdefault(cluster_name, set()).add(name)
    if len(node_set) < 2:
        return [{
            "severity": "INFO",
            "parameter": "drs.anti_affinity",
            "message": "La regla DRS no puede validarse entre vCenter; esta sede contiene un solo nodo del grupo.",
            "nodes": sorted(node_set),
            "remediation": "Validar la anti-afinidad en el diseño entre sitios y mantener una regla DRS para los nodos que compartan vCenter.",
        }]
    if len(nodes_by_cluster) > 1:
        findings.append({
            "severity": "INFO",
            "parameter": "drs.scope",
            "message": "Los nodos del Always On estan distribuidos en distintos clusters VMware; las reglas DRS VM-VM solo aplican dentro del mismo cluster vSphere.",
            "nodes_by_vsphere_cluster": {cluster: sorted(nodes) for cluster, nodes in nodes_by_cluster.items()},
            "remediation": "Mantener reglas DRS separadas por cluster vSphere y validar la anti-afinidad entre sedes mediante la arquitectura de disponibilidad.",
        })
    clusters = cluster_index(content)
    for cluster in clusters:
        cluster_nodes = nodes_by_cluster.get(cluster.name, set())
        if len(cluster_nodes) < 2:
            continue
        rules = prop(cluster, "configurationEx.rule", []) or []
        for rule in rules:
            members = [prop(vm, "name") for vm in (getattr(rule, "vm", None) or [])]
            overlap = sorted(cluster_nodes.intersection(members))
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
    for cluster_name, cluster_nodes in nodes_by_cluster.items():
        if len(cluster_nodes) >= 2 and not any(set(item.get("nodes", [])) == cluster_nodes for item in findings):
            findings.append({"severity": "HIGH", "parameter": "drs.anti_affinity", "message": "No se encontro una regla DRS de anti-afinidad para los nodos que comparten el cluster VMware", "cluster": cluster_name, "nodes": sorted(cluster_nodes), "remediation": "Crear regla DRS VM-VM Separate Virtual Machines con los nodos de ese cluster vSphere."})
    return findings


def add_finding(findings, severity, message, parameter, actual=None, expected=None):
    remediations = {
        "cpu.hot_add": "PowerCLI: Get-VM VM | Set-VM -CpuHotAddEnabled:$false -Confirm:$false",
        "memory.hot_add": "PowerCLI: Get-VM VM | Set-VM -MemoryHotAddEnabled:$false -Confirm:$false",
        "memory.reservation_percent": "Activar Reserve all guest memory (All locked), dejando Memory Reservation igual a la RAM asignada y Memory Limit = Unlimited.",
        "cpu.limit_mhz": "Configurar CPU Limit = Unlimited y conservar Reservation = 0 salvo estandar aprobado.",
        "cpu.shares": "Homologar CPU Shares en todos los nodos. Usar Normal por defecto; usar High solo con una politica formal de resource pool.",
        "memory.limit_mb": "Configurar Memory Limit = Unlimited en la configuracion de la VM.",
        "storage.controllers": "Agregar controladoras PVSCSI/NVMe separadas para SO, datos, logs y TempDB; validar dependencias SQL.",
        "network.adapter": "PowerCLI: Get-VM VM | Get-NetworkAdapter | Set-NetworkAdapter -Type Vmxnet3 -Confirm:$false",
        "network.mtu": "Consultar el vDS/portgroup y configurar MTU extremo a extremo en portgroup, vDS, uplinks y red de replicacion; validar jumbo frames.",
        "platform.virtual_hardware": "Actualizar VMware Tools y hardware virtual en una ventana controlada, validando compatibilidad del guest.",
        "platform.tools": "Actualizar/reparar VMware Tools y confirmar estado toolsOk/toolsOld.",
        "platform.time_sync": "Configurar NTP en el guest o sincronizacion de dominio; no mezclar VMware Tools periodic sync con NTP activo.",
        "os.identity": "Confirmar el OS dentro del guest, actualizar VMware Tools y corregir el Guest OS configurado en vCenter si corresponde.",
        "drs.anti_affinity": "Crear regla DRS VM-VM Separate Virtual Machines con todos los nodos del grupo.",
        "storage.datastore_affinity": "Ubicar los nodos en datastores/failure domains fisicos distintos o documentar la excepcion.",
        "network.dedicated_cluster_network": "Agregar un adaptador de red dedicado (VLAN separada) para trafico de cluster/heartbeat y replica de Always On, distinto del trafico de aplicacion/cliente.",
        "platform.snapshots": "Eliminar snapshots activos y usar backups nativos de SQL Server (Full/Log) o una solucion VSS certificada en lugar de snapshots de VM para nodos de produccion.",
        "platform.latency_sensitivity": "Evaluar Latency Sensitivity = High solo si CPU y memoria ya estan reservadas al 100% y la carga es critica en latencia; requiere validacion de NIC/vmxnet3 y capacidad del host.",
    }
    findings.append({"severity": severity, "parameter": parameter, "message": message, "actual": actual, "expected": expected, "remediation": remediations.get(parameter, "Revisar la recomendacion y aplicar el cambio mediante Change Management.")})


def compare_cluster(cluster, vms, drs):
    findings = list(drs)
    names = [vm["name"] for vm in vms]
    for vm in vms:
        vm["cpu"]["recommendation"] = cpu_recommendation(vm)
        if vm["cpu"]["recommendation"]["status"] != "ALINEADA":
            add_finding(findings, "HIGH", "Topologia de sockets/cores no alineada con NUMA fisico", "cpu.topology", {vm["name"]: vm["cpu"]["recommendation"]["current"]}, vm["cpu"]["recommendation"]["message"])
    for field in ("vcpus", "sockets", "cores_per_socket"):
        values = [vm["cpu"][field] for vm in vms]
        if len(set(values)) > 1:
            add_finding(findings, "MEDIUM", "Configuracion de CPU asimetrica", "cpu." + field, dict(zip(names, values)), "igual en todos los nodos")
    if any(vm["cpu"]["hot_add"] for vm in vms):
        add_finding(findings, "HIGH", "CPU Hot-Add habilitado; puede alterar la topologia vNUMA", "cpu.hot_add", dict(zip(names, [vm["cpu"]["hot_add"] for vm in vms])), False)
    if any(vm["cpu"]["limit_mhz"] not in (-1, 0, None) for vm in vms):
        add_finding(findings, "HIGH", "Existe limite de CPU", "cpu.limit_mhz", dict(zip(names, [vm["cpu"]["limit_mhz"] for vm in vms])), "unlimited")
    share_levels = [vm["cpu"]["shares"]["level"] for vm in vms]
    share_values = [vm["cpu"]["shares"]["shares"] for vm in vms]
    if len(set(share_levels)) > 1 or len(set(share_values)) > 1:
        add_finding(findings, "MEDIUM", "CPU Shares inconsistente entre nodos; la prioridad bajo contencion no es homogenea", "cpu.shares", dict(zip(names, [vm["cpu"]["shares"] for vm in vms])), "mismo nivel y valor en todos los nodos; Normal por defecto")
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
        if vm["os"]["status"] == "DIFIERE":
            add_finding(findings, "MEDIUM", "El OS configurado en vCenter difiere del OS reportado por VMware Tools", "os.identity", {vm["name"]: {"config_file": vm["os"]["configured"], "vmware_tools": vm["os"]["tools_reported"]}}, "Ambas fuentes deben identificar el mismo sistema operativo")
        elif vm["os"]["status"] == "NO_CONCLUSIVO":
            add_finding(findings, "MEDIUM", "No fue posible comparar el OS configurado con el reportado por VMware Tools", "os.identity", {vm["name"]: {"config_file": vm["os"]["configured"], "vmware_tools": vm["os"]["tools_reported"]}}, "Ambas fuentes disponibles y coincidentes")
    for vm in vms:
        if not vm["controllers"] or any(not ("ParaSCSI" in controller["type"] or "ParaVirtual" in controller["type"] or "NVMe" in controller["type"]) for controller in vm["controllers"]):
            add_finding(findings, "MEDIUM", "Controladora distinta de PVSCSI/NVMe", "storage.controllers", {vm["name"]: vm["controllers"]}, "PVSCSI o NVMe")
        for network in vm["networks"]:
            if network["adapter"] != "Vmxnet3":
                add_finding(findings, "MEDIUM", "Adaptador de red distinto de VMXNET3", "network.adapter", {vm["name"]: network["adapter"]}, "Vmxnet3")
            if network["mtu"] in ("Unknown", "No expuesto por API"):
                add_finding(findings, "MEDIUM", "El MTU no esta expuesto en el objeto de red consultado", "network.mtu", {vm["name"]: network["mtu"]}, "9000 para replicacion si la red lo soporta")
        if len(vm["networks"]) < 2:
            add_finding(findings, "MEDIUM", "El nodo tiene un unico adaptador de red; el trafico de cluster/AG comparte la misma red que el trafico de cliente", "network.dedicated_cluster_network", {vm["name"]: len(vm["networks"])}, "al menos 2 adaptadores, uno dedicado a heartbeat/replica AG")
        else:
            vlans = {network["vlan"] for network in vm["networks"]}
            if len(vlans) == 1:
                add_finding(findings, "MEDIUM", "Todos los adaptadores de red del nodo estan en la misma VLAN; no hay evidencia de una red dedicada para trafico de cluster/AG", "network.dedicated_cluster_network", {vm["name"]: sorted(str(v) for v in vlans)}, "VLANs distintas para trafico de cliente y trafico de cluster/AG")
    if any(vm["has_snapshots"] for vm in vms):
        add_finding(findings, "HIGH", "Uno o mas nodos tienen snapshots activos", "platform.snapshots", {vm["name"]: vm["has_snapshots"] for vm in vms}, "sin snapshots activos en nodos de produccion")
    if any(vm["latency_sensitivity"]["level"] != "high" for vm in vms):
        add_finding(findings, "INFO", "Latency Sensitivity no esta en 'High' en uno o mas nodos", "platform.latency_sensitivity", {vm["name"]: vm["latency_sensitivity"]["level"] for vm in vms}, "evaluar 'High' si la carga es critica en latencia y CPU/memoria ya estan reservadas al 100%")
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
        "vsphere_cluster": "Cluster-OFFLINE-%d" % (index % 2 + 1),
        "has_snapshots": False,
        "latency_sensitivity": {"level": "normal"},
        "cpu": {"vcpus": 8 if index == 1 else 4, "sockets": 1, "cores_per_socket": 4, "reservation_mhz": 0, "limit_mhz": -1, "hot_add": False, "shares": {"level": "normal", "shares": 4000}},
        "memory": {"assigned_mb": 32768, "reservation_mb": 16384 if index == 1 else 32768, "reservation_percent": 50 if index == 1 else 100, "reservation_delta_mb": 16384 if index == 1 else 0, "reservation_status": "PARTIAL" if index == 1 else "100% LOCKED", "limit_mb": -1, "hot_add": False},
        "disks": [{"label": "Hard disk 1", "capacity_gb": 100, "controller_key": 1000, "controller": "SCSI controller 0", "provisioning": "Thin", "datastore": "DS-OFFLINE", "storage_policy": "Unspecified"}],
        "controllers": [{"label": "SCSI controller 0", "type": "ParaVirtualSCSIController", "bus_number": 0}],
        "networks": [{"label": "Network adapter 1", "adapter": "Vmxnet3", "network": "VLAN-OFFLINE", "vlan": 100, "mtu": 9000}],
        "platform": {"virtual_hardware": "vmx-21", "tools_version": "offline", "tools_status": "Unknown", "time_sync": "Not evaluated in offline mode"},
        "os": {"configured": "Windows Server (offline)", "tools_reported": "Windows Server (offline)", "status": "COINCIDE", "recommendation": "No requiere ajuste en modo offline."},
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
        drs = [{"severity": "HIGH", "parameter": "drs.anti_affinity", "message": "Modo offline: no se valido la regla DRS contra vCenter", "nodes": [node["name"] for node in cluster["nodes"]]}]
        results.append(compare_cluster(cluster, vms, drs))
    return {"generated_at": now_local().isoformat(), "vcenter": None, "mode": "offline", "clusters": results}


def slugify(value):
    return re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-") or "cluster"


def html_report(report):
    rows = []
    overview_rows = []
    cluster_count = len(report["clusters"])
    finding_count = sum(len(cluster["findings"]) for cluster in report["clusters"])
    critical_count = sum(sum(item.get("severity") == "HIGH" for item in cluster["findings"]) for cluster in report["clusters"])
    warning_count = sum(sum(item.get("severity") == "MEDIUM" for item in cluster["findings"]) for cluster in report["clusters"])
    scores = [cluster["performance"]["score"] for cluster in report["clusters"]]
    global_score = round(sum(scores) / len(scores)) if scores else 0
    global_status = "RED" if critical_count else ("YELLOW" if warning_count else "GREEN")
    used_slugs = {}
    for cluster in report["clusters"]:
        performance = cluster["performance"]
        node_count = len(cluster["nodes"])
        base_slug = slugify(cluster["name"])
        used_slugs[base_slug] = used_slugs.get(base_slug, 0) + 1
        slug = base_slug if used_slugs[base_slug] == 1 else "%s-%s" % (base_slug, used_slugs[base_slug])
        cluster_critical = sum(item.get("severity") == "HIGH" for item in cluster["findings"])
        cluster_warning = sum(item.get("severity") == "MEDIUM" for item in cluster["findings"])
        overview_rows.append(
            "<tr><td><a href='#%s'>%s</a></td><td class='num'>%s</td><td class='num'>%s</td><td class='num'>%s</td><td><span class='pill %s'>%s</span></td><td class='num'>%s</td><td class='num'>%s</td></tr>"
            % (slug, html.escape(cluster["name"]), node_count, len(performance["physical_hosts"]), performance["score"],
               performance["status"].lower(), performance["status"], cluster_critical, cluster_warning)
        )
        node_table_rows = []
        storage_table_rows = []
        for vm in cluster["nodes"]:
            recommendation = vm["cpu"]["recommendation"]
            shares = vm["cpu"]["shares"]
            shares_text = "%s (%s)" % (shares["level"], shares["shares"] if shares["shares"] is not None else "default")
            controller_summary = ", ".join("%s x%s" % item for item in Counter(c["type"] for c in vm["controllers"]).items()) or "No informado"
            disk_summary = ", ".join("%s: %s" % item for item in Counter(d["provisioning"] for d in vm["disks"]).items()) or "No informado"
            network_summary = ", ".join("%s / %s: %s" % (n["adapter"], n["network"], n["mtu"]) for n in vm["networks"]) or "No informado"
            topology_pill = "ok" if recommendation["status"] == "ALINEADA" else "bad"
            os_pill = "ok" if vm["os"]["status"] == "COINCIDE" else "bad"
            reservation_pill = "ok" if vm["memory"]["reservation_delta_mb"] == 0 else "bad"
            latency_level = vm["latency_sensitivity"]["level"]
            latency_pill = "ok" if latency_level == "high" else "info"
            snapshot_badge = " <span class='pill bad'>Snapshot activo</span>" if vm["has_snapshots"] else ""
            node_table_rows.append(
                "<tr><td><strong>%s</strong><br><span class='muted'>%s</span></td><td>%s<br><span class='muted'>%s</span></td>"
                "<td>%s vCPU<br><span class='muted'>%s</span> · <span class='pill %s' title='%s'>%s</span></td>"
                "<td>%s GB<br><span class='pill %s'>%s</span> (%s%%)</td>"
                "<td>%s<br><span class='muted'>%s</span><br><span class='pill %s'>Latency: %s</span>%s</td><td><span class='pill %s'>%s</span></td></tr>"
                % (html.escape(vm["name"]), html.escape(vm.get("vcenter", "offline")),
                   html.escape(vm["host"]), html.escape(vm["vsphere_cluster"]),
                   vm["cpu"]["vcpus"], html.escape(shares_text), topology_pill, html.escape(recommendation["message"]), recommendation["status"],
                   round(vm["memory"]["assigned_mb"] / 1024, 1), reservation_pill, vm["memory"]["reservation_status"], vm["memory"]["reservation_percent"],
                   html.escape(vm["platform"]["virtual_hardware"]), html.escape(vm["platform"]["tools_version"]),
                   latency_pill, html.escape(latency_level), snapshot_badge,
                   os_pill, vm["os"]["status"])
            )
            storage_table_rows.append(
                "<tr><td><strong>%s</strong></td><td>%s</td><td>%s</td><td>%s</td></tr>"
                % (html.escape(vm["name"]), html.escape(controller_summary), html.escape(disk_summary), html.escape(network_summary))
            )
        finding_rows = []
        for finding in cluster["findings"]:
            severity = finding.get("severity", "INFO")
            cells = [finding.get("parameter", ""), finding.get("message", ""), finding.get("actual", ""), finding.get("expected", ""), finding.get("remediation", "Revisar manualmente")]
            escaped = [html.escape(str(x)) for x in cells]
            finding_rows.append(
                "<tr class='%s'><td><span class='pill %s'>%s</span></td><td class='mono'>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
                % (severity.lower(), severity.lower(), severity, escaped[0], escaped[1], escaped[2], escaped[3], escaped[4])
            )
        findings_html = (
            "<table class='data-table finding-table'><thead><tr><th>Severidad</th><th>Parametro</th><th>Hallazgo</th><th>Actual</th><th>Esperado</th><th>Remediacion</th></tr></thead><tbody>%s</tbody></table>"
            % "".join(finding_rows)
            if finding_rows else "<p class='muted'>Sin hallazgos para este cluster.</p>"
        )
        open_attr = " open" if performance["status"] == "RED" else ""
        rows.append(
            "<details class='cluster-section' id='%s'%s><summary class='cluster-header'><div><span class='chevron'>&#9656;</span><span class='eyebrow'>Cluster Always On</span><h2>%s</h2><p>%s nodos · %s host(s) fisico(s)</p></div><div class='score-ring %s'><strong>%s</strong><span>/100</span><small>%s</small></div></summary><div class='cluster-body'>"
            "<h3 class='section-title'>Nodos</h3><div class='table-scroll'><table class='data-table node-table'><thead><tr><th>Nodo</th><th>Host ESXi</th><th>CPU</th><th>RAM</th><th>Plataforma</th><th>OS</th></tr></thead><tbody>%s</tbody></table></div>"
            "<h3 class='section-title'>Aprovisionamiento y red</h3><div class='table-scroll'><table class='data-table storage-table'><thead><tr><th>Nodo</th><th>Controladoras</th><th>Discos</th><th>Red (adaptador / VLAN / MTU)</th></tr></thead><tbody>%s</tbody></table></div>"
            "<h3 class='section-title'>Hallazgos y remediacion</h3>%s</div></details>"
            % (slug, open_attr, html.escape(cluster["name"]), node_count, len(performance["physical_hosts"]),
               performance["status"].lower(), performance["score"], performance["status"],
               "".join(node_table_rows), "".join(storage_table_rows), findings_html)
        )
    overview_html = (
        "<section class='overview'><h2 class='section-title'>Resumen por cluster</h2><div class='table-scroll'><table class='data-table overview-table'><thead><tr><th>Cluster</th><th>Nodos</th><th>Hosts</th><th>Score</th><th>Estado</th><th>Criticos</th><th>Advertencias</th></tr></thead><tbody>%s</tbody></table></div></section>"
        % "".join(overview_rows)
    )
    generated = html.escape(report["generated_at"])
    return ("""<!doctype html><html lang='es'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Auditoria Always On</title><style>
:root{--ink:#17212b;--muted:#687582;--line:#dbe3e8;--paper:#f4f7f8;--white:#fff;--navy:#12344d;--red:#c43d3d;--red-bg:#fff1f1;--amber:#a66b00;--amber-bg:#fff8e6;--green:#28784b;--green-bg:#eaf7ef;--shadow:0 12px 28px rgba(18,52,77,.08)}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:14px/1.5 Inter,Segoe UI,Arial,sans-serif}main{max-width:1440px;margin:0 auto;padding:34px 28px 60px}.hero{background:var(--navy);color:#fff;border-radius:14px;padding:32px 36px;box-shadow:var(--shadow);display:flex;justify-content:space-between;gap:28px;align-items:flex-end}.eyebrow{text-transform:uppercase;letter-spacing:.12em;font-size:11px;font-weight:700;color:#7892a4}.hero .eyebrow{color:#9db7c8}.hero h1{font-size:32px;line-height:1.1;margin:7px 0 10px;font-weight:700}.hero p{margin:0;color:#c7d7e1}.hero-meta{text-align:right;color:#c7d7e1}.hero-meta strong{display:block;color:#fff;font-size:16px}.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:22px 0}.metric{background:var(--white);border:1px solid var(--line);border-radius:10px;padding:18px 20px;box-shadow:var(--shadow)}.metric span{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}.metric strong{display:block;font-size:29px;margin-top:5px;color:var(--navy)}.metric.red strong{color:var(--red)}.metric.yellow strong{color:var(--amber)}.metric.green strong{color:var(--green)}.overview{background:var(--white);border:1px solid var(--line);border-radius:12px;padding:20px 22px;margin:20px 0;box-shadow:var(--shadow)}.section-title{font-size:17px;color:var(--navy);margin:6px 0 13px}.table-scroll{overflow-x:auto}.data-table{width:100%;border-collapse:collapse;font-size:13px}.data-table th,.data-table td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}.data-table thead th{background:#eef2f4;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap}.data-table td.num,.data-table th.num{text-align:right;font-variant-numeric:tabular-nums}.overview-table td:nth-child(2),.overview-table td:nth-child(3),.overview-table td:nth-child(4),.overview-table td:nth-child(6),.overview-table td:nth-child(7),.overview-table th:nth-child(2),.overview-table th:nth-child(3),.overview-table th:nth-child(4),.overview-table th:nth-child(6),.overview-table th:nth-child(7){text-align:right;font-variant-numeric:tabular-nums}.overview-table a{color:var(--navy);font-weight:700;text-decoration:none}.overview-table a:hover{text-decoration:underline}.muted{color:var(--muted);font-size:12px}.mono{font:11px Consolas,monospace;color:var(--muted)}.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:800;letter-spacing:.04em;white-space:nowrap}.pill.ok,.pill.green,.pill.GREEN{background:var(--green-bg);color:var(--green)}.pill.bad,.pill.red,.pill.RED,.pill.high{background:var(--red-bg);color:var(--red)}.pill.yellow,.pill.YELLOW,.pill.medium{background:var(--amber-bg);color:var(--amber)}.pill.info{background:var(--green-bg);color:var(--green)}.cluster-section{background:var(--white);border:1px solid var(--line);border-radius:12px;margin:14px 0;box-shadow:var(--shadow);overflow:hidden}.cluster-section>summary{list-style:none;cursor:pointer}.cluster-section>summary::-webkit-details-marker{display:none}.cluster-header{display:flex;justify-content:space-between;align-items:center;gap:20px;padding:18px 22px}.cluster-header h2{margin:4px 0;font-size:22px;color:var(--navy);display:inline}.cluster-header p{margin:0;color:var(--muted)}.chevron{display:inline-block;margin-right:8px;color:var(--muted);transition:transform .15s}details[open]>summary .chevron{transform:rotate(90deg)}.cluster-body{padding:2px 22px 22px;border-top:1px solid var(--line)}.cluster-body h3.section-title{margin-top:18px}.score-ring{width:78px;height:78px;border:6px solid var(--line);border-radius:50%;display:flex;flex-wrap:wrap;align-content:center;justify-content:center;line-height:1;flex:0 0 auto}.score-ring strong{font-size:21px}.score-ring span{font-size:10px;color:var(--muted);align-self:center;margin-left:2px}.score-ring small{width:100%;text-align:center;font-size:9px;font-weight:700;letter-spacing:.1em;margin-top:4px}.score-ring.red{border-color:#edb1b1;color:var(--red)}.score-ring.yellow{border-color:#efd58e;color:var(--amber)}.score-ring.green{border-color:#a8d9ba;color:var(--green)}tr.high{background:var(--red-bg)}tr.medium{background:var(--amber-bg)}tr.info{background:var(--green-bg)}.footer{color:var(--muted);font-size:12px;text-align:right;margin-top:18px}@media(max-width:760px){main{padding:16px 12px 40px}.hero{display:block;padding:24px}.hero h1{font-size:26px}.hero-meta{text-align:left;margin-top:18px}.summary{grid-template-columns:1fr 1fr}.overview{padding:16px}.cluster-header{align-items:flex-start;padding:16px}.score-ring{flex:0 0 68px;width:68px;height:68px}.data-table{font-size:12px}}@media(max-width:420px){.summary{grid-template-columns:1fr}.cluster-header h2{font-size:18px}}
</style></head><body><main><header class='hero'><div><span class='eyebrow'>Informe de infraestructura critica</span><h1>Auditoria SQL Server Always On</h1><p>Evaluacion de homologacion, disponibilidad y rendimiento en VMware vSphere.</p></div><div class='hero-meta'><span>Generado</span><strong>%s</strong><span>Modo: %s</span></div></header><section class='summary'><div class='metric %s'><span>Score global</span><strong>%s/100</strong></div><div class='metric'><span>Clusters auditados</span><strong>%s</strong></div><div class='metric red'><span>Riesgos criticos</span><strong>%s</strong></div><div class='metric yellow'><span>Advertencias</span><strong>%s</strong></div></section>%s%s<footer class='footer'>Fuente: vCenter y configuracion declarada del inventario Always On.</footer></main></body></html>""".replace("%", "%%").replace("%%s", "%s") % (generated, html.escape(report.get("mode", "vCenter")), global_status.lower(), global_score, cluster_count, critical_count, warning_count, overview_html, "".join(rows)))


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
        report = {"generated_at": now_local().isoformat(), "vcenters": hosts, "mode": "vcenter", "clusters": results}
    finally:
        for service in services.values():
            connect.Disconnect(service)
    write_report(report, args.output_dir)


def write_report(report, output_dir):
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    stamp = now_local().strftime("%Y%m%d-%H%M%S")
    (output / ("alwayson-audit-%s.json" % stamp)).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    (output / ("alwayson-audit-%s.html" % stamp)).write_text(html_report(report), encoding="utf-8")
    print("Auditoria completada en modo %s: %d cluster(s), %d hallazgo(s)" % (report["mode"] if report.get("mode") else "vcenter", len(report["clusters"]), sum(len(c["findings"]) for c in report["clusters"])))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, yaml.YAMLError) as error:
        print("ERROR: %s" % error, file=sys.stderr)
        sys.exit(1)
