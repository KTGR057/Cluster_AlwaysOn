# Auditoria SQL Server Always On en vSphere

Pipeline Jenkins de solo lectura para comparar nodos de clusters SQL Server Always On y producir un informe JSON y HTML.

## Reutilizacion detectada

El workspace `Cluster_AlwaysOn` estaba vacio. Se reutilizaron los patrones encontrados en `../ansible-vm-provisioning`:

- Agente `k8s-ansible-arus` y contenedor `ansible`.
- Credencial Jenkins `vcenter_admin` mediante `withCredentials`.
- Versiones `ansible-core<2.17`, `ansible<10.0` y `pyvmomi==8.0.3.0.1`.
- Mapeo de vCenters existente: BTA `10.10.170.159`, MDE `10.10.144.159`.

No se reutilizo `provision_vm.yml` porque sus tareas modifican VMs. El auditor usa pyVmomi directamente para consultar configuracion, hosts fisicos y reglas DRS sin cambios en vCenter.

## Entrada

El archivo [inventario_alwayson.yml](inventario_alwayson.yml) contiene el inventario recibido. `nombre` es el identificador logico del Always On; no se usa como nombre del objeto ClusterComputeResource de vCenter. `nodos` contiene los nombres de las VMs. Como los nodos estan distribuidos entre Bogota y Medellin, el auditor determina el vCenter por prefijo (`BOP`/`SERV-BTA` -> `vCenter_BTA`; `MEP`/`SERV-MDE` -> `vCenter_MDE`) y abre ambas conexiones cuando el inventario las requiere.

El Jenkinsfile permite seleccionar el inventario `Prueba_2_nodos`, `Completo` o `Manual`. La opción `Prueba_2_nodos` usa [inventario_prueba_2nodos.yml](inventario_prueba_2nodos.yml), la opción `Completo` usa [inventario_alwayson.yml](inventario_alwayson.yml) y `Manual` utiliza el contenido de `CLUSTERS_YAML`.

El formato aceptado para el inventario es:

```yaml
clusters:
  - name: AG01
    nodes:
      - SQLNODE01
      - SQLNODE02
```

```yaml
clusters:
  - nombre: AG01
    nodos:
      - SQLNODE01
      - SQLNODE02
```

Los nodos deben ser nombres de VM en el vCenter seleccionado. La busqueda ignora diferencias de mayusculas/minusculas, pero falla si no encuentra el nodo o si el nombre es ambiguo. No se requieren IP para la auditoria de vSphere; pueden agregarse despues como dato de validacion.

## Salidas

Jenkins archiva en `artifacts/`:

- `alwayson-audit-*.json`: inventario detallado, hallazgos, hosts fisicos y valores comparados.
- `alwayson-audit-*.html`: resumen navegable con CPU, memoria, discos, red y recomendaciones.

## Ejecucion

El pipeline ejecuta la consulta real contra ambos vCenter. La validación de certificados TLS queda desactivada para mantener compatibilidad con el pipeline existente; la credencial `vcenter_admin` debe tener permisos de lectura en ambos.

Se reportan CPU (vCPU, sockets, cores/socket, reservas y limites), memoria (asignacion, reserva porcentual y limite), discos y controladores SCSI, aprovisionamiento, datastore/politica, adaptadores y red, hosts fisicos y reglas DRS.

## Recomendaciones evaluadas

- Misma topologia de CPU y memoria en todos los nodos.
- Reserva de memoria del 100% para SQL Server y limite de memoria ilimitado.
- Thick Eager Zeroed para discos de datos cuando el estandar de rendimiento lo requiera.
- Controladores PVSCSI y distribucion de discos entre controladores.
- Adaptadores VMXNET3 y redes/VLAN consistentes.
- Regla DRS VM-VM de anti-afinidad habilitada para todos los nodos.
- Nodos ubicados en hosts ESXi fisicos distintos; el reporte conserva tambien el vCenter de cada nodo.

Las reglas DRS solo pueden validarse dentro del vCenter donde residen los nodos. Si un grupo funcional cruza ambos vCenter, se valida la regla DRS de cada sede y se reporta por separado; vSphere no permite una regla DRS que abarque dos vCenter.

Estas son comprobaciones de referencia, no sustituyen la validacion de la arquitectura SQL, IOPS, latencia, NUMA ni la politica de almacenamiento corporativa.

## Permisos y seguridad

La credencial `vcenter_admin` debe tener permisos de lectura sobre VMs, datastores, redes, clusters DRS y reglas. No se requieren permisos de escritura. La contrasena se inyecta con `withCredentials` y se consume por variables de entorno; no se escribe en archivos ni argumentos de proceso.

Por compatibilidad con el repositorio de aprovisionamiento, el pipeline deja `VALIDATE_CERTS` desactivado por defecto. En produccion debe instalarse la CA de vCenter en la imagen del contenedor y ejecutarse con `VALIDATE_CERTS=true`.

## Ejecucion

El job requiere el plugin Pipeline Utility Steps (`readYaml`) y HTML Publisher (`publishHTML`). Para ejecución local se deben instalar las dependencias de `requirements.txt` y configurar `VCENTER_BTA_HOST`, `VCENTER_MDE_HOST`, `VCENTER_USER` y `VCENTER_PASS`.

## Subir el proyecto a Git

Desde esta carpeta, crear el repositorio local y registrar los archivos:

```powershell
git init
git add .
git commit -m "Agregar auditoria SQL Server Always On en vSphere"
git branch -M main
git remote add origin URL_DEL_REPOSITORIO
git push -u origin main
```

Reemplazar `URL_DEL_REPOSITORIO` por la URL HTTPS o SSH del repositorio corporativo. No subir credenciales, reportes generados ni archivos `clusters.yml`.
