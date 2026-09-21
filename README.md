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

Durante la ejecución, los archivos se crean temporalmente en `artifacts/` dentro del workspace del agente. Antes de ejecutar `cleanWs`, Jenkins hace lo siguiente:

- `archiveArtifacts` guarda el JSON y el HTML como artefactos permanentes del build.
- `publishHTML` publica el HTML en la página del job.
- `cleanWs` elimina únicamente la copia temporal del workspace.

Por tanto, el reporte se consulta desde Jenkins en el build ejecutado, en **Artifacts** o en **Auditoria SQL Server Always On**. La permanencia depende de la política de retención de builds de Jenkins y del Artifact Manager configurado.

Jenkins conserva:

- `alwayson-audit-*.json`: inventario detallado, hallazgos, hosts fisicos y valores comparados.
- `alwayson-audit-*.html`: resumen navegable con CPU, memoria, discos, red y recomendaciones.

## Ejecucion

El pipeline ejecuta la consulta real contra ambos vCenter. La validación de certificados TLS queda desactivada para mantener compatibilidad con el pipeline existente; la credencial `vcenter_admin` debe tener permisos de lectura en ambos.

Se reportan CPU (vCPU, sockets, cores/socket, reservas y limites), memoria (asignacion, reserva porcentual y limite), discos y controladores SCSI, aprovisionamiento, datastore/politica, adaptadores y red, hosts fisicos y reglas DRS.

Para cargas criticas SQL Server, el auditor aplica adicionalmente estas reglas:

- **vNUMA:** vCPU, sockets y cores por socket deben ser identicos; CPU Hot-Plug debe estar deshabilitado.
- **CPU Shares:** el nivel y valor deben ser homogeneos entre nodos. `Normal` es la recomendacion por defecto; `High` solo debe usarse con una politica formal de prioridad en resource pools.
- **Memoria:** la reserva debe ser del 100% de la RAM asignada y Memory Limit debe estar en Unlimited; Memory Hot-Add debe estar deshabilitado.
- **Hardware virtual:** la VM Hardware Version debe ser igual entre nodos.
- **VMware Tools:** se informa version y estado de Tools por VM y se marca inconsistencia o estado no saludable. La condicion de "ultima version compatible" requiere definir una baseline corporativa; sin ella el auditor no inventa una version objetivo.
- **Identidad del OS:** se comparan el `Guest OS` configurado en la VM y el `guestFullName` reportado por VMware Tools. El reporte muestra ambos valores, estado `COINCIDE`, `DIFIERE` o `NO_CONCLUSIVO`, y recomienda sincronizar la configuración de vCenter/Tools cuando sea necesario.
- **E/S:** se revisan Thick Eager Zeroed, controladoras PVSCSI/NVMe, separacion de buses para SO/datos/logs/TempDB y datastores compartidos.
- **Red y tiempo:** se informa adaptador, VLAN y MTU; se recomienda MTU 9000 solo cuando la red de replicacion lo soporte extremo a extremo. La sincronizacion NTP/dominio se deja como verificacion del guest porque vSphere no expone su estado real mediante esta consulta.
- **Alcance DRS:** cada nodo muestra su `Cluster VMware` real. La anti-afinidad VM-VM solo puede existir entre VMs del mismo `ClusterComputeResource`; si los nodos del Always On estan en clusters VMware distintos, el reporte lo informa y no genera un falso incumplimiento de una regla que no puede cruzar ese limite.

### Datos necesarios para MTU

La VM solo identifica el portgroup. El usuario configurado es `vcenter_admin` y tiene permisos administrativos, por lo que el auditor no espera una restriccion de permisos. Busca el `portgroupKey` del adaptador y consulta el `maxMtu` del vDS. Si la red es un portgroup estandar o la API no expone el valor en el objeto consultado, el reporte indicara `No expuesto por API`; en ese caso se debe confirmar manualmente en vCenter el MTU del portgroup, vDS, uplinks, switches fisicos y la interfaz de replicacion SQL. No se requiere una IP adicional para la consulta de vSphere.

### Interpretacion de memoria y controladoras

La reserva se valida comparando exactamente `Memory Reservation` contra `Memory assigned`, en MB. Por ejemplo, una VM de 530 GB con `542720 MB` asignados y `542720 MB` reservados debe aparecer como `100% LOCKED`; si la diferencia es mayor que cero, se marca como incumplimiento. La captura muestra ademas cuatro controladoras `VMware Paravirtual`, que corresponden a PVSCSI y cumplen el tipo recomendado; el reporte debe listar sus buses y no generar el hallazgo de controladora incorrecta.

El JSON conserva `score`, `status` (`RED`, `YELLOW` o `GREEN`) y cada hallazgo incluye parametro, valor actual, valor esperado y remediacion sugerida. El HTML presenta la misma informacion en una matriz visual.

## Recomendaciones evaluadas

- Misma topologia de CPU y memoria en todos los nodos.
- Reserva de memoria del 100% para SQL Server y limite de memoria ilimitado.
- Tipo de aprovisionamiento Thin/Thick informativo; no afecta el score porque puede variar intencionalmente por volumen.
- Controladores PVSCSI y distribucion de discos entre controladores.
- Adaptadores VMXNET3 y redes/VLAN consistentes.
- Regla DRS VM-VM de anti-afinidad habilitada para todos los nodos.
- Nodos ubicados en hosts ESXi fisicos distintos; el reporte conserva tambien el vCenter de cada nodo.

Las reglas DRS solo pueden validarse dentro del vCenter donde residen los nodos. Si un grupo funcional cruza ambos vCenter, se valida la regla DRS de cada sede y se reporta por separado; vSphere no permite una regla DRS que abarque dos vCenter.

Estas son comprobaciones de referencia, no sustituyen la validacion de la arquitectura SQL, IOPS, latencia, NUMA ni la politica de almacenamiento corporativa.

## Permisos y seguridad

La credencial `vcenter_admin` debe tener permisos de lectura sobre VMs, datastores, redes, clusters DRS y reglas. No se requieren permisos de escritura. La contrasena se inyecta con `withCredentials` y se consume por variables de entorno; no se escribe en archivos ni argumentos de proceso.

Para conservar históricos por más tiempo, la opción recomendada es configurar el Artifact Manager de Jenkins hacia S3, MinIO, Nexus o almacenamiento corporativo. Como alternativa, se puede copiar el reporte a un servidor remoto por SFTP, pero se necesitarían el host, la ruta, el puerto y una credencial SSH administrada por Jenkins. Esos datos no deben quedar escritos en el repositorio.

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
