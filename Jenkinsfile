pipeline {
    agent { label 'k8s-ansible-arus' }

    parameters {
        choice(name: 'MODO_AUDITORIA', choices: ['OFFLINE', 'VCENTER'], description: 'OFFLINE no contacta vCenter y usa datos sinteticos; VCENTER ejecuta la auditoria real')
        choice(name: 'VCENTER_SELECCIONADO', choices: ['vCenter_BTA', 'vCenter_MDE'], description: 'vCenter donde estan los clusters Always On')
        choice(name: 'INVENTARIO_SELECCIONADO', choices: ['Prueba_2_nodos', 'Completo', 'Manual'], description: 'Inventario a auditar')
        text(name: 'CLUSTERS_YAML', defaultValue: '''clusters:
  - name: AG01
    nodes:
      - SQLNODE01
      - SQLNODE02
''', description: 'YAML con clusters y nodos. Cada cluster requiere name y nodes.')
        booleanParam(name: 'VALIDATE_CERTS', defaultValue: false, description: 'Validar el certificado TLS de vCenter')
    }

    environment {
        PYTHONUNBUFFERED = '1'
        PYTHONWARNINGS = 'ignore'
    }

    stages {
        stage('Validar parametros') {
            steps {
                script {
                    def inventoryText
                    if (params.INVENTARIO_SELECCIONADO == 'Prueba_2_nodos') {
                        inventoryText = readFile(file: 'inventario_prueba_2nodos.yml')
                    } else if (params.INVENTARIO_SELECCIONADO == 'Completo') {
                        inventoryText = readFile(file: 'inventario_alwayson.yml')
                    } else {
                        inventoryText = params.CLUSTERS_YAML
                    }
                    if (!inventoryText?.trim()) {
                        error 'El inventario seleccionado no puede estar vacio'
                    }
                    writeFile file: 'clusters.yml', text: inventoryText
                    def config = readYaml file: 'clusters.yml'
                    if (!(config?.clusters instanceof List) || config.clusters.isEmpty()) {
                        error 'El YAML debe contener una lista no vacia en clusters'
                    }
                    config.clusters.eachWithIndex { cluster, index ->
                        def clusterName = cluster.name ?: cluster.nombre
                        def clusterNodes = cluster.nodes ?: cluster.nodos
                        if (!clusterName?.toString()?.trim() || !(clusterNodes instanceof List) || clusterNodes.size() < 2) {
                            error "Cluster ${index + 1}: requiere name y al menos dos nodos"
                        }
                        if (clusterNodes.any { !it?.toString()?.trim() }) {
                            error "Cluster ${clusterName}: nodes contiene un valor vacio"
                        }
                    }
                }
            }
        }

        stage('Preparar contenedor Ansible') {
            steps {
                container('ansible') {
                    sh '''
                        apt-get update && apt-get install -y git
                        pip install --upgrade pip
                        pip install "ansible-core<2.17" "ansible<10.0" "pyvmomi==8.0.3.0.1" PyYAML Jinja2
                    '''
                }
            }
        }

        stage('Auditar vSphere') {
            steps {
                script {
                    def runAudit = {
                        container('ansible') {
                            sh '''
                                export AUDIT_MODE="${MODO_AUDITORIA}"
                                export VCENTER_VALIDATE_CERTS="${VALIDATE_CERTS}"
                                if [ "${MODO_AUDITORIA}" = "VCENTER" ]; then
                                  case "${VCENTER_SELECCIONADO}" in
                                    vCenter_BTA) export VCENTER_HOST=10.10.170.159 ;;
                                    vCenter_MDE) export VCENTER_HOST=10.10.144.159 ;;
                                    *) echo "vCenter no permitido" >&2; exit 2 ;;
                                  esac
                                fi
                                ansible-playbook -i localhost, -c local audit_alwayson.yml
                            '''
                        }
                    }
                    if (params.MODO_AUDITORIA == 'VCENTER') {
                        withCredentials([usernamePassword(credentialsId: 'user_vCenter', usernameVariable: 'VCENTER_USER', passwordVariable: 'VCENTER_PASS')]) {
                            runAudit()
                        }
                    } else {
                        runAudit()
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'artifacts/alwayson-audit-*.json,artifacts/alwayson-audit-*.html', allowEmptyArchive: true, fingerprint: true
            publishHTML(target: [allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true,
                reportDir: 'artifacts', reportFiles: '*.html', reportName: 'Auditoria SQL Server Always On'])
            cleanWs(deleteDirs: true, notFailBuild: true)
        }
    }
}
