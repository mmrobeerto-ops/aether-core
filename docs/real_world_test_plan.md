# TZANiX-Æther-Core: Guía de Ejecución de Pruebas en Entorno Real Controlado

Esta guía documenta los pasos necesarios para desplegar la infraestructura de producción simulada de **TZANiX-Æther-Core** en la nube (AWS/DigitalOcean) y orquestar las sondas de inyección distribuidas para verificar la resiliencia en un entorno de red real.

---

## 🏛️ Arquitectura de la Topología de Prueba

La prueba de producción real se compone de una red aislada que separa las fuentes de tráfico (atacantes/usuarios legítimos) del servidor bajo prueba (defensor).

```mermaid
graph TD
    subgraph Sondas Distribuidas (Generadores de Carga)
        K1[Locust/k6: US East] -->|Inyección DDoS / Querys| TargetIP[IP Pública del Servidor]
        K2[Locust/k6: Europe Central] -->|Inyección DDoS / Querys| TargetIP
        K3[Locust/k6: Asia Pacific] -->|Inyección DDoS / Querys| TargetIP
    end

    subgraph Servidor TZANiX (Defensor)
        TargetIP --> Gateway[Contenedor: tzanix-aether-core]
        Gateway -->|ALLOW / Redirección| Backend[Contenedor: mock-protected-api]
        Gateway -->|BLACKHOLE / VETO| Void[Descarte Físico / 403 Forbidden]
    end
```

---

## 🚀 Paso 1: Levantar la Infraestructura de Producción Simulada

### A. Aprovisionamiento de la Instancia de Red (El Defensor)
1. **Crear Instancia:** Levanta una máquina virtual en tu proveedor preferido:
   * **AWS EC2:** Instancia de tipo `t3.medium` (2 vCPUs, 4 GB RAM) con Ubuntu Server 22.04 LTS.
   * **DigitalOcean:** Droplet estándar de $24/mes (2 vCPUs, 4 GB RAM) con Ubuntu 22.04 LTS.
2. **Puertos de Red:** Asegúrate de abrir los siguientes puertos en tu Grupo de Seguridad / Firewall:
   * `22/TCP` para SSH.
   * `8000/TCP` para recibir el tráfico de stress del motor TZANiX.
3. **Instalación de Docker y Git:** Conéctate vía SSH y ejecuta:
   ```bash
   sudo apt-get update && sudo apt-get install -y docker.io docker-compose git htop
   sudo systemctl enable --now docker
   ```

### B. Despliegue del Contenedor Blindado
1. Clonar el repositorio en la máquina virtual:
   ```bash
   git clone <URL_DE_TU_REPOSITORIO> tzanix-aether-core
   cd tzanix-aether-core
   ```
2. Levantar la pila de contenedores (puerta de enlace TZANiX + backend mock de Nginx):
   ```bash
   sudo docker-compose up -d --build
   ```
3. Verificar que los contenedores estén corriendo:
   ```bash
   sudo docker ps
   ```
   * El puerto `8000` de la máquina host estará enlazado al motor TZANiX, el cual filtrará el tráfico antes de cualquier procesamiento pesado.

---

## 🛰️ Paso 2: Configurar las Sondas de Inyección Distribuida

Para simular una latencia y congestión de red real, las solicitudes de stress deben venir desde fuera de la red local del servidor.

### Opción A: Orquestación Gestionada mediante k6 Cloud (Recomendada)
1. Regístrate gratis en [k6.io](https://k6.io) y obtén tu token de API.
2. Autentica tu consola de pruebas de carga:
   ```bash
   k6 login cloud --token <TU_K6_CLOUD_TOKEN>
   ```
3. Ejecuta la prueba distribuyendo la carga en 3 zonas geográficas simultáneas ejecutando:
   ```bash
   k6 run --cloud \
     -e TARGET_URL=http://<IP_PUBLICA_DEL_SERVIDOR>:8000 \
     tests/k6_stress_tests.js
   ```
   * k6 Cloud aprovisionará automáticamente los agentes en diferentes regiones del mundo y centralizará las métricas de latencia real y pérdida de paquetes.

### Opción B: Despliegue Manual con Locust (Distribuido)
1. Provisiona 3 instancias virtuales económicas de $5/mes (1 vCPU, 1 GB RAM) en 3 regiones geográficas distintas (ej. US-East, EU-West, AP-East).
2. Instala Python y Locust en cada una:
   ```bash
   pip install locust
   ```
3. Inicia los clientes Locust apuntando al servidor defensor:
   ```bash
   locust -f tests/locustfile.py --headless -u 2000 -r 500 --host http://<IP_PUBLICA_DEL_SERVIDOR>:8000
   ```

---

## 📊 Los 3 Escenarios de Validación Real (Ejecución y Monitoreo)

Con las sondas activas y disparando contra la IP pública del servidor, ejecuta los siguientes escenarios:

### 📈 Escenario 1: Latencia de Red Real (Jitter y Redirección)
* **Objetivo:** Demostrar que el tiempo de ejecución interna del motor en Rust (~19.3 ns / ~74 ns LUT) no añade sobrecarga a los flujos reales de red expuestos a internet.
* **Prueba:**
  1. Ejecuta el Escenario 1 de k6 (`SCENARIO=1` a 2,000 RPS).
  2. Verifica en la consola de k6 la métrica `http_req_duration`.
* **Criterio de Éxito:** La latencia promedio del cliente a través de internet debe mantenerse en los rangos habituales de transporte de red física (~15-20 ms) sin añadir latencia sintética ni colas de procesamiento internas.

### 🛑 Escenario 2: Mitigación de Pérdida de Paquetes (Packet Loss Under Stress)
* **Objetivo:** Validar que los filtros branchless a nivel de buffer bloquean ataques geométricos/NaN instantáneamente sin degradar a los clientes legítimos.
* **Prueba:**
  1. Ejecuta el Escenario 2 de k6 (`SCENARIO=2` a 8,000 RPS con payloads NaN/inf).
  2. Envía en paralelo una consulta legítima en bucle desde tu terminal local:
     ```bash
     curl -i -X POST http://<IP_PUBLICA_DEL_SERVIDOR>:8000/api/v1/query \
       -H "Content-Type: application/json" \
       -d '{"channel_alpha":[800,800,800,800,800,800,800,800],"channel_beta":[600,600,600,600,600,600,600,600]}'
     ```
* **Criterio de Éxito:**
  * El 100% de las solicitudes de inyección maliciosa deben rebotar con código **HTTP 403 Forbidden** de forma inmediata.
  * Tu consulta legítima local debe recibir un **HTTP 200 OK** sin experimentar pérdidas de paquetes.

### 🛡️ Escenario 3: Prueba de Resiliencia del Sistema Operativo
* **Objetivo:** Demostrar científicamente que el uso estricto de buffers `no_std` lock-free mapeados en memoria evita las fugas de memoria y degradación por recolección de basura bajo ataques masivos continuos.
* **Prueba:**
  1. Ejecuta el Escenario 3 (`SCENARIO=3` a 5,000 RPS contra el auditor temporal Lucy) configurando la duración en 10 minutos (`DURATION=10m`).
  2. Conéctate vía SSH al servidor defensor y ejecuta `htop` o `top`.
  3. Identifica el proceso `tzanix-aether-core`.
* **Criterio de Éxito:** El consumo de memoria RAM física asignada al proceso de Rust debe permanecer totalmente **congelado y plano** (ejemplo: exactamente ~28 MB de principio a fin, sin subir un solo Kilobyte). Esto garantiza inmunidad total contra colapsos por falta de memoria (OOM).
