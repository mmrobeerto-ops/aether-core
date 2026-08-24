import subprocess
import time
import sys
import os
import urllib.request
import urllib.error
import json
from concurrent.futures import ThreadPoolExecutor

# TZANiX-Aether-Core Stress Test Automation Script (ASCII-Safe for Windows)

PORT = 8000
SERVER_URL = f"http://127.0.0.1:{PORT}"

def run_http_request(url, method="POST", data=None):
    req = urllib.request.Request(url, method=method)
    if data:
        req.add_header('Content-Type', 'application/json')
        body = json.dumps(data).encode('utf-8')
    else:
        body = None
    
    try:
        with urllib.request.urlopen(req, data=body, timeout=5) as response:
            return response.status, response.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8')
    except Exception as e:
        return 500, str(e)

def run_scenario(name, endpoint, method, payload, concurrency, duration):
    print(f"\n[+] Iniciando {name}...")
    print(f"  Concurrencia: {concurrency} hilos | Duracion: {duration}s")
    
    url = f"{SERVER_URL}{endpoint}"
    start_time = time.time()
    total_requests = 0
    status_counts = {}
    latencies = []

    def worker():
        nonlocal total_requests
        while time.time() - start_time < duration:
            t0 = time.time()
            status, _ = run_http_request(url, method=method, data=payload)
            elapsed = time.time() - t0
            latencies.append(elapsed * 1000.0) # ms
            total_requests += 1
            status_counts[status] = status_counts.get(status, 0) + 1

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(worker) for _ in range(concurrency)]
        for f in futures:
            f.result()

    total_time = time.time() - start_time
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
    rps = total_requests / total_time

    print(f"[*] Resultados de {name}:")
    print(f"  Total Peticiones : {total_requests}")
    print(f"  Tiempo Total     : {total_time:.2f} s")
    print(f"  RPS (Req/Seg)    : {rps:.2f}")
    print(f"  Latencia Media   : {avg_latency:.2f} ms")
    print(f"  Codigos de Resp. : {status_counts}")

def main():
    print("=============================================================")
    print("      TZANiX-Aether-Core: Suite de Estres de Produccion      ")
    print("=============================================================\n")

    # 1. Iniciar el servidor Rust en segundo plano
    print("[*] Compilando e iniciando el servidor Rust...")
    server_process = subprocess.Popen(
        ["cargo", "run", "--release", "--", "server"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Esperar a que el puerto 8000 esté activo
    print("[*] Esperando que el servidor responda en el puerto 8000...")
    for _ in range(30):
        try:
            urllib.request.urlopen(f"{SERVER_URL}/api/v1/heavy-calc?stress=false", timeout=1)
            print("[*] Servidor Rust listo y escuchando!")
            break
        except Exception:
            time.sleep(1)
    else:
        print("[x] Error: El servidor no inicio a tiempo.")
        server_process.terminate()
        sys.exit(1)

    try:
        # Escenario A: Tráfico Legítimo Masivo (Canales coherentes bajo r=0.001)
        run_scenario(
            name="Escenario A: Trafico Legitimo Masivo",
            endpoint="/api/v1/query",
            method="POST",
            payload={
                "channel_alpha": [800, 800, 800, 800, 800, 800, 800, 800],
                "channel_beta": [600, 600, 600, 600, 600, 600, 600, 600]
            },
            concurrency=20,
            duration=5
        )

        # Escenario B: El Bombardeo de Inyección (Veto Geométrico / NaN)
        # Nota: El payload contiene la firma NaN que activa el veto branchless inmediato
        run_scenario(
            name="Escenario B: Inyeccion Maliciosa (Veto Geometrico)",
            endpoint="/api/v1/query",
            method="POST",
            payload={"tensor": ["NaN", 1.0, "inf"]},
            concurrency=20,
            duration=5
        )

        # Escenario C: El Ataque de Agotamiento de CPU (LucyTimeAuditor Veto)
        run_scenario(
            name="Escenario C: Agotamiento de CPU (Veto Temporal Lucy)",
            endpoint="/api/v1/heavy-calc?stress=true",
            method="GET",
            payload=None,
            concurrency=20,
            duration=5
        )

    finally:
        print("\n[*] Apagando el servidor Rust de forma limpia...")
        server_process.terminate()
        try:
            server_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_process.kill()
        print("[*] Apagado completo.")

if __name__ == "__main__":
    main()
