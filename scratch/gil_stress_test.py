import time
import threading
try:
    # Este módulo es compilado desde Rust a través de PyO3
    import tzanix_aether_core
except ImportError:
    print("Por favor, asegúrate de haber compilado la extensión: maturin develop --release --features python")
    import sys
    sys.exit(1)

# Variables globales para simulación UI
running = True
frames = 0
start_time = time.time()

def ui_render_loop():
    """Simula una interfaz gráfica de usuario corriendo a 60 FPS"""
    global frames, running
    while running:
        # Simulamos trabajo de UI (16.6 ms = ~60 FPS)
        time.sleep(0.0166)
        frames += 1

def heavy_rust_worker():
    """Simula un ataque inyectando una carga pesada al núcleo de Rust."""
    # Preparamos una señal falsa masiva
    snapshot = tzanix_aether_core.PyDenseSignalSnapshot(
        [900, 800, 700, 600, 500, 400, 300, 200],
        [100, 200, 300, 400, 500, 600, 700, 800]
    )
    
    print("\n[Worker] Lanzando ataque de cálculo MASIVO en Rust (100 millones de iteraciones)...")
    # Si `allow_threads` fue implementado correctamente en Rust, 
    # esto saturará un hilo del procesador pero dejará libre el GIL de Python.
    t0 = time.time()
    result = tzanix_aether_core.compute_signal_entropy_stress(snapshot, 100_000_000)
    elapsed = time.time() - t0
    print(f"[Worker] Finalizado en {elapsed:.2f}s. Entropía resultante: {result:.4f}")

if __name__ == "__main__":
    print("--- TZANiX-Æther-Core: PyO3 GIL Release Test ---")
    
    ui_thread = threading.Thread(target=ui_render_loop, daemon=True)
    ui_thread.start()
    
    # Pausa breve para estabilizar FPS base
    time.sleep(1)
    
    rust_thread = threading.Thread(target=heavy_rust_worker)
    rust_thread.start()
    
    # Monitoreo de FPS mientras Rust trabaja
    while rust_thread.is_alive():
        time.sleep(1)
        current_time = time.time() - start_time
        fps = frames / current_time
        print(f"[UI Monitor] FPS actuales: {fps:.1f} (El objetivo ideal son ~60 FPS)")
        
    running = False
    print("Prueba completada con éxito.")
