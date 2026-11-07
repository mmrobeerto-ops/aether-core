---
description: Reconstruye el kit de instalación (ZIP) con el binario y el instalador actuales.
---

Reconstruye el kit de instalación del cliente:
1. Compila el agente y el reporte si hace falta.
2. Verifica que el binario `deploy-guard/tzanix-guard` tenga las protecciones
   (soporte WINDOW, texto OBSERVACION, etiqueta tzanix-guard) con `strings`.
3. Empaqueta `tzanix-guard`, `instalar.sh`, `tzanix-report` y `LEEME.md` de
   `deploy-guard/` en un `TZANIX-instalar.zip` dentro del scratchpad.
4. Envíaselo al usuario con SendUserFile y recuérdale que ese es el kit para el cliente.

Antes de empaquetar, corre `bash -n deploy-guard/instalar.sh` para confirmar
que el instalador no tiene errores de sintaxis.
