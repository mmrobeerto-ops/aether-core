---
description: Explica cómo correr el reporte de amenazas en el servidor de un cliente.
---

Da al usuario los comandos (uno por bloque, limpios, para copiar en el teléfono)
para generar el reporte de amenazas en el servidor de un cliente:

1. Juntar TODO el historial de logs (incluidos rotados y comprimidos) en un archivo.
2. Correr `tzanix-report` sobre ese archivo.

Recuerda: el reporte necesita >= 2048 líneas. Si junta menos, el servidor es
muy tranquilo → vender el guardia en observación, no el reporte histórico.

Cuando el usuario pegue el resultado, explícale cada línea con manzanas y
tradúcelo a dinero/impacto para que lo use como argumento de venta.
