---
name: tzanix-flyer
description: Crea flyers/anuncios de marketing con la marca TZANIX (redes sociales, WhatsApp). Úsalo cuando el usuario pida una publicación, flyer, anuncio, imagen promocional o post con imagen para TZANIX.
---

# Skill: Flyer de marca TZANIX

Genera imágenes promocionales consistentes con la marca TZANIX, renderizando
HTML con Playwright a PNG.

## Marca
- Fondo oscuro: `#0a0f1e` / `#0b1120` con glow azul radial y grid sutil (opacidad ~0.05).
- Azul marca: `#2563eb`; azul claro acento: `#60a5fa`.
- Verde (WhatsApp/éxito): `#4ade80`; rojo alerta: `#f87171`; ámbar: `#fbbf24`.
- Tipografía: Barlow (800/900 para títulos) + JetBrains Mono para datos/URL.
- Logo: escudo SVG con palomita + texto `TZA<b>N</b>IX` (la N en azul claro).
- Siempre incluir: WhatsApp **+52 637 137 7861** y `tzanix.com`.

## Medidas
- Flyer vertical redes/WhatsApp: **1080 x 1350**, `deviceScaleFactor: 2`.
- Portada Facebook: 1640 x 624. Perfil: 1024 x 1024.

## Cómo generar
1. Escribe el HTML en el scratchpad (plantilla: ver flyers previos del proyecto).
2. Renderiza con Playwright (`chromium.launch()`, viewport fijo, `waitForTimeout` ~900ms, screenshot a PNG).
3. Envía el PNG con SendUserFile.

## Reglas de contenido (honestidad)
- Vender **impacto en dinero**, no tecnología (no "entropía de Shannon").
- No sobre-prometer: el bloqueo luce con tráfico alto; en servers chicos vender
  diagnóstico/tranquilidad. Es una capa, no protección total.
- Si se usa el dato "46% del tráfico eran ataques", aclarar "en un servidor real
  que analizamos" (es dato real del servidor de prueba, mantenerlo honesto).
