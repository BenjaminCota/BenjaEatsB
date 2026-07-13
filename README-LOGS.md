# Módulo de logs de seguridad para sitio estático

Adaptación del módulo `admin/logs` de *secure-framework-lab* (Next.js) a un
sitio estático puro (HTML/CSS/JS sin framework ni build tool). Sin dependencias:
solo necesita Node instalado.

## Archivos

| Archivo | Qué es |
|---|---|
| `server.mjs` | Mini-servidor que sirve el sitio estático **y** registra todo el tráfico con detección de ataques. |
| `admin.html` | Panel de administración (visor de logs) protegido por contraseña. |

## Instalación

1. Copia `server.mjs` y `admin.html` a la **raíz** de tu proyecto (junto a `index.html`).
2. Arranca el servidor:

   ```powershell
   node server.mjs
   ```

3. Abre:
   - Sitio: http://localhost:3000
   - Panel: http://localhost:3000/admin — contraseña por defecto: `admin123`

4. Para cambiar la contraseña del panel:

   ```powershell
   $env:ADMIN_PASSWORD = "mi-clave-segura"; node server.mjs
   ```

5. Agrega `.data/` al `.gitignore` (ahí se guarda `security-logs.json`).

## Qué registra

- **VISIT** — cada página visitada y cada petición a rutas inexistentes (404).
  Los sub-recursos (CSS, JS, imágenes, fuentes) que cargan bien no se registran
  para no meter ruido; si dan 404 sí se registran (puede ser una sonda).
- **ATTACK** — cinco detecciones:
  1. Patrones en la URL: inyección SQL, XSS, path traversal, inyección de comandos.
  2. Flood: 15+ peticiones de la misma IP en 12 segundos.
  3. Enumeración: 8+ rutas distintas de la misma IP en 12 segundos.
  4. Rutas-sonda típicas de escáneres (`.env`, `wp-admin`, `/.git`, `.php`, etc.).
  5. User-agents de herramientas (sqlmap, nikto, nmap, gobuster...).
- **AUTHZ** — intentos de entrar al panel con contraseña incorrecta.
- **ADMIN** — el borrado de logs desde el panel (queda siempre registrado).

## El panel (`/admin`)

Mismas funciones que el visor original: tarjetas de resumen, búsqueda de texto,
filtros por categoría y severidad, auto-refresh cada 4 s, tabla de actividad
agrupada por IP (con badge "Sospechosa"), exportación a JSON/CSV y botón de
limpiar logs con confirmación.

## Cómo probarlo rápido

```powershell
# Visita normal
curl http://localhost:3000/

# Simular otra IP (modo educativo, ?simip=)
curl "http://localhost:3000/?simip=8.8.8.8"

# Sonda de escáner (ruta inexistente típica)
curl http://localhost:3000/wp-login.php

# Inyección SQL en la URL
curl "http://localhost:3000/?q=%27%20OR%201=1"

# User-agent de herramienta
curl -A "sqlmap/1.7" http://localhost:3000/
```

## Limitaciones (heredadas del módulo original, es material de práctica)

- El almacén es un archivo JSON con rotación a 500 eventos: vale para un
  laboratorio o demo, no para producción (ahí iría una base de datos).
- Funciona con **una sola instancia** del servidor (el archivo no soporta
  escrituras concurrentes de varios procesos).
- La contraseña viaja en un header sin HTTPS: úsalo en red local o detrás de
  un proxy con TLS.
- El parámetro `?simip=` permite falsificar la IP a propósito (modo educativo);
  elimínalo de `logTraffic` si no lo quieres.
