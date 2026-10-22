# Net-Check

Diagnóstico rápido de conectividad desde terminal, con informes HTML y JSON.
Un proyecto de soporte técnico en Python, sin dependencias externas.

## Qué hace

- Resuelve nombres mediante el DNS configurado en el sistema.
- Comprueba si puede establecer una conexión TCP con un destino y puerto.
- Realiza una petición HTTPS con validación de certificados.
- Ejecuta comprobaciones en paralelo y muestra duración y errores.
- Exporta un informe visual y otro estructurado para analizar resultados.

## Inicio rápido

Requiere Python 3.10 o superior. Desde la carpeta del proyecto:

```bash
python3 netcheck.py --demo
python3 netcheck.py
```

En WSL usa `python3`. En Windows (PowerShell), con Python instalado:

```powershell
py -3 netcheck.py --demo --output reports/demo
py -3 netcheck.py --dns example.com --tcp example.com:443 --https https://example.com
```

No hace falta instalar paquetes ni crear un entorno virtual.
Abre `reports/report.html` en el navegador. La demo utiliza datos **ficticios** y
no requiere Internet. La ejecución normal consulta `example.com`.

## Personalizar destinos

```bash
python3 netcheck.py --dns example.com --tcp example.com:443 --https https://example.com --timeout 3
python3 netcheck.py --tcp 127.0.0.1:8000 --output reports/local
```

Puedes repetir `--dns`, `--tcp` y `--https`. Al indicar cualquier destino, se
sustituyen todos los predeterminados. Un servicio local debe estar escuchando
para que la prueba TCP sea correcta. Las opciones TCP usan `HOST:PUERTO`;
para IPv6 puedes usar `[::1]:443` (también se admite `::1:443`).
`--timeout` acepta números finitos mayores que 0 y hasta 60 segundos.
`--demo` no se combina con destinos reales.

## Interpretar resultados

`OK` significa que esa comprobación terminó correctamente. `FALLO` incluye el
error recibido; puede deberse al destino, un proxy, un firewall o la conexión.
Un HTTP 4xx/5xx se informa como fallo de la petición, aunque el servidor responda.
La duración mide la operación completa, **no es un ping ICMP** ni un test de velocidad.
HTTPS sigue redirecciones únicamente hacia HTTPS y usa los proxies configurados
en el entorno. Valida certificados con las autoridades de confianza de Python/sistema.
No descarga el cuerpo de la respuesta: comprueba la recepción de cabeceras.

`--timeout` limita operaciones de socket TCP/HTTPS; no es un límite global.
La resolución DNS depende del resolver del sistema y puede superar ese tiempo.
No se guarda el nombre del equipo ni un inventario de interfaces. Los informes
sí incluyen destinos, direcciones resueltas y errores: revísalos antes de compartir.
Los informes se sobrescriben en cada ejecución y están excluidos de Git.

Códigos de salida: `0` si todo pasa o se ejecuta la demo, `1` si falla una prueba,
`2` si los argumentos son inválidos y `3` si no se pueden guardar los informes
(puede quedar un informe parcial). Prueba únicamente destinos que puedas consultar.

## Pruebas

```bash
python3 -m unittest discover -s tests -v
```

Las pruebas usan simulaciones y no necesitan Internet. GitHub Actions está
configurado para Windows y Linux con Python 3.10 y 3.12. Los resultados reales de CI se consultan en la pestaña Actions del repositorio.

## Informe de ejemplo

Abre [la demo HTML](examples/demo/report.html) en el navegador. Todos sus datos son
ficticios. Para regenerarla: `python3 netcheck.py --demo --output examples/demo`.
El JSON incluye fecha UTC, marca `demo`, totales y resultados con tipo, destino,
estado, duración en milisegundos, detalle y error (`null` cuando pasa).

## Estructura

- `netcheck.py`: CLI, comprobaciones y generación de informes.
- `tests/`: pruebas de errores, DNS, argumentos, demo y escape HTML.
- `.github/workflows/tests.yml`: integración continua.

## Posibles mejoras

Histórico de resultados, comparación entre ejecuciones y diagnóstico de proxy.

## Licencia

MIT. Consulta `LICENSE`.
