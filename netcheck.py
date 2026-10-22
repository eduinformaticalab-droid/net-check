#!/usr/bin/env python3
"""Diagnóstico básico de conectividad. Solo biblioteca estándar."""
import argparse
import concurrent.futures
import datetime
import html
import http.client
import json
import math
import ssl
import sys
from pathlib import Path
import socket
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit


class HTTPSOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """No permitir que una prueba HTTPS termine enviando HTTP sin cifrar."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        https_target(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def check(kind, target, timeout):
    start = time.perf_counter()
    try:
        if kind == 'DNS':
            addresses = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
            detail = ', '.join(sorted({a[4][0] for a in addresses}))
        elif kind == 'TCP':
            host, port = target.rsplit(':', 1)
            host = host.strip('[]')
            with socket.create_connection((host, int(port)), timeout=timeout):
                detail = 'Conexión establecida'
        elif kind == 'HTTPS':
            https_target(target)
            request = urllib.request.Request(target, headers={'User-Agent': 'Net-Check/1.0'})
            opener = urllib.request.build_opener(
                HTTPSOnlyRedirect(),
                urllib.request.HTTPSHandler(context=ssl.create_default_context()))
            with opener.open(request, timeout=timeout) as response:
                detail = f'HTTP {response.status}'
        else:
            raise ValueError('Tipo de comprobación desconocido')
        ok = True
    except (OSError, ValueError, UnicodeError, http.client.HTTPException,
            urllib.error.URLError, argparse.ArgumentTypeError) as exc:
        ok, detail = False, str(exc)
    return dict(kind=kind, target=target, ok=ok,
                elapsed_ms=round((time.perf_counter() - start) * 1000, 1),
                detail=detail, error=None if ok else detail)


def make_report(results):
    return {'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'passed': sum(r['ok'] for r in results), 'total': len(results), 'results': results}


def render_html(report):
    escape = lambda value: html.escape(str(value), quote=True)
    banner = '<p><strong>DEMO: datos ficticios, sin acceso a la red.</strong></p>' if report.get('demo') else ''
    rows = ''.join(
        '<tr>' + ''.join(f'<td>{escape(value)}</td>' for value in
        (r['kind'], r['target'], 'OK' if r['ok'] else 'FALLO', r['elapsed_ms'], r['detail'])) + '</tr>'
        for r in report['results'])
    return '''<!doctype html><html lang="es"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Net-Check · Informe</title><style>
body{font:16px system-ui;background:#0c1424;color:#e7eefb;margin:0;padding:5vw}
main{max-width:1100px;margin:auto}h1{font-size:42px;margin-bottom:8px}
p{color:#a7b7d0}.summary{background:#17334b;padding:22px;border-radius:16px;font-size:24px}
.scroll{overflow:auto}table{width:100%;border-collapse:collapse;margin-top:28px}
th,td{text-align:left;padding:15px;border-bottom:1px solid #2b3b52}th{color:#6de0c2}
td:last-child{overflow-wrap:anywhere;min-width:200px}footer{margin-top:30px;color:#a7b7d0}
</style><main><h1>Net-Check</h1><p>Diagnóstico de conectividad</p>''' + (
        f'{banner}<div class="summary">{escape(report["passed"])} / {escape(report["total"])} comprobaciones correctas</div>'
        f'<p>{escape(report["generated_at"])}</p><div class="scroll"><table><thead><tr>'
        '<th>Prueba</th><th>Destino</th><th>Estado</th><th>Tiempo (ms)</th><th>Detalle</th>'
        f'</tr></thead><tbody>{rows}</tbody></table></div><footer>'
        'El tiempo mide la comprobación completa, no el ping. Un fallo puede deberse a un bloqueo '
        'o al destino; no demuestra por sí solo una avería de tu conexión.</footer></main></html>')


def tcp_target(value):
    try:
        host, port = value.rsplit(':', 1)
        if not host or not 1 <= int(port) <= 65535:
            raise ValueError()
    except ValueError:
        raise argparse.ArgumentTypeError('Usa HOST:PUERTO con puerto entre 1 y 65535')
    dns_target(host.strip('[]'))
    if ('[' in host or ']' in host) and not (host.startswith('[') and host.endswith(']')):
        raise argparse.ArgumentTypeError('Corchetes IPv6 inválidos')
    return value


def dns_target(value):
    if not value or any(c.isspace() or c in '/\\@?#<>' or ord(c) < 32 for c in value):
        raise argparse.ArgumentTypeError('Usa un nombre de host o dirección IP sin URL ni espacios')
    return value


def https_target(value):
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment
                or any(c.isspace() or ord(c) < 32 for c in value)):
            raise ValueError()
        dns_target(parsed.hostname)
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError()
    except (ValueError, argparse.ArgumentTypeError):
        raise argparse.ArgumentTypeError('Usa una URL HTTPS válida, sin credenciales ni fragmentos') from None
    return value


def positive_timeout(value):
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError('El timeout debe ser un número') from None
    if not math.isfinite(number) or not 0 < number <= 60:
        raise argparse.ArgumentTypeError('El timeout debe ser mayor que 0 y como máximo 60')
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dns', action='append', type=dns_target, help='Dominio; repetible')
    parser.add_argument('--tcp', action='append', type=tcp_target, help='HOST:PUERTO; repetible')
    parser.add_argument('--https', action='append', type=https_target, help='URL HTTPS; repetible')
    parser.add_argument('--timeout', type=positive_timeout, default=4)
    parser.add_argument('--output', type=Path, default=Path('reports'))
    parser.add_argument('--demo', action='store_true', help='Informe ficticio sin acceder a la red')
    args = parser.parse_args(argv)
    if args.demo and (args.dns or args.tcp or args.https):
        parser.error('--demo no admite destinos reales')
    if args.demo:
        results = [dict(kind='DNS', target='example.com', ok=True, elapsed_ms=12.5,
                        detail='DEMO: datos ficticios; no se ha consultado la red', error=None),
                   dict(kind='TCP', target='example.com:443', ok=False, elapsed_ms=4000,
                        detail='DEMO: timeout simulado', error='Timeout ficticio'),
                   dict(kind='HTTPS', target='https://example.com', ok=True, elapsed_ms=85,
                        detail='DEMO: HTTP 200 ficticio', error=None)]
    else:
        custom = args.dns or args.tcp or args.https
        jobs = ([('DNS', x) for x in (args.dns or ([] if custom else ['example.com']))] +
                [('TCP', x) for x in (args.tcp or ([] if custom else ['example.com:443']))] +
                [('HTTPS', x) for x in (args.https or ([] if custom else ['https://example.com']))])
        # getaddrinfo usa el resolver del sistema; su tiempo máximo no lo controla socket timeout.
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda job: check(*job, args.timeout), jobs))
    report = make_report(results)
    report['demo'] = args.demo
    try:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / 'report.json').write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
        page = render_html(report)
        (args.output / 'report.html').write_text(page, encoding='utf-8')
    except OSError as exc:
        print(f'Error al guardar informes: {exc}', file=sys.stderr)
        return 3
    for r in results:
        print(f"{'OK' if r['ok'] else 'FALLO':5} {r['kind']:5} {r['target']} ({r['elapsed_ms']} ms) — {r['detail']}")
    print(f"\nInforme: {(args.output / 'report.html').resolve()}")
    return 0 if args.demo or all(r['ok'] for r in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
