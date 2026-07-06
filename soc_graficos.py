#!/usr/bin/env python3
"""
soc_graficos.py — Genera gráficos a partir de CSVs de eventos exportados de Wazuh.

Uso:
    # Día de baseline (un solo CSV):
    python soc_graficos.py <csv_baseline>

    # Día de ataque (dos CSVs — baseline primero):
    python soc_graficos.py <csv_baseline> <csv_ataque>

El CSV debe tener al menos estas columnas (como las exporta Wazuh):
    timestamp, agent.name, rule.description, rule.level, rule.id
"""

import sys
import csv
from collections import Counter
from datetime import datetime, timedelta
import statistics

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker
import matplotlib.dates as mdates
import numpy as np


# ── Helpers ──────────────────────────────────────────────────────────────────

MESES = {
    'Jan':1,'Feb':2,'Mar':3,'Apr':4,'May':5,'Jun':6,
    'Jul':7,'Aug':8,'Sep':9,'Oct':10,'Nov':11,'Dec':12
}

def cargar_eventos(ruta_csv):
    """Lee el CSV y devuelve una lista de diccionarios (una fila = un evento)."""
    with open(ruta_csv, newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))

def parse_timestamp(ts):
    """Convierte el timestamp de Wazuh a datetime.
    Formato: 'Jul 4, 2026 @ 09:59:37.385'
    """
    fecha, hora = ts.split('@')
    partes = fecha.replace(',', '').split()
    mes, dia, anio = MESES[partes[0]], int(partes[1]), int(partes[2])
    hms = hora.strip().split(':')
    return datetime(anio, mes, dia, int(hms[0]), int(hms[1]), int(float(hms[2])))

def categoria_severidad(nivel):
    """Traduce rule.level numérico a categoría de severidad."""
    n = int(nivel)
    if n <= 6:  return 'Low (0-6)'
    if n <= 11: return 'Medium (7-11)'
    if n <= 14: return 'High (12-14)'
    return 'Critical (15)'


# ── Gráfico 1: Eventos por regla (baseline) ──────────────────────────────────

def grafico_por_regla(eventos, salida='eventos_por_regla.png'):
    """Barras horizontales: cuántas veces se disparó cada regla (rule.description)."""
    conteo = Counter(e['rule.description'] for e in eventos)
    etiquetas, valores = zip(*sorted(conteo.items(), key=lambda x: x[1]))

    fig, ax = plt.subplots(figsize=(10, 0.6 * len(etiquetas) + 1.5))
    barras = ax.barh(etiquetas, valores, color='#2a9d8f')
    for barra, valor in zip(barras, valores):
        ax.text(valor + 0.1, barra.get_y() + barra.get_height() / 2,
                str(valor), va='center', fontsize=10)

    agentes = sorted(set(e['agent.name'] for e in eventos))
    nombre = agentes[0] if len(agentes) == 1 else 'todos los agentes'
    ax.set_title(f'Eventos por regla - {nombre}  (total: {len(eventos)})',
                 fontsize=13, fontweight='bold')
    ax.set_xlabel('Número de eventos')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    fig.tight_layout()
    fig.savefig(salida, dpi=150)
    print(f'[OK] {salida}')


# ── Gráfico 2: Eventos por severidad (baseline) ──────────────────────────────

def grafico_por_severidad(eventos, salida='eventos_por_severidad.png'):
    """Barras por categoría de severidad (Low / Medium / High / Critical)."""
    categorias = ['Low (0-6)', 'Medium (7-11)', 'High (12-14)', 'Critical (15)']
    colores = {
        'Low (0-6)':    '#2a9d8f',
        'Medium (7-11)':'#e9c46a',
        'High (12-14)': '#f4a261',
        'Critical (15)':'#e76f51',
    }
    conteo = Counter(categoria_severidad(e['rule.level']) for e in eventos)
    valores = [conteo.get(c, 0) for c in categorias]

    fig, ax = plt.subplots(figsize=(8, 5))
    barras = ax.bar(categorias, valores, color=[colores[c] for c in categorias])
    for barra, valor in zip(barras, valores):
        ax.text(barra.get_x() + barra.get_width() / 2, valor + 0.2,
                str(valor), ha='center', fontsize=11, fontweight='bold')

    agentes = sorted(set(e['agent.name'] for e in eventos))
    nombre = agentes[0] if len(agentes) == 1 else 'todos los agentes'
    ax.set_title(f'Eventos por severidad - {nombre}  (total: {len(eventos)})',
                 fontsize=13, fontweight='bold')
    ax.set_ylabel('Número de eventos')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    fig.tight_layout()
    fig.savefig(salida, dpi=150)
    print(f'[OK] {salida}')


# ── Gráfico 3: Serie de tiempo (baseline) ────────────────────────────────────

def grafico_serie_tiempo(eventos, salida='serie_tiempo.png'):
    """Serie de tiempo: número de eventos por hora cronológica."""
    baldes = [parse_timestamp(e['timestamp']).replace(minute=0, second=0, microsecond=0)
              for e in eventos]
    conteo = Counter(baldes)
    inicio, fin = min(baldes), max(baldes)
    horas, t = [], inicio
    while t <= fin:
        horas.append(t); t += timedelta(hours=1)
    valores = [conteo.get(h, 0) for h in horas]

    fig, ax = plt.subplots(figsize=(11, 4.5))
    ax.plot(horas, valores, color='#264653', marker='o', linewidth=2)
    ax.fill_between(horas, valores, color='#264653', alpha=0.15)
    for h, v in zip(horas, valores):
        if v > 0:
            ax.text(h, v + 0.4, str(v), ha='center', fontsize=9, fontweight='bold')

    ax.xaxis.set_major_formatter(mdates.DateFormatter('%d %b %H:%M'))
    fig.autofmt_xdate(rotation=45)
    agentes = sorted(set(e['agent.name'] for e in eventos))
    nombre = agentes[0] if len(agentes) == 1 else 'todos los agentes'
    ax.set_title(f'Serie de tiempo de eventos - {nombre}  (total: {len(eventos)})',
                 fontsize=13, fontweight='bold')
    ax.set_ylabel('Número de eventos')
    ax.set_ylim(bottom=0)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    fig.tight_layout()
    fig.savefig(salida, dpi=150)
    print(f'[OK] {salida}')


# ── Gráfico 4a: Firma del ataque — reglas clave ──────────────────────────────

REGLAS_ATAQUE = {
    '31101': 'Web server\n400 error\n(reconocimiento)',
    '31151': 'Multiple 400\nfrom same IP\n(correlación nivel 10)',
    '554':   'File added\nto system\n(FIM — webshell)',
}

def grafico_firma_ataque(pre, post, salida='firma_ataque_reglas.png'):
    """Barras agrupadas: reglas clave del ataque en baseline vs. post-ataque."""
    pre_c  = Counter(r['rule.id'] for r in pre)
    post_c = Counter(r['rule.id'] for r in post)
    ids       = list(REGLAS_ATAQUE.keys())
    etiquetas = [REGLAS_ATAQUE[i] for i in ids]
    pre_vals  = [pre_c.get(i, 0)  for i in ids]
    post_vals = [post_c.get(i, 0) for i in ids]

    x = np.arange(len(ids)); w = 0.35
    fig, ax = plt.subplots(figsize=(11, 5.5))
    b1 = ax.bar(x - w/2, pre_vals,  w, label='Baseline (pre-ataque)', color='#2a9d8f')
    b2 = ax.bar(x + w/2, post_vals, w, label='Durante el ataque',     color='#e76f51')

    for b, v in zip(b1, pre_vals):
        if v > 0:
            ax.text(b.get_x()+b.get_width()/2, v+5, str(v),
                    ha='center', fontsize=10, fontweight='bold', color='#2a9d8f')
    for b, v in zip(b2, post_vals):
        if v > 0:
            ax.text(b.get_x()+b.get_width()/2, v+5, str(v),
                    ha='center', fontsize=10, fontweight='bold', color='#e76f51')

    ax.set_xticks(x); ax.set_xticklabels(etiquetas, fontsize=10)
    ax.set_ylabel('Número de eventos')
    ax.set_title('Firma del ataque — Reglas clave: Baseline vs. Ataque',
                 fontsize=12, fontweight='bold')
    ax.legend(fontsize=10)
    ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
    ax.set_yscale('log'); ax.set_ylim(bottom=0.5)
    ax.yaxis.set_major_formatter(matplotlib.ticker.ScalarFormatter())
    ax.annotate('* Escala logarítmica',
                xy=(0.98, 0.97), xycoords='axes fraction', fontsize=8,
                ha='right', va='top', color='gray',
                bbox=dict(boxstyle='round,pad=0.3', fc='white', ec='gray', alpha=0.7))
    fig.tight_layout()
    fig.savefig(salida, dpi=150)
    print(f'[OK] {salida}')


# ── Gráfico 4b: Comparativa de severidad baseline vs. ataque ─────────────────

def grafico_comparativa_severidad(pre, post, salida='comparativa_baseline_ataque.png'):
    """Barras lado a lado: distribución de severidad en baseline vs. ataque."""
    cats    = ['Low (0-6)', 'Medium (7-11)', 'High (12-14)', 'Critical (15)']
    colores = ['#2a9d8f', '#e9c46a', '#f4a261', '#e76f51']
    pre_lc  = Counter(categoria_severidad(r['rule.level']) for r in pre)
    post_lc = Counter(categoria_severidad(r['rule.level']) for r in post)
    pre_v   = [pre_lc.get(c, 0)  for c in cats]
    post_v  = [post_lc.get(c, 0) for c in cats]

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    for ax, vals, titulo, total in zip(
        axes, [pre_v, post_v],
        ['Baseline (pre-ataque)', 'Durante el ataque'],
        [len(pre), len(post)]
    ):
        bars = ax.bar(cats, vals, color=colores)
        for b, v in zip(bars, vals):
            ax.text(b.get_x()+b.get_width()/2, v+0.5, str(v),
                    ha='center', fontsize=10, fontweight='bold')
        ax.set_title(f'{titulo}\n(total: {total} eventos)', fontsize=12, fontweight='bold')
        ax.set_ylabel('Número de eventos')
        ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
    fig.suptitle('Impacto del ataque detectado en Wazuh — Comparativa de severidad',
                 fontsize=13, fontweight='bold', y=1.02)
    fig.tight_layout()
    fig.savefig(salida, dpi=150, bbox_inches='tight')
    print(f'[OK] {salida}')


# ── Gráfico 4c: Serie de tiempo baseline vs. ataque ──────────────────────────

def grafico_serie_tiempo_ataque(pre, post, salida='serie_tiempo_ataque.png'):
    """Serie de tiempo combinada con anotación del pico del ataque."""
    todos = pre + post
    baldes_all = [parse_timestamp(r['timestamp']).replace(minute=0, second=0, microsecond=0)
                  for r in todos]
    c_all = Counter(baldes_all)
    inicio, fin = min(c_all), max(c_all)
    horas, t = [], inicio
    while t <= fin:
        horas.append(t); t += timedelta(hours=1)
    valores = [c_all.get(h, 0) for h in horas]

    pico_h = max(c_all, key=c_all.get)
    pico_v = c_all[pico_h]

    # Baseline promedio (horas antes del pico)
    bl_vals = [c_all.get(h, 0) for h in horas if h < pico_h - timedelta(hours=2)]
    avg = statistics.mean(bl_vals) if bl_vals else 0

    fig, ax = plt.subplots(figsize=(14, 5))
    ax.plot(horas, valores, color='#264653', linewidth=2, marker='o', markersize=4)
    ax.fill_between(horas, valores, color='#264653', alpha=0.12)
    ax.annotate(
        f'Reconocimiento + Webshell\n{pico_v} eventos',
        xy=(pico_h, pico_v), xytext=(pico_h, pico_v + 150),
        ha='center', fontsize=9, fontweight='bold', color='#e76f51',
        arrowprops=dict(arrowstyle='->', color='#e76f51', lw=1.5)
    )
    if avg > 0:
        ax.axhline(avg, color='#2a9d8f', linestyle='--', linewidth=1.2, alpha=0.7,
                   label=f'Promedio baseline: {avg:.0f} eventos/hora')
        ax.legend(fontsize=9)
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%d %b %H:%M'))
    fig.autofmt_xdate(rotation=40)
    ax.set_title('Serie de tiempo — Baseline vs. Ataque · Wazuh',
                 fontsize=12, fontweight='bold')
    ax.set_ylabel('Número de eventos por hora')
    ax.set_ylim(bottom=0)
    ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
    fig.tight_layout()
    fig.savefig(salida, dpi=150)
    print(f'[OK] {salida}')


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print('Uso:')
        print('  python soc_graficos.py <csv_baseline>')
        print('  python soc_graficos.py <csv_baseline> <csv_ataque>')
        sys.exit(1)

    pre = cargar_eventos(sys.argv[1])
    print(f'Cargados {len(pre)} eventos desde {sys.argv[1]}')

    if len(sys.argv) == 2:
        # Modo baseline: tres gráficos de un solo CSV
        grafico_por_regla(pre)
        grafico_por_severidad(pre)
        grafico_serie_tiempo(pre)

    else:
        # Modo ataque: tres gráficos comparativos
        post = cargar_eventos(sys.argv[2])
        print(f'Cargados {len(post)} eventos desde {sys.argv[2]}')
        grafico_firma_ataque(pre, post)
        grafico_comparativa_severidad(pre, post)
        grafico_serie_tiempo_ataque(pre, post)


if __name__ == '__main__':
    main()
