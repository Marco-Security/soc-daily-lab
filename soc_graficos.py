#!/usr/bin/env python3
"""
soc_graficos.py - Genera graficos a partir de un CSV de eventos exportado de Wazuh.

Uso:
    python soc_graficos.py <ruta_al_csv>

El CSV debe tener al menos estas columnas (como las exporta Wazuh):
    timestamp, agent.name, rule.description, rule.level, rule.id
"""

import sys
import csv
from collections import Counter
from datetime import datetime, timedelta

import matplotlib
matplotlib.use("Agg")          # backend "sin ventana": dibuja directo a archivo PNG
import matplotlib.pyplot as plt
import matplotlib.dates as mdates


def cargar_eventos(ruta_csv):
    """Lee el CSV y devuelve una lista de diccionarios (una fila = un evento)."""
    with open(ruta_csv, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def grafico_por_regla(eventos, salida="eventos_por_regla.png"):
    """Barras horizontales: cuantas veces se disparo cada regla (rule.description)."""
    # Contamos cuantos eventos hay de cada descripcion de regla.
    conteo = Counter(e["rule.description"] for e in eventos)
    # Ordenamos de menor a mayor para que la barra mas larga quede arriba.
    etiquetas, valores = zip(*sorted(conteo.items(), key=lambda x: x[1]))

    fig, ax = plt.subplots(figsize=(10, 0.6 * len(etiquetas) + 1.5))
    barras = ax.barh(etiquetas, valores, color="#2a9d8f")

    # Escribimos el numero al final de cada barra.
    for barra, valor in zip(barras, valores):
        ax.text(valor + 0.1, barra.get_y() + barra.get_height() / 2,
                str(valor), va="center", fontsize=10)

    # Titulo: tomamos el nombre del agente del propio CSV.
    agentes = sorted(set(e["agent.name"] for e in eventos))
    nombre = agentes[0] if len(agentes) == 1 else "todos los agentes"
    ax.set_title(f"Eventos por regla - {nombre}  (total: {len(eventos)})",
                 fontsize=13, fontweight="bold")
    ax.set_xlabel("Numero de eventos")

    # Limpieza visual: quitamos los bordes superior y derecho.
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    fig.tight_layout()
    fig.savefig(salida, dpi=150)
    print(f"[OK] Guardado: {salida}")


def grafico_por_severidad(eventos, salida="eventos_por_severidad.png"):
    """Barras por categoria de severidad (mapea rule.level -> Low/Medium/High/Critical)."""
    # Orden fijo de categorias y su color semantico (verde -> rojo).
    categorias = ["Low (0-6)", "Medium (7-11)", "High (12-14)", "Critical (15)"]
    colores = {
        "Low (0-6)": "#2a9d8f",       # verde: informativo / bajo riesgo
        "Medium (7-11)": "#e9c46a",   # ambar: merece atencion
        "High (12-14)": "#f4a261",    # naranja: prioritario
        "Critical (15)": "#e76f51",   # rojo: maxima severidad
    }

    def categoria(nivel):
        """Traduce un rule.level (numero) a su categoria de severidad."""
        n = int(nivel)
        if n <= 6:
            return "Low (0-6)"
        if n <= 11:
            return "Medium (7-11)"
        if n <= 14:
            return "High (12-14)"
        return "Critical (15)"

    # Contamos eventos por categoria. Mostramos las 4 siempre (0 si no aparece),
    # para que se vea explicitamente que High/Critical estan en cero.
    conteo = Counter(categoria(e["rule.level"]) for e in eventos)
    valores = [conteo.get(c, 0) for c in categorias]

    fig, ax = plt.subplots(figsize=(8, 5))
    barras = ax.bar(categorias, valores, color=[colores[c] for c in categorias])

    # Numero encima de cada barra.
    for barra, valor in zip(barras, valores):
        ax.text(barra.get_x() + barra.get_width() / 2, valor + 0.2,
                str(valor), ha="center", fontsize=11, fontweight="bold")

    agentes = sorted(set(e["agent.name"] for e in eventos))
    nombre = agentes[0] if len(agentes) == 1 else "todos los agentes"
    ax.set_title(f"Eventos por severidad - {nombre}  (total: {len(eventos)})",
                 fontsize=13, fontweight="bold")
    ax.set_ylabel("Numero de eventos")

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    fig.tight_layout()
    fig.savefig(salida, dpi=150)
    print(f"[OK] Guardado: {salida}")


MESES = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
         "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


def parse_timestamp(ts):
    """Convierte el timestamp de Wazuh a un objeto datetime.

    Formato de entrada: 'Jul 4, 2026 @ 09:59:37.385'.
    Mapeamos el mes a mano (MESES) para no depender del idioma del sistema.
    """
    fecha, hora = ts.split("@")
    partes = fecha.replace(",", "").split()      # ["Jul", "4", "2026"]
    mes, dia, anio = MESES[partes[0]], int(partes[1]), int(partes[2])
    hms = hora.strip().split(":")                # ["09", "59", "37.385"]
    return datetime(anio, mes, dia, int(hms[0]), int(hms[1]), int(float(hms[2])))


def grafico_serie_tiempo(eventos, salida="serie_tiempo.png"):
    """Serie de tiempo: numero de eventos por hora cronologica (fecha + hora real)."""
    # Cada evento cae en el 'balde' de su hora (minutos/segundos a cero).
    baldes = [parse_timestamp(e["timestamp"]).replace(minute=0, second=0, microsecond=0)
              for e in eventos]
    conteo = Counter(baldes)

    # Rellenamos TODAS las horas entre la primera y la ultima, incluso las de 0
    # eventos, para que la linea sea continua y se vean los huecos de inactividad.
    inicio, fin = min(baldes), max(baldes)
    horas, t = [], inicio
    while t <= fin:
        horas.append(t)
        t += timedelta(hours=1)
    valores = [conteo.get(h, 0) for h in horas]

    fig, ax = plt.subplots(figsize=(11, 4.5))
    ax.plot(horas, valores, color="#264653", marker="o", linewidth=2)
    ax.fill_between(horas, valores, color="#264653", alpha=0.15)

    # Etiquetamos solo los puntos con actividad (evita saturar de ceros).
    for h, v in zip(horas, valores):
        if v > 0:
            ax.text(h, v + 0.4, str(v), ha="center", fontsize=9, fontweight="bold")

    # Eje X con formato de fecha/hora legible.
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%d %b %H:%M"))
    fig.autofmt_xdate(rotation=45)

    agentes = sorted(set(e["agent.name"] for e in eventos))
    nombre = agentes[0] if len(agentes) == 1 else "todos los agentes"
    ax.set_title(f"Serie de tiempo de eventos - {nombre}  (total: {len(eventos)})",
                 fontsize=13, fontweight="bold")
    ax.set_ylabel("Numero de eventos")
    ax.set_ylim(bottom=0)

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    fig.tight_layout()
    fig.savefig(salida, dpi=150)
    print(f"[OK] Guardado: {salida}")


def main():
    if len(sys.argv) < 2:
        print("Uso: python soc_graficos.py <ruta_al_csv>")
        sys.exit(1)

    ruta = sys.argv[1]
    eventos = cargar_eventos(ruta)
    print(f"Cargados {len(eventos)} eventos desde {ruta}")

    grafico_por_regla(eventos)
    grafico_por_severidad(eventos)
    grafico_serie_tiempo(eventos)


if __name__ == "__main__":
    main()
