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

import matplotlib
matplotlib.use("Agg")          # backend "sin ventana": dibuja directo a archivo PNG
import matplotlib.pyplot as plt


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


def main():
    if len(sys.argv) < 2:
        print("Uso: python soc_graficos.py <ruta_al_csv>")
        sys.exit(1)

    ruta = sys.argv[1]
    eventos = cargar_eventos(ruta)
    print(f"Cargados {len(eventos)} eventos desde {ruta}")

    grafico_por_regla(eventos)


if __name__ == "__main__":
    main()
