# Día 2 — Montaje del objetivo vulnerable

**Fecha:** 2026-07-04 / 2026-07-05
**Fase:** 2 — Detección y triage

## Objetivo

Montar una página de WordPress con un plugin vulnerable que permita ejecutar un ataque de webshell y RCE, con la finalidad de detectar y analizar el incidente mediante el SIEM de Wazuh en el Día 3.

## Entorno

- Wazuh 4.14.6 (Docker single-node: indexer + manager + dashboard).
- Agentes: `Ubuntu-Victim` (Ubuntu 25.10) — Active, `MacBook-M1` (macOS) — Active.
- Módulo usado: N/A (día de montaje, sin análisis en SIEM).
- Objetivo montado: WordPress 6.x + Front End Users 3.2.32 (CVE-2025-2005) sobre LAMP (Apache + MariaDB 11.8 + PHP 8.4) en Ubuntu-Victim (`192.168.1.96`).

## Vulnerabilidad objetivo

| Campo | Detalle |
|---|---|
| CVE | CVE-2025-2005 |
| Plugin | Front End Users ≤ 3.2.32 |
| Tipo | Arbitrary File Upload → RCE |
| CVSS | 10 (Crítico) |
| Autenticación requerida | Ninguna (unauthenticated) |
| Vector | Campo de subida de archivos sin validación de tipo en el formulario de registro público |
| Directorio de subida | `wp-content/uploads/ewd_feup_uploads/` |

## Ejecución (montaje del escenario)

Se instaló y configuró el stack LAMP (Apache, MariaDB 11.8, PHP 8.4) para alojar WordPress. Se instaló el plugin Front End Users 3.2.32 con un campo personalizado de tipo File (slug: `documento`) como vector de ataque. Se configuró el agente de Wazuh para ingerir los logs de Apache (`access.log` y `error.log`) y se habilitó el FIM en tiempo real sobre `/var/www/html` para detectar la creación de webshells.

**Datos clave del objetivo (para el Día 3):**

| Dato | Valor |
|---|---|
| URL del formulario vulnerable | `http://192.168.1.96/index.php/registro/` |
| Slug del campo de subida | `documento` |
| Directorio de webshell | `/var/www/html/wp-content/uploads/ewd_feup_uploads/` |
| Admin WordPress | `marco_admin` |

## Visibilidad configurada en Wazuh

Dos fuentes de detección activas para el Día 3:

- **Logs de Apache:** `access.log` y `error.log` monitoreados por `wazuh-logcollector`. Detectará el POST de subida del webshell y el GET de ejecución.
- **FIM en tiempo real:** `wazuh-syscheckd` con `realtime="yes"` sobre `/var/www/html`. Detectará la creación del archivo `.php` malicioso en el instante en que sea subido.

Verificado en el log del agente:
```
wazuh-syscheckd: INFO: (6012): Real-time file integrity monitoring started.
```

## Notas

- Las salts generadas aleatoriamente para la codificación de sesiones de WordPress se corrompieron al insertarse vía shell (los caracteres especiales fueron interpretados por bash). Esto impidió el acceso al portal. Se diagnosticó mediante el `error.log` de Apache (`Undefined array key` en `pluggable.php`) y se resolvió insertando las salts directamente desde archivo con `sed ... r`, evitando la interpretación del shell.
- El backdoor `lowpriv ALL=(ALL) NOPASSWD: ALL` reaparece en `/etc/sudoers` en cada sesión — confirmando un mecanismo de persistencia activo en Ubuntu-Victim. Pendiente de investigar con Wazuh en día dedicado.

## Lecciones

1. El onboarding a Wazuh contiene varias capas de telemetría: la del dispositivo (equivalente a Defender for Endpoint — logs del SO, procesos, FIM, SCA) y la de aplicaciones (equivalente a Defender for Cloud Apps — logs de Apache, accesos web). Entender esa separación es clave para saber dónde buscar según el tipo de incidente.
2. Las aplicaciones vulnerables son uno de los vectores de entrada principales en ataques a servidores. Un plugin desactualizado con un CVE conocido puede comprometer toda la infraestructura independientemente de cuán bien esté configurado el sistema operativo.
