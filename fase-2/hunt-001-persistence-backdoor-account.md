# Hunt-001 — Persistencia vía Cuenta Backdoor Local

**Threat Hunting Report · Ancla Lab SOC**

| Campo | Valor |
|---|---|
| **Hunt ID** | HUNT-001 |
| **Analista** | Marco Antonio Esperón Pintos |
| **Fecha del hunt** | 12 julio 2026 |
| **Entorno** | Lab SOC — Wazuh 4.14.6 (Docker) |
| **Host objetivo** | Ubuntu-Victim · `192.168.1.96` · Ubuntu 25.10 · agent.id `001` |
| **Ventana analizada** | 3 – 12 julio 2026 (Last 30 days) |
| **Tipo de hunt** | Hypothesis-driven (proactivo) |
| **Veredicto** | ✅ **Hipótesis CONFIRMADA** — persistencia activa detectada |
| **MITRE ATT&CK** | T1136.001, T1078, T1548.003, T1562.001 (sospecha) |

---

## Resumen ejecutivo

Se ejecutó una cacería proactiva basada en hipótesis para verificar si un adversario, tras comprometer el servidor web del host `Ubuntu-Victim`, había establecido persistencia mediante la creación de una cuenta local.

La cacería **confirmó la hipótesis**: existe una cuenta local llamada `backdoor` (UID 1002), con shell interactivo `/bin/bash` y directorio home propio, creada el **8 de julio 2026 a las 05:55 UTC** — dentro de la ventana de actividad de ataque conocida. La cuenta fue creada de forma no interactiva (`from=none`), consistente con ejecución desde un webshell.

Adicionalmente, la cacería reveló:
- Una modificación a `/etc/sudoers` (posible mecanismo de escalada de privilegios asociado a la cuenta).
- Un **gap de detección** relevante: el módulo FIM, en su configuración por defecto (`scheduled`), no registró la modificación de los archivos de cuentas, dejando la detección de creación rápida de usuarios dependiente de una sola fuente confiable.

El host figuraba como `disconnected` desde el 8 de julio a las 11:31 UTC — aproximadamente 12 horas después de la creación del backdoor.

---

## Paso 1 — Hipótesis

> *Si el atacante buscó persistencia tras comprometer el servidor web, entonces creó una **cuenta local nueva** en Ubuntu-Victim — posiblemente con UID 0 para tener privilegios equivalentes a root — dejando evidencia en los archivos de cuentas del sistema y en los logs de autenticación.*

**Propiedades de la hipótesis:** específica (apunta a un comportamiento concreto), testeable (verificable con la telemetría disponible) y anclada a MITRE ATT&CK **T1136.001 — Create Account: Local Account** (relacionada con T1078 — Valid Accounts).

**Refinamiento posterior:** la evidencia mostró UID **1002**, no 0. La cuenta no es root por sí misma; su privilegio (de existir) proviene de otra vía — hilo que condujo al hallazgo secundario en `/etc/sudoers`. Una hipótesis que se ajusta con la evidencia no es un fallo; es el método funcionando.

---

## Paso 2 — Fuentes de datos

Un usuario nuevo en Linux deja huella en dos categorías, cada una recolectada por un módulo distinto de Wazuh:

| Categoría | Artefacto | Módulo Wazuh | Estado |
|---|---|---|---|
| Archivos de estado | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` | FIM / Syscheck | Verificado (parcial) |
| Logs de eventos | `/var/log/auth.log` | Log Collection | Verificado (dio resultado) |
| Ejecución de comandos | syscall `execve` (quién ejecutó `useradd`) | auditd (avanzado) | No disponible — evolución futura |

**Nota:** dado que `Ubuntu-Victim` estaba `disconnected`, no se pudo validar la configuración del agente por interfaz (`Agent is not active`). La cacería se realizó sobre datos históricos ya indexados, cubriendo la ventana del ataque (3–8 julio).

---

## Paso 3 — Lógica de cacería (queries)

Universo inicial: **3,045 eventos** en 30 días (ya filtrados a `agent.id: 001`).
Contexto de autenticación: **0 fallos** / **113 accesos exitosos** — el acceso fue limpio, no por fuerza bruta, consistente con webshell + credenciales válidas.

### Vía A — la acción (`auth.log` → reglas `adduser`)

```
rule.groups: adduser
```
→ **2 hits.** Un valor bajo es esperado y deseable: crear cuentas es un evento raro en un servidor. De 3,045 a 2 mediante hipótesis.

### Vía B — el cambio de estado (FIM sobre `/etc/passwd`)

```
rule.groups: syscheck AND syscheck.path: "/etc/passwd"
```
→ **0 hits.** No es un fallo: es un hallazgo (ver Paso 4).

Query de validación (¿FIM está vivo?):
```
rule.groups: syscheck
```
→ **53 hits.** FIM funciona.

Query ampliada (comodín sobre `/etc/`):
```
rule.groups: syscheck AND syscheck.path: /etc/*
```
→ **4 hits.**

---

## Paso 4 — Filtrado de ruido y evidencia

### Hallazgo primario — cuenta backdoor (vía A)

**Evento 1 — creación de usuario**
```
Jul 08 05:55:39 Ubuntu-Victim useradd[12521]: new user:
name=backdoor, UID=1002, GID=1002, home=/home/backdoor,
shell=/bin/bash, from=none
```
- `rule.description`: New user added to the system · `rule.level`: 8
- `data.dstuser`: **backdoor**

**Evento 2 — creación de grupo (efecto colateral)**
```
Jul 08 05:55:39 Ubuntu-Victim useradd[12521]: new group:
name=backdoor, GID=1002
```
- **Mismo PID (12521)** y **mismo segundo** → una sola ejecución de `useradd` generó ambos eventos.

**Indicadores de compromiso (análisis):**
- `shell=/bin/bash` → cuenta diseñada para **acceso interactivo humano** (una cuenta de servicio legítima usaría `/usr/sbin/nologin` o `/bin/false`). **Bandera roja principal.**
- `home=/home/backdoor` → directorio propio, refuerza intención de acceso interactivo.
- `from=none` → sin tty de origen, consistente con ejecución desde webshell (`www-data` sin terminal).
- `UID=1002` → usuario normal, no root. Privilegio proveniente de otra vía (ver hallazgo secundario).

> **Nota de campo:** en un ataque real el nombre `backdoor` sería obvio en exceso; un adversario usaría algo mimético (`svc-backup`, `support`). La detección no debe basarse en el nombre, sino en el **comportamiento**: cuenta nueva + shell interactivo + creada durante actividad sospechosa.

### Hallazgo secundario — modificación de `/etc/sudoers` (vía B)

Clasificación de los 4 eventos FIM en `/etc/`:

| Archivo | Timestamp (local) | Veredicto |
|---|---|---|
| `/etc/sudoers` | Jul 5 21:53 | 🔴 **Relevante** — control de privilegios root |
| `/etc/cups/subscriptions.conf` | Jul 5 21:53 | ⚪ Ruido — servicio de impresión CUPS |
| `/etc/cups/subscriptions.conf.O` | Jul 5 21:53 | ⚪ Ruido — variante temporal de CUPS |
| `/etc/ld.so.cache` | Jul 5 21:53 | ⚪ Ruido — regenerado por `ldconfig` (gestión de paquetes) |

La modificación de `/etc/sudoers` (~2 días antes de la creación del usuario) es el probable mecanismo que otorga privilegios elevados a una cuenta que por UID no es root. Se mapea a **T1548.003 — Sudo and Sudo Caching**.

### Hallazgo por ausencia — gap de detección FIM

Los 4 eventos FIM son del **5 de julio ~21:53 local**. **No existe ningún evento FIM en `/etc/` a la hora de creación del backdoor** (8 julio 05:55 UTC), pese a que `/etc/passwd`, `/etc/shadow` y `/etc/group` necesariamente cambiaron en ese instante.

**Interpretación:** FIM está vivo (53 eventos) y detecta modificaciones in-place (detectó `sudoers`), pero por defecto opera en modo `scheduled` (escaneo periódico), no `realtime`, sobre `/etc`. La ventana entre la creación del backdoor (05:55 UTC) y el silenciamiento del agente (11:31 UTC) fue más corta que el intervalo de escaneo → el cambio ocurrió pero nunca se reportó.

---

## Línea de tiempo

> Los logs del host están en **UTC**; el dashboard renderiza en local **UTC-6 (Puebla)**. Ejemplo: `05:55 UTC` = `23:55 local` del día anterior. La confirmación de zona horaria es indispensable para no romper la correlación temporal.

| Fecha/hora (UTC) | Evento |
|---|---|
| Jul 3, 20:26 | Registro del agente Ubuntu-Victim |
| Jul 6, ~03:53 | Modificación de `/etc/sudoers` (escalada de privilegios) |
| **Jul 8, 05:55** | **Creación de la cuenta `backdoor` (UID 1002, `/bin/bash`)** |
| Jul 8, 11:31 | Último keep-alive — el agente pasa a `disconnected` |

La secuencia sugiere: preparación de privilegios → creación de persistencia → silenciamiento del monitoreo ~12 h después (posible **T1562.001 — Impair Defenses**, no confirmado).

---

## Paso 5 — Respuesta y mejora

### A) Respuesta (ciclo NIST IR)

1. **Contener** — aislar el host de la red (network isolation) **sin apagarlo**, para preservar evidencia volátil (procesos, conexiones, sesiones activas).
2. **Preservar** — capturar estado: procesos en ejecución, conexiones abiertas de la cuenta `backdoor`, sesiones activas.
3. **Erradicar** — deshabilitar/eliminar la cuenta `backdoor` **y revertir la modificación de `/etc/sudoers`** (eliminar solo el usuario dejaría abierta la segunda vía).
4. **Recuperar** — identificar y parchar el vector de entrada (explotación de WordPress, CVE-2025-2005) para cerrar la raíz; sin esto, el atacante recrea la persistencia.
5. **Notificar** — escalar a CISO / compliance / legal. En entorno bancario, la comunicación a stakeholders arranca temprano y en paralelo, no al final.

### B) Mejora de detección (por capas)

El problema **no fue la herramienta**: Wazuh detectó la creación del usuario (regla `adduser`, nivel 8). La causa raíz fue de **configuración**. Migrar de herramienta sin corregir la causa reproduce el gap en una plataforma más cara.

1. **Configuración** — cambiar FIM a modo `realtime` para `/etc`, cerrando el gap dentro de Wazuh sin costo adicional.
2. **Detección afinada** — elevar la severidad de la regla `adduser`, o crear una regla derivada que dispare **crítico** cuando una cuenta nueva tenga shell interactivo (`/bin/bash`) — señal fuerte de intención de acceso humano.
3. **Correlación (avanzado)** — regla que dispare cuando `useradd` sea ejecutado por un proceso hijo de `www-data`, uniendo "servidor web comprometido" + "cuenta creada" en una alerta única de alta confianza. Requiere telemetría de ejecución (auditd/execve).

> Herramientas como Microsoft Sentinel o Splunk aportan valor real en **escala** (miles de endpoints), **correlación multi-fuente** y **retención larga** — como evolución con propósito, no como sustituto de corregir una configuración.

---

## Mapeo MITRE ATT&CK

| Técnica | ID | Evidencia en este hunt |
|---|---|---|
| Create Account: Local Account | T1136.001 | Cuenta `backdoor` creada vía `useradd` |
| Valid Accounts | T1078 | Cuenta local reutilizable para acceso persistente |
| Sudo and Sudo Caching | T1548.003 | Modificación de `/etc/sudoers` |
| Impair Defenses: Disable/Modify Tools | T1562.001 | Sospecha — agente silenciado ~12 h después (no confirmado) |
| Server Software Component: Web Shell | T1505.003 | Contexto del vector de entrada (`from=none`) |

---

## Conclusión

Primer ciclo de threat hunting ejecutado de punta a punta sobre el framework de 5 pasos. La hipótesis fue confirmada mediante una cadena de evidencia coherente y autosostenida: evento directo de creación, corroboración por PID/timestamp, contexto de acceso compatible y coherencia temporal con la ventana de ataque.

El valor del hunt no se limita al hallazgo: se identificó un **gap de detección accionable** (FIM `scheduled` no confiable para creación rápida de cuentas) y se propusieron mejoras concretas de configuración, detección y correlación. Esa es la transición de "encontré algo" a "mejoré la postura defensiva" — el objetivo real del threat hunting.

**Estado del hunt:** ✅ Cerrado · Hipótesis confirmada · Mejoras propuestas.
