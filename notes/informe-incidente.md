# Informe de Incidente de Seguridad — Fuerza bruta SSH y persistencia

> **Documento de laboratorio.** Caso reproducido en un entorno virtualizado y aislado
> con fines de formación y validación de controles de detección y respuesta (SOC).
> Las técnicas ofensivas se ejecutaron contra sistemas propios y bajo control. La
> estructura de este informe sigue el flujo de un informe SOC real y puede reutilizarse
> como plantilla.

---

## 1. Resumen ejecutivo

El 2026-10-25, el SIEM del laboratorio (Wazuh 4.14) detectó un ataque de **fuerza
bruta por SSH** contra un endpoint monitorizado, originado desde un host no autorizado
de la red interna. El motor de **respuesta activa** bloqueó automáticamente la dirección
de origen en el cortafuegos del endpoint en **0,14 segundos** desde la detección,
conteniendo el ataque sin intervención humana. En la fase de post-explotación se
simularon y detectaron tres técnicas de **persistencia** (alta de cuenta local,
manipulación de la configuración SSH y tarea cron), registradas en tiempo real por el
módulo de integridad de ficheros (FIM).

**Veredicto:** ataque detectado y contenido. No hubo acceso válido (ninguna credencial
adivinada). Los artefactos de persistencia se introdujeron como simulación controlada
y fueron detectados y revertidos.

| Campo | Valor |
|-------|-------|
| Fecha / hora (UTC+2) | 2026-10-25, 22:06 – 23:16 |
| Clasificación | Intento de acceso no autorizado + persistencia (simulada) |
| Severidad | Alta |
| Estado | Contenido y documentado |
| Activo afectado | `debian-wordpress` (10.10.10.20) |
| Origen del ataque | `kali` (10.10.10.55) |
| Analista | Bryan Calderón Herrera (REDNIX) |

---

## 2. Alcance y entorno

| Rol | Host | IP | Sistema |
|-----|------|----|---------|
| SIEM | `wazuh-server` | 10.10.10.10 | Wazuh 4.14 all-in-one (OVA, Amazon Linux 2023) |
| Víctima | `debian-wordpress` (agente 001) | 10.10.10.20 | Debian GNU/Linux 13 + SSH + WordPress |
| Atacante | `kali` | 10.10.10.55 | Kali Linux |

Red interna aislada de VirtualBox (`LabNetwork`, 10.10.10.0/24), sin salida a otras redes.

---

## 3. Cronología del incidente (timeline)

| Hora (UTC+2) | Fase | Evento | Detección (regla) |
|--------------|------|--------|-------------------|
| 22:06 | Persistencia | Alta de cuenta local `soc_test_user` → cambio en `/etc/passwd` y `/etc/passwd-` | FIM 550 |
| 22:06 | Persistencia | Modificación de `/etc/ssh/sshd_config` | FIM 550 |
| 22:06 | Persistencia | Tarea cron nueva en `/etc/cron.d/soc_test_cron` | FIM 554 |
| 23:12:45 | Acceso | Fuerza bruta SSH (Hydra, 11 intentos, usuario `cbry`) | sshd 5760 → correlación **5763** (nivel 10) |
| 23:12:45 | Respuesta | `firewall-drop` bloquea 10.10.10.55 vía iptables (180 s) | **651** |
| 23:15:46 | Respuesta | Expiración del bloqueo: comando `delete` automático | `active-responses.log` |

> Nota sobre husos horarios: los logs del endpoint se registran en **UTC**; el
> dashboard muestra la hora local (UTC+2). El mismo evento aparece, p. ej., como
> 21:12 en `full_log` y 23:12 en el `timestamp` del dashboard.

---

## 4. Análisis técnico

### 4.1 Fuerza bruta SSH (T1110.001)

El ataque generó una ráfaga de eventos `sshd: authentication failed` (regla 5760,
nivel 5). Al acumularse 8 fallos del mismo origen en la ventana de correlación, Wazuh
elevó el caso a la regla **5763 — "SSHD brute force trying to get access to the
system"** (nivel 10). Evidencia del motor de respuesta (`active-responses.log`):

```
"rule":{"level":10,"description":"sshd: brute force trying to get access to the system.",
"id":"5763","mitre":{"id":["T1110"],"tactic":["Credential Access"],"technique":["Brute Force"]},
"frequency":8,...}
"data":{"srcip":"10.10.10.55","srcport":"43558","dstuser":"cbry"}
"full_log":"... Failed password for cbry from 10.10.10.55 port 43558 ssh2"
```

Ninguno de los 11 intentos acertó la contraseña (`0 valid password found`), por lo que
**no hubo compromiso de la cuenta**.

### 4.2 Respuesta activa (contención automática)

La regla 5763 desencadenó el comando `firewall-drop` (iptables) en el endpoint, que
generó la regla **651 — "Host Blocked by firewall-drop Active Response"**. Latencia
detección→respuesta: **0,14 s** (5763 a las 23:12:45.573; 651 a las 23:12:45.716). El
bloqueo se mantuvo 180 s y se retiró automáticamente (comando `delete`), comportamiento
esperado de una respuesta activa *stateful*.

### 4.3 Persistencia (post-explotación)

Se simularon tres técnicas habituales de persistencia en Linux, todas detectadas por FIM
en tiempo real:

| Acción | Fichero | Regla | MITRE |
|--------|---------|-------|-------|
| Alta de usuario | `/etc/passwd` (+ `/etc/passwd-`) | 550 | T1136.001 |
| Modificar config SSH | `/etc/ssh/sshd_config` | 550 | T1098 |
| Tarea programada | `/etc/cron.d/soc_test_cron` | 554 | T1053.003 |

El alta de usuario tocó también `/etc/passwd-` (respaldo automático del sistema), señal
inequívoca de un `useradd` real frente a una edición manual de una sola línea.

---

## 5. Mapeo MITRE ATT&CK

| Táctica | Técnica | ID | Evidencia |
|---------|---------|----|-----------|
| Credential Access | Brute Force: Password Guessing | T1110.001 | Reglas 5760, 5763 |
| Persistence | Create Account: Local Account | T1136.001 | FIM `/etc/passwd` |
| Persistence | Account Manipulation | T1098 | FIM `sshd_config` |
| Persistence | Scheduled Task/Job: Cron | T1053.003 | FIM `/etc/cron.d` |

---

## 6. Impacto

- **Confidencialidad:** sin impacto. No se obtuvo acceso válido.
- **Integridad:** artefactos de persistencia introducidos de forma controlada y
  revertidos. En un escenario real, el alta de `soc_test_user` y la línea
  `PermitRootLogin yes` habrían supuesto una vía de acceso persistente de severidad alta.
- **Disponibilidad:** sin impacto sobre el servicio.

---

## 7. Acciones de contención y erradicación

| Acción | Tipo | Estado |
|--------|------|--------|
| Bloqueo de la IP de origen (iptables, 180 s) | Automática (`firewall-drop`) | ✅ Ejecutada |
| Eliminación de `soc_test_user` (`userdel -r`) | Manual | ✅ Ejecutada |
| Reversión de `/etc/ssh/sshd_config` | Manual | ✅ Ejecutada |
| Eliminación de `/etc/cron.d/soc_test_cron` | Manual | ✅ Ejecutada |

---

## 8. Recomendaciones (remediación)

| # | Acción | Prioridad | Plazo |
|---|--------|-----------|-------|
| 1 | Deshabilitar el login SSH por contraseña; usar solo clave pública | Alta | Inmediato |
| 2 | Mantener `firewall-drop` o `fail2ban` como control permanente anti-fuerza bruta | Alta | 24 h |
| 3 | Restringir SSH por ACL/firewall a orígenes autorizados | Media | 72 h |
| 4 | Auditar periódicamente `/etc/passwd`, `sudoers` y `/etc/cron.*` | Alta | Semanal |
| 5 | Mantener FIM en tiempo real sobre ficheros críticos y revisar su ruido | Media | Continuo |
| 6 | Integrar un IDS de red (Suricata) para detectar reconocimiento (Nmap) | Baja | Backlog |

---

## 9. Lecciones aprendidas (para otros analistas)

- **Detectar no basta: hay que responder.** El valor del caso no está en ver el ataque,
  sino en contenerlo automáticamente. La respuesta activa es lo que diferencia un
  visor de logs de un SOC.
- **Un SIEM sin disco falla en silencio.** Durante el montaje, el servidor se quedó sin
  espacio (25 GB al 100 %): el agente seguía *Active* y el manager generaba alertas,
  pero Filebeat no podía entregarlas al indexer (`no space left on device`) y el
  dashboard dejaba de actualizarse. Diagnóstico por la cadena agente → manager →
  Filebeat → indexer. Se resolvió ampliando el disco a 50 GB. Dimensionar el disco
  (≥50 GB) es un requisito, no un extra.
- **"Misma IP" no es "misma red".** Un error de diseño hizo que el rango 10.10.10.0/24
  estuviera repartido entre un adaptador puente y la red interna; dos segmentos L2
  distintos. El síntoma fue `Destination Host Unreachable` (fallo de ARP). Un lab de
  portafolio debe usar una red interna aislada con IP fija para ser reproducible.
- **El FIM por defecto no es en tiempo real** (escanea cada 12 h). Sin `realtime="yes"`,
  un fichero creado y borrado entre escaneos no deja rastro.
- **Correlación frente a evento simple.** Un intento SSH deja rastro en varias fuentes
  (sshd, PAM, syslog). La regla de fuerza bruta (5763) solo salta al correlacionar
  ~8 fallos del mismo origen; pocos intentos se quedan en alertas sueltas.

---

## 10. Reproducibilidad

El laboratorio completo (topología, configuraciones de `ossec.conf`, guía de ejecución
paso a paso y evidencias) está documentado en este repositorio. Cualquier analista puede
reconstruir el escenario y validar los mismos controles de detección y respuesta.

**Autor:** Bryan Calderón Herrera — REDNIX · https://github.com/cbry-96 · https://linkedin.com/in/bcalderonh
