# Guía de ejecución — SOC Detection Lab (Wazuh 4.14)

Procedimiento reproducible paso a paso. Comandos verificados contra la documentación
oficial de Wazuh. Ejecuta cada fase en orden y captura las evidencias indicadas.

> Convención de evidencias: guarda cada captura con el nombre exacto que se indica,
> en la carpeta `evidence/faseN-.../`. Así el README y las evidencias quedan alineados.

---

## Fase 0 — Preparación del entorno (VirtualBox)

1. Crea una **red interna** llamada `intnet-soc` (no NAT, sin acceso a Internet entre VMs).
2. Crea las 3 VMs con el adaptador conectado a `intnet-soc`:
   - `WAZUH-SRV` — Ubuntu Server 22.04 — 4 GB RAM — 2 vCPU
   - `TARGET` — Ubuntu Server 22.04 — 2 GB RAM — 1 vCPU
   - `KALI` — Kali Linux — 2 GB RAM — 2 vCPU
3. Asigna IP estática a cada una (ver Fase 1, paso 1).

> La instalación de Wazuh (Fase 1) necesita Internet para descargar paquetes. Opciones:
> hacer la instalación con un adaptador NAT temporal y luego dejar solo `intnet-soc`, o
> añadir un segundo adaptador NAT solo durante la instalación. El ataque (Fase 3) se
> hace ya en la red interna aislada.

---

## Fase 1 — Despliegue de Wazuh (en WAZUH-SRV)

**1. IP estática** (ejemplo con netplan; ajusta el nombre de la interfaz con `ip a`):

```yaml
# /etc/netplan/00-installer-config.yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: no
      addresses: [10.10.10.10/24]
```
```bash
sudo netplan apply
ip a                       # verifica 10.10.10.10
```

**2. Instalación all-in-one** (Manager + Indexer + Dashboard):

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

Al terminar, el instalador muestra la contraseña del usuario `admin`. **Guárdala.**
También puedes recuperarla con:

```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

**3. Verificación de servicios:**

```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
```

**4. Acceso al dashboard:** desde el navegador → `https://10.10.10.10` (usuario `admin`).

> 📸 Evidencias Fase 1 → `evidence/fase1-despliegue/`
> - `f1-01-install-ok.png` — final de la instalación con el usuario/clave.
> - `f1-02-servicios-active.png` — salida de `systemctl status` (3 servicios *active*).
> - `f1-03-dashboard-login.png` — pantalla de login del dashboard.
> - `f1-04-dashboard-home.png` — dashboard ya dentro.

---

## Fase 2 — Instalación del agente (en TARGET)

**1. IP estática** → `10.10.10.20/24` (mismo método que Fase 1).

**2. Instalar servicios a monitorizar:**

```bash
sudo apt update
sudo apt install -y openssh-server apache2
sudo systemctl enable --now ssh apache2
```

**3. Añadir el repositorio de Wazuh e instalar el agente** (comandos oficiales):

```bash
sudo apt-get install gnupg apt-transport-https curl
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
sudo WAZUH_MANAGER="10.10.10.10" apt-get install -y wazuh-agent
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

**4. Aplicar el FIM en tiempo real:** edita `/var/ossec/etc/ossec.conf` con el bloque
`<syscheck>` de [`configs/agent-fim-syscheck.conf`](../configs/agent-fim-syscheck.conf)
y reinicia:

```bash
sudo systemctl restart wazuh-agent
```

**5. Verificar** en el dashboard → *Agents*: `TARGET` debe aparecer como **Active**.

> 📸 Evidencias Fase 2 → `evidence/fase2-agente/`
> - `f2-01-agent-service-active.png` — `systemctl status wazuh-agent`.
> - `f2-02-dashboard-agent-active.png` — agente *Active* en el dashboard.

---

## Fase 3 — Simulación de ataques (desde KALI → TARGET)

IP de KALI: `10.10.10.55/24`. Confirma conectividad: `ping 10.10.10.20`.

### 3.1 Fuerza bruta SSH (Hydra) — T1110.001

```bash
# En KALI: crea una lista de contraseñas de prueba
printf '123456\npassword\nadmin\nroot\ntoor\nqwerty\nletmein\nubuntu\n12345678\nabc123\n' > passlist.txt

# Ataque contra el usuario del TARGET (ajusta <usuario>)
sudo hydra -t 4 -l <usuario> -P passlist.txt 10.10.10.20 ssh
```

En el dashboard salta la regla **5763** (*SSHD brute force trying to get access to the system*).

> 📸 `evidence/fase3-deteccion/f3-01-hydra-kali.png` — Hydra en ejecución.
> 📸 `evidence/fase3-deteccion/f3-02-alerta-5763-ssh.png` — alerta 5763 en el dashboard.

### 3.2 Reconocimiento de red (Nmap) — T1046

```bash
# En KALI
nmap -sS 10.10.10.20                 # escaneo SYN de puertos
nmap -A 10.10.10.20                  # detección de servicios y versiones
```

> ⚠️ **Nota honesta sobre la detección del escaneo.** Wazuh **no detecta de forma
> nativa y fiable** un escaneo Nmap entrante solo con el agente: no hay una regla
> "de serie" robusta para esto. Para evidenciarlo de verdad tienes dos vías, ambas
> propuestas de mejora reales (no las des por hechas sin configurarlas):
> 1. **Logging de firewall:** habilitar reglas `iptables -j LOG` en TARGET y recoger
>    `/var/log/kern.log` con un `<localfile>` en el agente. Wazuh levantará alertas
>    por las conexiones registradas.
> 2. **IDS Suricata** integrado con Wazuh (mejora de la fase siguiente del ciclo).
>
> Si no configuras ninguna, documenta el Nmap como **fase de reconocimiento del
> atacante** (contexto del incidente), no como una alerta de Wazuh.

> 📸 `evidence/fase3-deteccion/f3-03-nmap-kali.png` — salida del escaneo en KALI.

### 3.3 Persistencia monitorizada por FIM (en TARGET) — T1136.001 / T1098 / T1053.003

Simula las acciones post-explotación que el FIM debe detectar. Ejecútalas **en TARGET**
(como si el atacante ya tuviera acceso):

```bash
# Alta de usuario local no autorizado  -> /etc/passwd  (T1136.001)
sudo useradd -m -s /bin/bash attacker

# Manipulación de la config SSH  -> /etc/ssh/sshd_config  (T1098)
echo "PermitRootLogin yes" | sudo tee -a /etc/ssh/sshd_config

# Persistencia vía cron  -> /etc/cron.d/  (T1053.003)
echo '* * * * * root /bin/bash -c "id > /tmp/persist.log"' | sudo tee /etc/cron.d/persistence_test
```

En el dashboard verás alertas FIM: regla **550** (fichero modificado) para `/etc/passwd`
y `sshd_config`, y regla **554** (fichero añadido) para el cron. Con `report_changes`
se muestra la línea exacta añadida a `/etc/passwd`.

> 📸 `evidence/fase3-deteccion/f3-04-fim-passwd.png` — alerta FIM del alta de usuario.
> 📸 `evidence/fase3-deteccion/f3-05-fim-sshd-cron.png` — alertas FIM de sshd_config y cron.

---

## Fase 4 — Análisis y respuesta SOC

### 4.1 Configurar la respuesta activa (en WAZUH-SRV)

Aplica el bloque de [`configs/manager-active-response.conf`](../configs/manager-active-response.conf)
en `/var/ossec/etc/ossec.conf` y reinicia el manager:

```bash
sudo systemctl restart wazuh-manager
```

### 4.2 Verificar el bloqueo automático

Repite el ataque Hydra (3.1) desde KALI. En menos de 3 minutos, comprueba que KALI
queda bloqueada:

```bash
# En KALI, tras el ataque
ping 10.10.10.20          # debe empezar a fallar (100% packet loss)
```

En el dashboard aparece la alerta de regla **651** (*Host Blocked by firewall-drop*).
Log en TARGET: `/var/ossec/logs/active-responses.log`.

> 📸 `evidence/fase4-analisis-respuesta/f4-01-alerta-651-bloqueo.png`
> 📸 `evidence/fase4-analisis-respuesta/f4-02-ping-bloqueado.png`

### 4.3 Triaje, timeline e informe

1. En el dashboard, filtra las alertas del incidente por agente y por rango de tiempo.
2. Construye el **timeline**: reconocimiento → fuerza bruta → acceso → creación de
   cuenta → persistencia → respuesta/bloqueo.
3. Revisa el mapeo **MITRE ATT&CK** del dashboard (módulo *MITRE ATT&CK*).
4. Redacta el **informe de incidente** (plantilla abajo) y guárdalo en
   `evidence/fase4-analisis-respuesta/informe-incidente.md`.

> 📸 `evidence/fase4-analisis-respuesta/f4-03-mitre-dashboard.png` — vista MITRE.
> 📸 `evidence/fase4-analisis-respuesta/f4-04-timeline.png` — timeline de alertas.

#### Plantilla mínima del informe de incidente

```
# Informe de incidente — Fuerza bruta SSH y persistencia
- Fecha / hora (UTC+2):
- Activo afectado: TARGET (10.10.10.20)
- Origen: 10.10.10.55 (KALI)
- Resumen ejecutivo:
- Cronología (timeline):
- Técnicas MITRE observadas: T1110.001, T1046, T1136.001, T1098, T1053.003
- Detección: reglas Wazuh 5763, 550, 554, 651
- Respuesta: firewall-drop (bloqueo 180 s) + acciones manuales
- Remediación aplicada:
- Lecciones aprendidas:
```

---

## Checklist final antes del push de evidencias

- [ ] Todas las capturas renombradas según esta guía y ubicadas en su `evidence/faseN/`.
- [ ] `informe-incidente.md` redactado.
- [ ] Sección 6 (Hallazgos) y 9 (Lecciones aprendidas) del README completadas.
- [ ] Sin credenciales ni `wazuh-passwords.txt` en el repo (lo cubre `.gitignore`).
