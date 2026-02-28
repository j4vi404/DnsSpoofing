# DnsSpoofing
# DNS-Spoofing-Attack
**Network Security Tool**
**Python**

Herramienta automatizada para demostración de ataques DNS Spoofing en entornos de laboratorio controlados

---
#Link del video: https://youtu.be/vi2Oz2m_vCQ 
---

## 📋 Tabla de Contenidos
- [Objetivo del Script](#-objetivo)
- [Características Principales](#-características-principales)
- [Capturas de Pantalla](#️-capturas-de-pantalla)
- [Topología de Red](#-topología-de-red)
- [Parámetros de Configuración](#-parámetros-de-configuración)
- [Uso y Ejemplos](#-uso-y-ejemplos)
- [Medidas de Mitigación](#️-medidas-de-mitigación)

---

## 🎯 Objetivo

El objetivo de este script es simular, en un entorno de laboratorio controlado, un ataque de **DNS Spoofing** para interceptar consultas DNS legítimas realizadas por los clientes y responder con direcciones IP falsas controladas por el atacante, redirigiendo el tráfico hacia sitios maliciosos y posicionando al atacante como **Man-in-the-Middle**, con fines exclusivamente educativos y de análisis de seguridad.

**Autor**
ALEXIS JAVIER CRUZ MINYETE

---

### Reporte de Seguridad

Durante la ejecución del laboratorio se identificó que la red evaluada carece de mecanismos básicos de protección DNS, lo que permitió la ejecución exitosa de un ataque de DNS Spoofing. La ausencia de DNSSEC, validación de respuestas DNS, monitoreo de consultas anómalas y uso de servidores DNS confiables representa un riesgo crítico para la integridad de la resolución de nombres en la red.

El impacto principal del ataque es la capacidad de redirigir a los clientes hacia sitios web falsos controlados por el atacante, permitiendo ataques de phishing, captura de credenciales, suplantación de servicios y distribución de malware. En un entorno real, este tipo de vulnerabilidad podría facilitar el acceso no autorizado a información sensible y comprometer la seguridad de todos los usuarios de la red.

La implementación de controles como DNSSEC, uso de DNS sobre HTTPS (DoH), DNS sobre TLS (DoT), monitoreo activo de consultas DNS y servidores DNS corporativos protegidos permitiría reducir considerablemente la superficie de ataque.

---

## 🖼️ Capturas de Pantalla

Las capturas incluidas en este repositorio documentan el proceso completo del laboratorio:

- Topología de red del escenario

 <img width="1778" height="825" alt="image" src="https://github.com/user-attachments/assets/1270f1c1-c477-43ad-a5bc-d35bf942e3b8" />

---
- Ejecución del ataque DnS Spoofing
  
<img width="797" height="254" alt="image" src="https://github.com/user-attachments/assets/9fd1fba7-e4c9-4108-bc30-6802697653fd" />
<img width="611" height="105" alt="image" src="https://github.com/user-attachments/assets/57631c95-005c-484d-aa43-6588926aa39b" />


---
 -Tráfico DNS interceptado
 
<img width="1051" height="870" alt="image" src="https://github.com/user-attachments/assets/400c30b3-2385-4f4f-be16-6e3c92a93205" />

---
- Redirección exitosa al sitio web falso
<img width="911" height="676" alt="image" src="https://github.com/user-attachments/assets/b5234364-7b34-4cab-8621-874c912d8ffb" />

---

## DNS Spoofing - Rogue DNS Response Attack

Script de Python que utiliza Scapy para realizar ataques de DNS Spoofing mediante la interceptación de consultas DNS legítimas y el envío de respuestas falsas que redirigen a los clientes hacia IPs controladas por el atacante antes que el servidor DNS legítimo pueda responder.

### Requisitos
```
pip install scapy
```

### Uso
```
git clone https://github.com/j4vi404/DNS-Spoofing-Attack.git
cd DNS-Spoofing
chmod +x DNS_spoofing.py
sudo python3 DNS_spoofing.py
```

### Características
- 🎯 **DNS Spoofing:** Intercepta consultas DNS y responde con IPs falsas
- 🔄 **Redirección automática:** Redirige dominios legítimos hacia IPs del atacante
- ⚡ **Respuesta rápida:** Responde antes que el servidor DNS legítimo
- ✅ **ARP Poisoning integrado:** Posiciona al atacante como MitM para interceptar tráfico DNS
- ✅ **Monitoreo en tiempo real:** Muestra cada consulta DNS interceptada
- 📊 **Logging detallado:** Registra todos los dominios resueltos falsamente
- 🔧 **Configuración simple:** Variables fáciles de modificar

---

## 🔧 Configuración

Edita las siguientes variables según tu red:

```python
interface       = "eth0"            # Interfaz de red del atacante
ip_atacante     = "15.0.7.2"    # IP del atacante (servidor DNS falso)
ip_victima      = "15.0.7.7"    # IP de la víctima
ip_gateway      = "15.0.7.1"     # IP del gateway legítimo
dominio_falso   = "itla.edu.do"       # Dominio a suplantar
ip_falsa        = "15.0.7.2"    # IP falsa a retornar en la respuesta DNS
puerto_dns      = 53                # Puerto estándar DNS
protocolo       = "UDP"             # Protocolo de transporte DNS
```

### Notas
> ⚠️ **Advertencia:** Este script requiere privilegios de root para interceptar y manipular paquetes DNS a nivel de red.

> ⚠️ **Uso responsable:** Utiliza este script únicamente en entornos de prueba autorizados y con fines educativos.

> ⚠️ **Legal:** El uso no autorizado de este script puede ser ilegal. Asegúrate de tener permiso explícito.

---

### Cómo funciona
1. **ARP Poisoning:** El atacante envenena la caché ARP de la víctima y el gateway para posicionarse como MitM
2. **Interceptación DNS:** Captura paquetes UDP en el puerto 53 dirigidos al servidor DNS legítimo
3. **Respuesta falsa:** Envía una respuesta DNS con la IP falsa controlada por el atacante antes que el servidor legítimo
4. **Redirección:** El cliente resuelve el dominio hacia la IP del atacante sin saberlo
5. **Man-in-the-Middle:** El tráfico del cliente es redirigido a sitios falsos del atacante

### Detección

Este ataque puede ser detectado mediante:
- Monitoreo de respuestas DNS con IPs inesperadas
- DNSSEC para validación de autenticidad de respuestas DNS
- Análisis de logs de consultas DNS anómalas
- IDS/IPS con reglas para detectar DNS Spoofing
- Comparación de respuestas DNS contra servidores de referencia

---

## 🌐 Topología de Red

Elementos de la red:

- **Cloud My House:** Conexión a Internet
- **Kali Linux Atacante:** Máquina atacante con servidor DNS malicioso
- **SW-Cloud:** Switch de conexión a cloud
- **SW-1:** Switch principal izquierda
- **SW-2:** Switch segmento inferior izquierdo
- **SW-3:** Switch segmento derecho
- **R-SD DNS:** Router con servidor DNS legítimo
- **USER:** Clientes víctimas 

### Tabla de Interfaces

**Kali Linux Atacante (DNS Rogue Server)**

| Interfaz | Dirección IP | Máscara | Descripción |
|----------|-------------|---------|-------------|
| e0 | 15.0.7.2 | /24 | Interfaz principal de ataque |
| e1 | Acceso Cloud | — | Conexión a Internet |

**R-SD DNS (Router con DNS Legítimo)**

| Interfaz | Dirección IP | Máscara | Descripción |
|----------|-------------|---------|-------------|
| e0/0 | IP Interna | /24 | Red interna |
| e0/1 | Conexión SW-Cloud | — | Uplink |
| e1/0 | Conexión SW-3 | — | Distribución |

**SW-1 (ARISTA - Switch Principal)**

| Interface | Tipo | Modo | Descripción |
|-----------|------|------|-------------|
| e0/0 | Ethernet | Access | Conexión Kali Atacante |
| e1/0 | Ethernet | Trunk | Uplink a Cloud |
| e0/3 | Ethernet | Access | Conexión SW-2 |

**SW-2 (ARISTA - Switch Segmento Inferior)**

| Interface | Tipo | Modo | Descripción |
|-----------|------|------|-------------|
| e0/0 | Ethernet | Trunk | Uplink SW-1 |
| e0/2 | Ethernet | Access | Usuario 1 |

**SW-3 (ARISTA - Switch Segmento Derecho)**

| Interface | Tipo | Modo | Descripción |
|-----------|------|------|-------------|
| e0/0 | Ethernet | Trunk | Uplink SW-Cloud |
| e0/2 | Ethernet | Trunk | Conexión PNET |
| e0/4 | Ethernet | Access | Usuario 2 |
| e1/0 | Ethernet | Trunk | Uplink R-SD |
| e1/1 | Ethernet | Access | Usuario 3 |
| e1/2 | Ethernet | Access | Usuario 3 (secundaria) |
| e1/3 | Ethernet | Access | Usuario 3 (terciaria) |

**SW-Cloud (Switch de Acceso Cloud)**

| Interface | Tipo | Modo | Descripción |
|-----------|------|------|-------------|
| e0/0 | Ethernet | Trunk | Downlink SW-3 |
| e0/1 | Ethernet | Trunk | Uplink Cloud My House |

**Dispositivos Finales (USERS)**

| Dispositivo | Interfaz | Configuración | Switch Conectado |
|-------------|----------|---------------|-----------------|
| User 1 | eth0 | DHCP | SW-2 (e0/2) |
| User 2 | eth0 | DHCP | SW-3 (e0/4) |
| User 3 | eth0 | DHCP | SW-3 (e1/1, e1/2, e1/3) |

---

## 📊 Parámetros Usados

### Configuración de Red

| Parámetro | Valor | Descripción |
|-----------|-------|-------------|
| Red Clientes | 15.0.7.0/24 | VLAN 20 - Segmento objetivo |
| R-SD DNS | — | VLAN 20 - Segmento administrativo |
| VLAN Nativa | 888 | VLAN para tráfico no etiquetado |

### Parámetros de Ataque

**DNS Spoofing**

| Parámetro | Valor | Descripción |
|-----------|-------|-------------|
| Interfaz | eth0 | Interfaz de red del atacante |
| IP Atacante | 15.0.7.2 | IP del servidor DNS falso |
| IP Víctima | 115.0.7.7 | IP del cliente objetivo |
| IP Gateway | 15.0.7.1 | IP del gateway legítimo |
| Dominio Falso | itla.edu.do | Dominio a suplantar |
| IP Falsa Retornada | 15.0.7.2 | IP falsa enviada en respuesta DNS |
| Puerto DNS | 53 | Puerto estándar DNS |
| Protocolo | UDP | Protocolo de transporte DNS |
| TTL Respuesta | 300 segundos | Tiempo de vida de la respuesta falsa |

### Routers

| Fabricante | Modelos Soportados | Versión OS | Estado |
|------------|-------------------|------------|--------|
| Cisco | ISR 1900/2900/4000 | IOS 15.0+ | ✅ Completo |

---

## 🛡️ Medidas de Mitigación

### Análisis de Riesgos y Controles - DNS Spoofing

| ID | Riesgo Identificado | Severidad | Probabilidad | Impacto | Medida de Mitigación Implementada |
|----|---------------------|-----------|--------------|---------|----------------------------------|
| R-001 | DNS Spoofing - Servidor DNS malicioso | CRÍTICO | Alta | Crítico | • Implementación de DNSSEC • Validación de firmas digitales en respuestas DNS • Uso de DNS sobre HTTPS (DoH) o DNS sobre TLS (DoT) • Servidores DNS corporativos protegidos |
| R-002 | Redirección a sitios falsos (Phishing) | CRÍTICO | Alta | Crítico | • DNSSEC con validación de cadena de confianza • Filtrado de URLs maliciosas • Certificados SSL/TLS en sitios críticos • Listas de bloqueo de dominios maliciosos |
| R-003 | Man-in-the-Middle (MitM) | CRÍTICO | Alta | Crítico | • Uso obligatorio de HTTPS/TLS • Implementación de VPN para tráfico sensible • DAI (Dynamic ARP Inspection) • Detección de ataques MitM con IDS/IPS |
| R-004 | Captura de credenciales | ALTO | Alta | Alto | • Autenticación multifactor (MFA) • Cifrado de credenciales en tránsito • HSTS (HTTP Strict Transport Security) • Monitoreo de intentos de autenticación anómalos |
| R-005 | Envenenamiento de caché DNS | ALTO | Alta | Alto | • Randomización de puertos DNS origen • Randomización de Transaction ID • DNS sobre HTTPS para evitar interceptación • Tiempo de vida (TTL) corto en registros críticos |
| R-006 | Acceso no autorizado a red | ALTO | Alta | Alto | • Autenticación 802.1X • NAC (Network Access Control) • Port Security con sticky MAC • Autenticación RADIUS/TACACS+ |
| R-007 | Falta de detección de ataques | ALTO | Alta | Alto | • IDS/IPS (Snort, Suricata) • SIEM para correlación de eventos • Monitoreo de logs DNS • Alertas en tiempo real de resoluciones anómalas |
| R-008 | Propagación del ataque | MEDIO | Media | Alto | • Segmentación de VLANs • ACLs entre segmentos • Private VLANs • Firewall interno |

---

### Controles Específicos - DNS Spoofing

#### 1. DNSSEC (DNS Security Extensions)
Valida la autenticidad e integridad de las respuestas DNS mediante firmas digitales

```
! Habilitar validación DNSSEC en el resolver
Router(config)# ip domain lookup
Router(config)# ip name-server 8.8.8.8
Router(config)# ip dns spoofing

! Configurar DNSSEC en servidor DNS Cisco IOS
Router(config)# ip dns server
Router(config)# ip dns primary ejemplo.com SOA ns1.ejemplo.com admin.ejemplo.com
```

#### 2 Dynamic ARP Inspection (DAI)
Previene el envenenamiento ARP utilizado para posicionarse como MitM antes del DNS Spoofing

```
SW-3(config)# ip arp inspection vlan 20
SW-3(config)# ip arp inspection validate src-mac dst-mac ip

! Puerto trust para gateway legítimo
SW-3(config)# interface Ethernet0/1
SW-3(config-if)# ip arp inspection trust
```

#### 3. Port Security
Limita direcciones MAC permitidas por puerto para evitar ataques desde dispositivos no autorizados

```
SW-3(config)# interface range Ethernet0/1-5
SW-3(config-if-range)# switchport port-security
SW-3(config-if-range)# switchport port-security maximum 2
SW-3(config-if-range)# switchport port-security violation restrict
SW-3(config-if-range)# switchport port-security mac-address sticky
```

#### 4. ACLs para Restricción de Tráfico DNS
Permite consultas DNS únicamente hacia servidores autorizados

```
! Permitir DNS solo hacia servidores autorizados
Router(config)# ip access-list extended DNS-CONTROL
Router(config-ext-nacl)# permit udp any host 15.0.7.1 eq 53
Router(config-ext-nacl)# deny udp any any eq 53
Router(config-ext-nacl)# permit ip any any

! Aplicar ACL en interfaz de clientes
Router(config)# interface Ethernet0/0
Router(config-if)# ip access-group DNS-CONTROL in
```

#### 5. Autenticación 802.1X
Control de acceso a nivel de puerto antes de permitir cualquier tráfico

```
! Habilitar AAA
SW-3(config)# aaa new-model
SW-3(config)# aaa authentication dot1x default group radius

! Configurar RADIUS
SW-3(config)# radius server RADIUS-SERVER
SW-3(config-radius-server)# address ipv4 192.168.1.10 auth-port 1812
SW-3(config-radius-server)# key SecureKey123

! Habilitar 802.1X en puertos
SW-3(config)# interface range Ethernet0/1-5
SW-3(config-if-range)# authentication port-control auto
SW-3(config-if-range)# dot1x pae authenticator
```

### Monitoreo y Detección

| Herramienta | Propósito | Implementación |
|-------------|-----------|----------------|
| Wireshark/tcpdump | Análisis de tráfico DNS | Filtro: `udp port 53` para capturar consultas DNS |
| dnsspoof detector | Detección DNS Rogue | Compara respuestas DNS contra servidores de referencia |
| Snort/Suricata | IDS/IPS | Reglas para detectar DNS Spoofing y respuestas anómalas |
| Syslog | Logging centralizado | Logs de resoluciones DNS sospechosas |
| SIEM | Correlación de eventos | Alertas de dominios resueltos con IPs inesperadas |
| Nagios/Zabbix | Monitoreo de red | Alertas de cambios en resolución DNS de dominios críticos |

### Plan de Respuesta a Incidentes

**FASE 1: DETECCIÓN**
- Sistema detecta respuestas DNS con IPs no autorizadas
- Alerta automática al equipo de seguridad
- Revisión de logs de consultas DNS anómalas
- Identificación del dispositivo que envía respuestas falsas

**FASE 2: CONTENCIÓN**
- Bloquear tráfico DNS no autorizado mediante ACLs
- Aislar segmento de red comprometido
- Preservar evidencia (capturas de tráfico DNS)
- Revisar clientes que recibieron respuestas DNS falsas

**FASE 3: ERRADICACIÓN**
- Identificar y eliminar servidor DNS malicioso
- Limpiar caché DNS en todos los clientes afectados
- Forzar renovación de resoluciones DNS en clientes
- Verificar integridad de servidores DNS legítimos

**FASE 4: RECUPERACIÓN**
- Restaurar configuración DNS correcta en clientes
- Verificar resolución correcta de dominios críticos
- Confirmar que el tráfico apunta a servidores legítimos
- Monitoreo intensivo durante 24-48 horas

**FASE 5: LECCIONES APRENDIDAS**
- Documentar el incidente completo
- Revisar efectividad de controles DNSSEC implementados
- Actualizar políticas de seguridad DNS
- Capacitación al equipo técnico

---

## ⚠️ Disclaimer de Responsabilidad

Este proyecto es exclusivamente para fines educativos y de investigación en entornos de laboratorio controlados. El uso de estas técnicas en redes sin autorización explícita es ilegal y puede resultar en consecuencias legales graves.

El autor no se hace responsable del mal uso de esta herramienta. Al utilizar este código, aceptas usar este conocimiento de manera ética y legal.

*Última actualización: Febrero 2026*
