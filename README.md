# 🚀 IPBlocker

Un kit de herramientas en Python para automatizar el aislamiento de direcciones IP comprometidas y la recolección de logs del sistema para un análisis forense inicial.

## 📖 Introducción

IPBlocker está diseñado para agilizar la respuesta a incidentes de seguridad en redes. Al aislar máquinas comprometidas y recopilar datos forenses esenciales, este kit de herramientas permite una acción rápida y una contención efectiva de amenazas dentro de una red. Ideal para administradores de sistemas y equipos de seguridad, IPBlocker garantiza una gestión eficiente de incidentes y la recopilación de datos para análisis posteriores.

## ✨ Características

- **Aislamiento de Máquinas Comprometidas**: Bloquea todo el tráfico entrante y saliente de direcciones IP comprometidas utilizando `iptables`.
- **Rango de IPs**: Gestiona y aísla rangos de direcciones IP simultáneamente.
- **Recolección de Logs**: Recopila archivos de log críticos (`syslog`, `auth.log`, `kern.log`) desde máquinas remotas utilizando SSH y SFTP.
- **Análisis Inicial**: Analiza los logs recolectados usando `pandas` para obtener una visión inmediata de los datos.
- **Registro de Actividades**: Registra todas las actividades y errores en un archivo de log para auditoría y resolución de problemas.

## 🛠️ Instalación

Asegúrate de tener Python 3.x instalado. Luego, instala las dependencias necesarias:

```bash
pip install paramiko pandas
Ejecuta el script y sigue las indicaciones en pantalla para proporcionar la información necesaria, como la IP del servidor remoto, el nombre de usuario, la contraseña y el rango de IPs comprometidas.

python isolate_ips.py

Introduce los Detalles:

IP del servidor remoto
Nombre de usuario
Contraseña (la entrada se oculta por seguridad)
IP de inicio del rango comprometido
IP de fin del rango comprometido


🌟 Ejemplo


$ python isolate_ips.py
Introduce la IP del servidor remoto: 192.168.1.101
Introduce el nombre de usuario: admin
Introduce la contraseña:
Introduce la IP de inicio: 192.168.1.100
Introduce la IP de fin: 192.168.1.110

Máquina con IP 192.168.1.100 ha sido aislada.
Máquina con IP 192.168.1.101 ha sido aislada.
...
Logs recolectados y analizados con éxito.


## Uso del Script de Desbloqueo
python unblock_ips.py


🤝 Contribuir
¡Acepto contribuciones! Por favor, haz un fork del repositorio y envía un pull request.

Haz un fork del repositorio
Crea una nueva rama (git checkout -b feature-branch)
Realiza tus cambios
Haz commit de tus cambios (git commit -am 'Añadir nueva característica')
Haz push a la rama (git push origin feature-branch)
Crea un nuevo Pull Request


