import paramiko
import getpass
import logging
from ipaddress import ip_address, IPv4Address
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
import os
#autor Ltomxd
# Configurar el logging
logging.basicConfig(filename='incident_response.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def validate_ip(ip: str) -> bool:
    try:
        return isinstance(ip_address(ip), IPv4Address)
    except ValueError:
        return False

def isolate_machine(hostname: str, username: str, password: str, compromised_ip: str):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=username, password=password)

        command = f"iptables -A INPUT -s {compromised_ip} -j DROP && iptables -A OUTPUT -d {compromised_ip} -j DROP"
        stdin, stdout, stderr = ssh.exec_command(command)

        logging.info(f"Máquina con IP {compromised_ip} ha sido aislada.")
        ssh.close()
    except Exception as e:
        logging.error(f"Error aislando la máquina con IP {compromised_ip}: {e}")

def collect_logs(hostname: str, username: str, password: str, remote_log_paths: list, local_log_dir: str):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=username, password=password)

        sftp = ssh.open_sftp()
        for remote_log_path in remote_log_paths:
            local_log_path = os.path.join(local_log_dir, f"{hostname}_{os.path.basename(remote_log_path)}")
            sftp.get(remote_log_path, local_log_path)
            logging.info(f"Log recolectado de {remote_log_path} a {local_log_path}")
        
        sftp.close()
        ssh.close()
    except Exception as e:
        logging.error(f"Error recolectando logs de {hostname}: {e}")

def analyze_logs(log_files: list):
    for log_file in log_files:
        try:
            df = pd.read_csv(log_file, delimiter=' ', error_bad_lines=False)
            logging.info(f"Análisis del archivo {log_file}:")
            logging.info(df.head())
        except Exception as e:
            logging.error(f"Error analizando el archivo {log_file}: {e}")

def get_ip_range(start_ip: str, end_ip: str):
    start = int(ip_address(start_ip).packed[-1])
    end = int(ip_address(end_ip).packed[-1])
    base_ip = '.'.join(start_ip.split('.')[:-1])
    return [f"{base_ip}.{i}" for i in range(start, end + 1)]

if __name__ == "__main__":
    hostname = input("Introduce la IP del servidor remoto: ")
    username = input("Introduce el nombre de usuario: ")
    password = getpass.getpass("Introduce la contraseña: ")
    start_ip = input("Introduce la IP de inicio: ")
    end_ip = input("Introduce la IP de fin: ")

    if not validate_ip(start_ip) or not validate_ip(end_ip):
        print("Una o ambas IPs son inválidas.")
        logging.error("Una o ambas IPs proporcionadas son inválidas.")
    elif ip_address(start_ip) > ip_address(end_ip):
        print("La IP de inicio no puede ser mayor que la IP de fin.")
        logging.error("La IP de inicio es mayor que la IP de fin.")
    else:
        ip_range = get_ip_range(start_ip, end_ip)
        
        # Aislar máquinas comprometidas
        with ThreadPoolExecutor(max_workers=10) as executor:
            for ip in ip_range:
                executor.submit(isolate_machine, hostname, username, password, ip)
        
        # Recolectar logs
        remote_log_paths = ['/var/log/syslog', '/var/log/auth.log', '/var/log/kern.log']
        local_log_dir = '/tmp/incident_response_logs'
        os.makedirs(local_log_dir, exist_ok=True)
        
        collect_logs(hostname, username, password, remote_log_paths, local_log_dir)
        
        # Analizar logs recolectados
        log_files = [os.path.join(local_log_dir, f) for f in os.listdir(local_log_dir)]
        analyze_logs(log_files)
