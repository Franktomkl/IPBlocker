import paramiko
import getpass
import logging
from ipaddress import ip_address, IPv4Address
from concurrent.futures import ThreadPoolExecutor

# Configurar el logging
logging.basicConfig(filename='incident_response.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def validate_ip(ip: str) -> bool:
    try:
        return isinstance(ip_address(ip), IPv4Address)
    except ValueError:
        return False

def unblock_machine(hostname: str, username: str, password: str, compromised_ip: str):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=username, password=password)

        command = f"iptables -D INPUT -s {compromised_ip} -j DROP && iptables -D OUTPUT -d {compromised_ip} -j DROP"
        stdin, stdout, stderr = ssh.exec_command(command)

        logging.info(f"Tráfico restaurado para la máquina con IP {compromised_ip}.")
        ssh.close()
    except Exception as e:
        logging.error(f"Error restaurando el tráfico para la máquina con IP {compromised_ip}: {e}")

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
        
        # Desbloquear máquinas comprometidas
        with ThreadPoolExecutor(max_workers=10) as executor:
            for ip in ip_range:
                executor.submit(unblock_machine, hostname, username, password, ip)
