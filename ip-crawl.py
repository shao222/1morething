import psutil
import time
import sys
from ipaddress import ip_interface
import socket

def get_c_subnet(ip_address):
    try:
        ip_network_str = f"{ip_address}/24"
        ip_interface_obj = ip_interface(ip_network_str)
        return str(ip_interface_obj.network)
    except ValueError:
        return "unknown_subnet"

def find_process_by_name(process_name):
    processes = []

    for process in psutil.process_iter(['name']):
        if process.info['name'] == process_name:
            processes.append(process)

    return processes

def get_protocol_name(protocol_num):
    try:
        protocol_name = socket.getservbyport(protocol_num)
    except OSError:
        protocol_name = 'unknown'

    return protocol_name

def get_protocol_name_by_type(proto_type):
    if proto_type == socket.SOCK_STREAM:
        return 'TCP'
    elif proto_type == socket.SOCK_DGRAM:
        return 'UDP'
    elif proto_type == socket.SOCK_RAW:
        return 'RAW'
    else:
        return 'unknown'

def monitor_connections(process_name, duration):
    try:
        target_process = None
        pid = None

        visited_c_subnets = set()
        recorded_c_subnets = set()

        while True:
            if not target_process or not psutil.pid_exists(pid):
                target_processes = find_process_by_name(process_name)
                if not target_processes:
                    print(f"No processes found with the name '{process_name}'. Waiting for the process to start...")
                    time.sleep(duration)
                    continue
                
                # 获取第一个进程实例并记录其pid
                target_process = target_processes[0]
                pid = target_process.pid

                print(f"Monitoring connections for process: {process_name} (PID: {pid})")

            connections = psutil.net_connections('all')

            target_connections = []
            for conn in connections:
                if conn.pid == pid:
                    target_connections.append(conn)

            with open("access_log.txt", 'a') as log_file:
                for conn in target_connections:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    protocol_num = conn.type
                    protocol_name = get_protocol_name_by_type(conn.type)

                    console_entry = f"{remote_ip}:{remote_port} {protocol_name}"
                    print(console_entry)

                    remote_ip_c_subnet = get_c_subnet(remote_ip)
                    if remote_ip_c_subnet not in visited_c_subnets:
                        visited_c_subnets.add(remote_ip_c_subnet)
                        if remote_ip_c_subnet not in recorded_c_subnets:
                            log_entry = f"  - '{remote_ip_c_subnet}'"
                            log_file.write(log_entry + '\n')
                            recorded_c_subnets.add(remote_ip_c_subnet)

            time.sleep(duration)

            # 清空已记录的C段地址
            recorded_c_subnets.clear()

    except KeyboardInterrupt:
        print("\nMonitoring program stopped by user.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py your_program_name")
        sys.exit(1)

    target_process_name = sys.argv[1]

    monitoring_duration = 10

    monitor_connections(target_process_name, monitoring_duration)