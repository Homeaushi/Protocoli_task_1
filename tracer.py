import re
import socket
import subprocess
import requests
from ipaddress import ip_address, IPv4Address


def validate_ip(ip):
    try:
        return bool(ip_address(ip))
    except ValueError:
        return False

def convert_domain_to_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        raise ValueError(f"Проблема с доменным именем")

def run_tracert(target):
    try:
        command = ['tracert', '-d', '-w', '1000', '-h', '30', target]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output, error = process.communicate()

        if process.returncode != 0:
            raise RuntimeError(f"Ошибка трассировки")
        return output
    except FileNotFoundError:
        raise RuntimeError("tracert не найдена")
    except Exception as e:
        raise RuntimeError(f"Ошибка при выполнении трассировки")

def parse_traceroute_output(output):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = []

    for line in output.split('\n'):
        if '*' in line or 'Request timed out' in line:
            continue
        match = re.search(ip_pattern, line)
        if match:
            ip = match.group(0)
            if ip not in ips:
                ips.append(ip)
    return ips

def get_asn_info(ip):
    if not validate_ip(ip):
        return None
    try:
        if IPv4Address(ip).is_private:
            return {
                'asn': 'Частная',
                'country': 'Ru',
                'provider': 'Частная сеть'
            }
    except:
        pass

    try:
        url = f"https://stat.ripe.net/data/whois/data.json?resource={ip}"
        answer = requests.get(url, timeout=5)
        data = answer.json()
        asn = 'Неизвестно'
        country = 'Неизвестно'
        provider = 'Неизвестно'
        records = data.get('data', {}).get('records', [])

        for record_group in records:
            for record in record_group:
                key = record.get('key', '').lower()
                value = record.get('value', '')
                if key == 'origin':
                    asn = value
                elif key == 'country':
                    country = value
                elif key == 'descr':
                    provider = value if provider == 'Неизвестно' else provider
        return {
            'asn': asn,
            'country': country,
            'provider': provider
        }
    except requests.exceptions.RequestException:
        return {
            'asn': 'Время истекло',
            'country': 'Неизвестно',
            'provider': 'Неизвестно'
        }

def print_results_table(ips, asn_info_list):
    print("\nРезультаты трассировки:")
    print(f"{'№':<5}{'IP-адрес':<20}{'AS':<15}{'Страна':<10}{'Провайдер'}")
    for i, (ip, info) in enumerate(zip(ips, asn_info_list), 1):
        if not info:
            print(f"{i:<5}{ip:<20}{'Error':<15}{'Error':<10}{'Error'}")
            continue
        print(f"{i:<5}{ip:<20}{info['asn']:<15}{info['country']:<10}{info['provider']}")

def main():
    print("Введите доменное имя или IP-адрес для трассировки: ")
    try:
        input_text = input().strip()
        if validate_ip(input_text):
            ip = input_text
        else:
            ip = convert_domain_to_ip(input_text)
            print(f"IP-адрес для {input_text}: {ip}")
        print(f"\nВыполняю трассировку до {input_text} ({ip})")
        traceroute_output = run_tracert(ip)
        ips = parse_traceroute_output(traceroute_output)
        if not ips:
            raise RuntimeError("Не удалось обнаружить IP-адреса в результате трассировки")
        asn_info_list = []
        for ip in ips:
            try:
                info = get_asn_info(ip)
                asn_info_list.append(info)
            except Exception as e:
                print(f"Ошибка при получении информации для {ip}: {str(e)}")
                asn_info_list.append(None)
        print_results_table(ips, asn_info_list)
    except Exception as e:
        print(f"\nОшибка: {str(e)}")
        print("Проверьте подключение к интернету и правильность введенного адреса.")

if __name__ == "__main__":
    main()
