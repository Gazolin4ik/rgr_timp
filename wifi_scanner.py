import subprocess
import re
from datetime import datetime

def get_test_aps():
    return [
        {
            'ssid': 'TestOpen',
            'bssid': '00:11:22:33:44:55',
            'signal': 80,
            'channel': 1,
            'encryption': 'Open',
        },
        {
            'ssid': 'TestSecure',
            'bssid': '66:77:88:99:AA:BB',
            'signal': 70,
            'channel': 6,
            'encryption': 'WPA2-Personal',
        },
        {
            'ssid': 'TestClone',
            'bssid': '12:34:56:78:90:AB',
            'signal': 60,
            'channel': 11,
            'encryption': 'WPA2-Personal',
        },
        {
            'ssid': 'TestClone',
            'bssid': '12:34:56:78:90:AC',
            'signal': 55,
            'channel': 11,
            'encryption': 'WPA2-Personal',
        },
        {
            'ssid': 'TestWeird',
            'bssid': 'notamac',
            'signal': 50,
            'channel': 3,
            'encryption': 'Open',
        },
    ]

def scan_wifi():
    result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'], capture_output=True, text=True, encoding='cp866')
    lines = result.stdout.split('\n')
    networks = []
    current_ssid = None
    current_encryption = ''
    for i, line in enumerate(lines):
        line = line.strip()
        if line.startswith('SSID '):
            current_ssid = line.split(':', 1)[1].strip()
            current_encryption = ''
        elif line.startswith('Шифрование'):
            current_encryption = line.split(':', 1)[1].strip()
        elif line.startswith('BSSID'):
            bssid = line.split(':', 1)[1].strip()
            signal = ''
            channel = ''
            auth = ''
            # Ищем параметры ниже по списку
            for j in range(i+1, min(i+10, len(lines))):
                l2 = lines[j].strip()
                if l2.startswith('Сигнал'):
                    val = l2.split(':', 1)[1].strip().replace('%', '')
                    signal = val if val else ''
                elif l2.startswith('Канал'):
                    val = l2.split(':', 1)[1].strip()
                    channel = val if val else ''
                elif l2.startswith('Проверка подлинности'):
                    val = l2.split(':', 1)[1].strip()
                    auth = val if val else ''
            networks.append({
                'ssid': current_ssid or '',
                'bssid': bssid or '',
                'signal': signal,
                'channel': channel,
                'encryption': current_encryption or auth,
            })
    # Добавляем тестовые точки
    networks.extend(get_test_aps())
    # Определяем открытые и подозрительные точки
    for ap in networks:
        encryption = ap.get('encryption') or ''
        ap['is_open'] = encryption.lower() in ['open', 'открытая', 'none', 'нет', 'Нет']
    for ap in networks:
        ap['is_suspicious'] = is_suspicious_ap(ap, networks)
    return networks

def is_suspicious_ap(ap, all_aps):
    # Подозрительно: SSID совпадает, а BSSID разный
    same_ssid = [a for a in all_aps if a.get('ssid') == ap.get('ssid') and a.get('bssid') != ap.get('bssid')]
    # Подозрительно: BSSID не похож на MAC
    bssid_susp = not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", ap.get('bssid') or "")
    return bool(same_ssid) or bssid_susp 