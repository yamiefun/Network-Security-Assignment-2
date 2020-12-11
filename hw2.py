import json
import sys
import os


def read_logs(filename):
    logs = []
    with open(filename, "r") as f:
        for line in f:
            data = json.loads(line)
            logs.append(data)
    return logs


def count_port(logs):
    ports = set()
    for log in logs:
        try:
            port = log['destination']['port']
            ports.add(port)
        except Exception:
            pass
    return len(ports)


def SQL(logs):
    # Check if there is "select" sql in logs.
    count = 0
    for log in logs:
        try:
            if "SELECT" in log['url']['query']:
                count += 1
        except Exception:
            pass
    return count


def brute_force(logs):
    count = 0
    for log in logs:
        try:
            if "Login" in log['url']['query']:
                count += 1
        except Exception:
            pass
    return count


def DDoS(logs):
    count = 0
    for log in logs:
        try:
            if log['http']['response']['status_phrase'] == \
                    "request-uri too long":
                count += 1
                return True
        except Exception:
            pass
    return count


def email(logs):
    count = 0
    for log in logs:
        try:
            if 'cmd.exe' in log['winlog']['event_data']['ProcessName']:
                count += 1
        except Exception:
            pass
    return count


def main():
    path = str(sys.argv[1])
    test_cases = os.listdir(path)
    test_cases.sort()
    for case in test_cases:
        # get path
        path_packet = os.path.join(path, case, 'packetbeat.json')
        path_winlog = os.path.join(path, case, 'winlogbeat.json')

        # read log file
        logs_packet = read_logs(path_packet)
        logs_winlog = read_logs(path_winlog)

        sql_ratio = SQL(logs_packet)/len(logs_packet)
        ddos_ratio = DDoS(logs_packet)/len(logs_packet)
        email_ratio = email(logs_winlog)/len(logs_winlog)
        bf_ratio = brute_force(logs_packet)/len(logs_packet)
        ps_ratio = count_port(logs_packet)/len(logs_packet)

        if ddos_ratio > 0:
            msg = f'{case}: DDoS'
        elif max(sql_ratio, email_ratio, bf_ratio, ps_ratio) == ps_ratio:
            msg = f'{case}: Port Scan'
        elif max(sql_ratio, email_ratio, bf_ratio) == sql_ratio:
            msg = f'{case}: SQL Injection'
        elif max(sql_ratio, email_ratio, bf_ratio) == email_ratio:
            msg = f'{case}: Phishing Email'
        elif max(sql_ratio, email_ratio, bf_ratio) == bf_ratio:
            msg = f'{case}: Brute-Force attack'
        print(msg)


if __name__ == "__main__":
    main()
