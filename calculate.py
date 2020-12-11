import hw2


def main():
    packet_path = "Logs/Example_Test/Test_5/packetbeat.json"
    winlog_path = "Logs/Example_Test/Test_5/winlogbeat.json"
    logs_packet = hw2.read_logs(packet_path)
    logs_winlog = hw2.read_logs(winlog_path)
    total_count_packet = len(logs_packet)
    total_count_winlog = len(logs_winlog)
    ratio_SQL = hw2.SQL(logs_packet)/total_count_packet
    ratio_email = hw2.email(logs_winlog)/total_count_winlog
    ratio_DDoS = hw2.DDoS(logs_packet)/total_count_packet
    ratio_brute_force = hw2.brute_force(logs_packet)/total_count_packet
    ratio_port_scan = hw2.count_port(logs_packet)/total_count_packet

    print("SQL:\t", ratio_SQL)
    print("email:\t", ratio_email)
    print("DDoS:\t", ratio_DDoS)
    print("brute:\t", ratio_brute_force)
    print("PS:\t", ratio_port_scan)


if __name__ == "__main__":
    main()
