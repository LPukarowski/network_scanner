from queue import Queue

que = Queue()

results = {}
ip_active = []

common_vuln_ports = {
    
}

possible_service = {
    20: "FTP-Data", 21: "FTP", 22: "SSH",
    23: "Telnet", 25: "SMTP", 53: "DNS", 
    67: "DHCP-Server", 68: "DHCP-Client", 69: "TFTP",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 
    119: "NNTP", 123: "NTP", 135: "RPC / MSRPC",
    137: "NetBIOS-Name", 138: "NetBIOS-Datagram", 
    139: "NetBIOS-Session", 143: "IMAP", 161: "SNMP",
    162: "SNMP-Trap", 179: "BGP", 389: "LDAP", 
    443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 515: "LPD/LPR", 520: "RIP", 
    587: "SMTP-Submission", 631: "IPP / CUPS",
    636: "LDAPS", 873: "rsync", 902: "VMware-Server", 
    912: "VMware-VIX", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 
    1434: "MSSQL-Monitor", 1521: "Oracle",
    1723: "PPTP", 2049: "NFS", 2181: "Zookeeper", 
    2375: "Docker", 2376: "Docker TLS",
    2483: "Oracle-DB", 2484: "Oracle-DB TLS", 
    3306: "MySQL", 3389: "RDP", 3478: "STUN",
    3632: "distccd", 4369: "Erlang-PortMapper", 
    5000: "UPnP / Flask", 5432: "PostgreSQL",
    5672: "AMQP / RabbitMQ", 5900: "VNC", 
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis",
    6667: "IRC", 8000: "HTTP-Alt", 8008: "HTTP-Proxy",
    8080: "HTTP-Proxy/Alt", 8081: "HTTP-API", 8443: "HTTPS-Alt", 
    8500: "Consul", 9000: "SonarQube / PHP-FPM",
    9090: "Prometheus", 9200: "Elasticsearch", 
    9300: "Elasticsearch-Cluster", 9999: "Abyss",
    11211: "Memcached", 27017: "MongoDB", 
    27018: "MongoDB-Cluster", 50000: "SAP",
}