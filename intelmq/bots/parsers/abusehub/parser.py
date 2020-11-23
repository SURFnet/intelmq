"""
AbuseHub parser
"""
from intelmq.lib.bot import ParserBot
from intelmq.lib.harmonization import DateTime


class AbuseHubParserBot(ParserBot):
    '''
    abusehub_to_type = {
        "ShadowServer Accessible VNC Service Report": ("potentially-unwanted-accessible", "vnc"),
        "ShadowServer Amplification DDoS Victim Report": ("ddos", "ddos"),
        "Shadowserver Command and Control": ("c2server", "c2server"),
        "Shadowserver Sinkhole HTTP Drone": ("c2server", "drone"),
        "Shadowserver Botnet Drone": ("infected-system", "drone"),
        "ShadowServer Accessible Apple Remote Desktop Report": ("potentially-unwanted-accessible", "rdp"),
        "ShadowServer Open Elasticsearch Server Report": ("potentially-unwanted-accessible", "elasticsearch"),
        "ShadowServer SSL/Freak Vulnerable Servers report": ("weak-crypto", "ssl_freak"),
        "ShadowServer Accessible FTP Service Report": ("potentially-unwanted-accessible", "ftp"),
        "Shadowserver SSLv3/Poodle Vulnerable Servers": ("weak-crypto", "ssl_poodle"),
        "ShadowServer Accessible Telnet Service Report": ("potentially-unwanted-accessible", "telnet"),
        "ShadowServer Accessible HTTP Report": ("potentially-unwanted-accessible", "http"),
        "ShadowServer Open TFTP Servers Report": ("potentially-unwanted-accessible", "tftp"),
        "Shadowserver Open SSDP": ("potentially-unwanted-accessible", "ssdp"),
        "Shadowserver NTP Version": ("ddos-amplifier", "ntp"),
        "ShadowServer Accessible RDP Services Report": ("potentially-unwanted-accessible", "rdp"),
        "ShadowServer Blacklisted IP Addresses Report": ("blacklist", "blacklist"),
        "Shadowserver Open NetBIOS": ("potentially-unwanted-accessible", "netbios"),
        "Shadowserver Open DNS Resolvers": ("ddos-amplifier", "dns"),
        "ShadowServer Vulnerable NAT-PMP Systems report": ("vulnerable-system", "nat"),
        "Shadowserver Open MS-SQL Server Resolution Service Report": ("potentially-unwanted-accessible", "ms-sql"),
        "ShadowServer Open MongoDB Service Report": ("potentially-unwanted-accessible", "mongodb"),
        "ShadowServer Open Portmapper Scan Report": ("potentially-unwanted-accessible", "portmapper"),
        "ShadowServer Open mDNS Servers Report": ("potentially-unwanted-accessible", "mdns"),
        "ShadowServer ISAKMP Vulnerability Scan Report": ("vulnerable-system", "isakmp"),
        "ShadowServer Accessible SMB Service Report": ("potentially-unwanted-accessible", "smb"),
        "ShadowServer Accessible rsync service Report": ("potentially-unwanted-accessible", "rsync"),
        "ShadowServer Accessible Apple Filing Protocol Report": ("potentially-unwanted-accessible", "afp"),
        "ShadowServer Drone Brute Force Report": ("infected-system", "bruteforce"),
        "Spamhaus Bot Report": ("infected-system", "bot"),
        "Vulnerable Citrix Services": ("potentially-unwanted-accessible", "citrix"),
        "N6": ("other", "n6"),
    }
    '''
    abusehub_to_type = {}

    parse = ParserBot.parse_csv_dict
    recover_line = ParserBot.recover_line_csv_dict

    def parse_line(self, line, report):
        event = self.new_event(report)

        # Map the infection_type if we know it, otherwise pass it on as-is
        mapped_type = self.abusehub_to_type.get(line["report_type"], ["other", line["infection_type"]])
        report_type, report_identifier = mapped_type

        event.add('feed.provider', line["reliable_notifier"], overwrite=True)
        event.add('feed.name', line["report_type"], overwrite=True)
        event.add("feed.code", "AbuseHub", overwrite=True)
        #event.add("extra.datasource", "AbuseHub", overwrite=True)

        # TODO, What are correlation_score[1234]?
        accuracy = event.get('feed.accuracy', 100) * int(line["correlation_score4"]) / 1000
        event.add("feed.accuracy", min(accuracy, 100),
                  overwrite=True)

        event.add("source.ip", line["src_ip"])
        event.add("source.port", line["src_port"])

        # src_hostname does not contain hostname
        #event.add("source.fqdn", line["src_hostname"])
        event.add("source.asn", line["src_asn"])

        event.add("destination.ip", line["dst_ip"])
        event.add("destination.port", line["dst_port"])

        # I don't trust dst_hostname, see src_hostname
        #event.add("destination.fqdn", line["dst_hostname"])
        event.add("destination.asn", line["dst_asn"])

        # TODO We need mapping between Abusehub and intelmq
        event.add("classification.type", report_type)
        event.add("classification.identifier", report_identifier)

        # TODO, observation is intelmq
        event.add("time.source", line["event_date"] + "T" + line["event_time"] + "+00:00")
        event.add("protocol.application", line["protocol"])

        event.add("raw", self.recover_line(line))
        yield event

BOT = AbuseHubParserBot

