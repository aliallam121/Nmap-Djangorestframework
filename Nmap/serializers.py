from rest_framework import serializers
import socket

from .models import (
    Project,
    Range,
    Host,
    OperativeSystemMatch,
    OperativeSystemClass,
    Port,
    PortService,
    ScannerHistory,
    Sub_Domain
)


class RangeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Range
        fields = "__all__"


class ProjectSerializer(serializers.ModelSerializer):
    has_ranges = RangeSerializer(read_only=True, many=True)

    class Meta:
        model = Project
        fields = "__all__"


class HostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Host
        fields = "__all__"


class OperativeSystemClassSerializer(serializers.ModelSerializer):
    class Meta:
        model = OperativeSystemClass
        fields = "__all__"


class OperativeSystemMatchSerializer(serializers.ModelSerializer):
    specs = OperativeSystemClassSerializer(read_only=True)

    class Meta:
        model = OperativeSystemMatch
        fields = "__all__"


class PortServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = PortService
        fields = "__all__"


class PortSerializer(serializers.ModelSerializer):
    port_service = PortServiceSerializer(read_only=True)

    class Meta:
        model = Port
        fields = "__all__"


class Sub_DomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sub_Domain
        fields = "__all__"


class ScannerHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = ScannerHistory
        fields = "__all__"

    def save(self):
        target = self.validated_data['target']
        scanname = self.validated_data['scanname']
        subnet_to_attack = ""
        type = self.validated_data['type']
        if target.given=="ip":
            subnet_to_attack = target.ip_range + "/" + str(target.mask)
        else:
            subnet_to_attack = target.domain_name

        if type == 'FULL_TCP_SCAN' or type == 'FULL_UDP_SCAN' or type == 'PORT_SCAN_ONLY' or type == 'STEALTHY_SCAN' or type == 'ALL_PORT_SCAN_ONLY':
            ##########################################################################################################
            nmap = nmap3.Nmap()
            scanner_result = {}
            scanner_history = {}
            if type == 'FULL_TCP_SCAN':
                scanner_history = ScannerHistory(
                    target=target,
                    type='FULL_TCP_SCAN',
                    status='PENDING',
                    scanname=scanname
                )
                scanner_history.save()
                scanner_result = nmap.nmap_version_detection(
                    subnet_to_attack, args="-A")
            elif type == 'FULL_UDP_SCAN':
                scanner_history = ScannerHistory(
                    target=target,
                    type='FULL_UDP_SCAN',
                    status='PENDING',
                    scanname=scanname
                )
                scanner_history.save()
                nmap = nmap3.NmapScanTechniques()
                scanner_result = nmap.nmap_udp_scan(
                    subnet_to_attack, args="-F -sV -O -sC")
            elif type == 'PORT_SCAN_ONLY':
                scanner_history = ScannerHistory(
                    target=target,
                    type='PORT_SCAN_ONLY',
                    status='PENDING',
                    scanname=scanname
                )
                scanner_history.save()
                nmap = nmap3.NmapHostDiscovery()
                scanner_result = nmap.nmap_portscan_only(
                    subnet_to_attack, args="-A")
            elif type == 'ALL_PORT_SCAN_ONLY':
                scanner_history = ScannerHistory(
                    target=target,
                    type='ALL_PORT_SCAN_ONLY',
                    status='PENDING',
                    scanname=scanname
                )
                scanner_history.save()
                nmap = nmap3.NmapHostDiscovery()
                scanner_result = nmap.nmap_portscan_only(
                    subnet_to_attack, args="-p-")
            elif type == 'STEALTHY_SCAN':
                #    https://www.computerweekly.com/tip/How-to-manage-firewall-testing-using-Nmap
                # nmap -Pn -F -n –sF –g 443  --scan-delay 15 –f --reason
                # -Pn consider is up, -n dont reverse query dns
                # target to use FIN and spoof sourceport as 443
                # –f fragmented/devided packets with delay 15s between each
                scanner_history = ScannerHistory(
                    target=target,
                    type='STEALTHY_SCAN',
                    status='PENDING',
                    scanname=scanname
                )
                scanner_history.save()
                nmap = nmap3.NmapHostDiscovery()
                scanner_result = nmap.nmap_portscan_only(
                    subnet_to_attack, args="-n -sF -g 443  -f --reason")
            else:
                scanner_result = {}
                scanner_history = {}
                scanner_history.save()

            IPList = list(scanner_result)
            # take out stats and runtime from list, to remain a list of IPs
            IPList = IPList[: -2]
            for IP in IPList:

                host_data = {
                    'ip': IP
                }
                if "macaddress" in scanner_result[IP]:

                    if scanner_result[IP]["macaddress"] is not None:

                        if "addr" in scanner_result[IP]["macaddress"]:
                            host_data['mac_address'] = scanner_result[IP]["macaddress"]["addr"]

                host, created = Host.objects.get_or_create(**host_data)

                # Add host to scanner history (many to many relation)
                scanner_history.hosts.add(host)

                if "osmatch" in scanner_result[IP]:
                    for osmatch in scanner_result[IP]["osmatch"]:

                        operative_system_match, created = OperativeSystemMatch.objects.get_or_create(
                            name=osmatch["name"],
                            accuracy=osmatch["accuracy"],
                            line=osmatch["line"],
                            host=host
                        )

                        if "osclass" in osmatch:

                            operative_system_class_data = {}

                            operative_system_class_data['operative_system_match'] = operative_system_match

                            if "type" in osmatch["osclass"]:
                                operative_system_class_data['type'] = osmatch["osclass"]["type"]

                            if "vendor" in osmatch["osclass"]:
                                operative_system_class_data['vendor'] = osmatch["osclass"]["vendor"]

                            if "osfamily" in osmatch["osclass"]:
                                operative_system_class_data['operative_system_family'] = osmatch["osclass"]["osfamily"]

                            if "osgen" in osmatch["osclass"]:
                                operative_system_class_data['operative_system_generation'] = osmatch["osclass"]["osgen"]

                            if "accuracy" in osmatch["osclass"]:
                                operative_system_class_data['accuracy'] = osmatch["osclass"]["accuracy"]

                            operative_system_class, created = OperativeSystemClass.objects.get_or_create(
                                **operative_system_class_data
                            )

                if "ports" in scanner_result[IP]:
                    for ports in scanner_result[IP]["ports"]:

                        port = Port(
                            protocol=ports["protocol"],
                            port_number=ports["portid"],
                            state=ports["state"],
                            reason=ports["reason"],
                            reason_ttl=ports["reason_ttl"],
                            host=host
                        )
                        try:
                            port.save()
                        except:
                            port = None
                            return scanner_history
                        if "service" in ports:
                            port_service_data = {}

                            port_service_data['port'] = port

                            if "name" in ports["service"]:
                                port_service_data['name'] = ports["service"]["name"]

                            if "product" in ports["service"]:
                                port_service_data['product'] = ports["service"]["product"]

                            if "extrainfo" in ports["service"]:
                                port_service_data['extra_info'] = ports["service"]["extrainfo"]

                            if "hostname" in ports["service"]:
                                port_service_data['hostname'] = ports["service"]["hostname"]

                            if "ostype" in ports["service"]:
                                port_service_data['operative_system_type'] = ports["service"]["ostype"]

                            if "method" in ports["service"]:
                                port_service_data['method'] = ports["service"]["method"]

                            if "conf" in ports["service"]:
                                port_service_data['conf'] = ports["service"]["conf"]

                            port_service, created = PortService.objects.get_or_create(
                                **port_service_data
                            )
            scanner_history.status = 'FINISHED'
            scanner_history.save()
            return scanner_history
        elif type == 'HOST_DISCOVERY':
            ################################
            scanner_history = ScannerHistory(
                target=target,
                type=type,
                status='PENDING',
                scanname=scanname
            )
            scanner_history.save()

            nmap = nmap3.NmapHostDiscovery()
            scanner_result = nmap.nmap_no_portscan(subnet_to_attack)
            IPList = list(scanner_result)
            # take out stats and runtime from list, to remain a list of IPs
            IPList = IPList[: -2]
            for IP in IPList:
                host_data = {
                    'ip': IP
                }
                if "macaddress" in scanner_result[IP]:
                    if scanner_result[IP]["macaddress"] is not None:
                        if "addr" in scanner_result[IP]["macaddress"]:
                            host_data['mac_address'] = scanner_result[IP]["macaddress"]["addr"]
                host, created = Host.objects.get_or_create(**host_data)

                # Add host to scanner history (many to many relation)
                scanner_history.hosts.add(host)

            scanner_history.status = 'FINISHED'
            scanner_history.save()
            return scanner_history

        elif type == 'DNS_BRUTE':
            ################################
            scanner_history = ScannerHistory(
                target=target,
                type=type,
                status='PENDING',
                scanname=scanname
            )
            scanner_history.save()

            nmap = nmap3.Nmap()
            results = nmap.nmap_dns_brute_script(subnet_to_attack)
            if target.give =="ip":
                host_data = {
                    "ip":target.ip_range,
                    "mac_address": "unkown"
                }
                host, created = Host.objects.get_or_create(**host_data)
            else:
                host_data = {
                    "ip":socket.gethostbyaddr(target.ip_range)[2][0],
                    "mac_address": "unkown"
                }
                host, created = Host.objects.get_or_create(**host_data)
            for row in results:
                hostname = row['hostname']
                try:
                    sub_domain, created = Sub_Domain.objects.get_or_create(
                        host=host,
                        name=hostname,
                    )
                except:
                    pass
            scanner_history.status = 'FINISHED'
            scanner_history.save()
            return scanner_history
