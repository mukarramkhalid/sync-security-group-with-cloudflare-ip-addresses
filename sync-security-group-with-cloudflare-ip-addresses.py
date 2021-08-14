# Specify security group id and ports below.
# Each cloudflare IP address will be added for each port from-to combincation.
# So number of rules created will be equal to number of items in the ports list.
# Also, any other rules will be deleted from the specified security group.
# At the end of this script, only cloudflare IP addresses with the given combination
# of ports will remain in this security group

security_group_id = "sg-09023ab02701ccabd"
ports = [
    {"from": 80, "to": 80},
    {"from": 443, "to": 443},
]

# No need to change anything below this line.
import json
import boto3
import urllib3


def lambda_handler(event, context):
    security_group = SecurityGroup(security_group_id, ports)
    security_group.sync_with_cloudflare_ipaddresses()
    return {"statusCode": 200, "body": None}


class SecurityGroup:
    """SecurityGroup Class"""

    cloudflare_ip_addresses_v4 = []

    cloudflare_ip_addresses_v6 = []

    ipv4_rule_map = []

    ipv6_rule_map = []

    security_group = None

    ports = []

    def __init__(self, security_group_id, ports):
        ec2 = boto3.resource("ec2")
        self.security_group = ec2.SecurityGroup(security_group_id)
        self.ports = ports

    def sync_with_cloudflare_ipaddresses(self):
        self.grab_cloudflare_ipaddresses()
        self.make_rule_maps()
        self.process_inbound_rules()
        return

    def grab_cloudflare_ipaddresses(self):
        http = urllib3.PoolManager()
        response = http.request("GET", "https://www.cloudflare.com/ips-v4")
        self.cloudflare_ip_addresses_v4 = response.data.decode("utf-8").split("\n")
        http = urllib3.PoolManager()
        response = http.request("GET", "https://www.cloudflare.com/ips-v6")
        self.cloudflare_ip_addresses_v6 = response.data.decode("utf-8").split("\n")
        return
    
    def make_rule_maps(self):
        for cidr in self.cloudflare_ip_addresses_v4:
            for port in self.ports:
                self.ipv4_rule_map.append({
                    "cidr": cidr,
                    "from_port": port["from"],
                    "to_port": port["to"],
                })
        for cidr in self.cloudflare_ip_addresses_v6:
            for port in self.ports:
                self.ipv6_rule_map.append({
                    "cidr": cidr,
                    "from_port": port["from"],
                    "to_port": port["to"],
                })
        return

    def process_inbound_rules(self):
        ingress_rules = self.security_group.ip_permissions
        self.delete_ingress_rules_that_do_not_exist_anymore(ingress_rules)
        print(json.dumps(self.ipv4_rule_map))
        print(json.dumps(self.ipv6_rule_map))
        self.insert_remaining_ingress_rules()
        return

    def port_combination_exists(self, from_port, to_port):
        for port in ports:
            if from_port == port["from"] and to_port == port["to"]:
                return True
        return False

    def remove_ingress_rule_for_ipv4(self, ingress_rule, ipv4):
        return self.security_group.revoke_ingress(
            IpPermissions=[
                {
                    "FromPort": ingress_rule["FromPort"],
                    "IpProtocol": ingress_rule["IpProtocol"],
                    "IpRanges": [
                        {"CidrIp": ipv4["CidrIp"]},
                    ],
                    "ToPort": ingress_rule["ToPort"],
                },
            ]
        )

    def remove_ingress_rule_for_ipv6(self, ingress_rule, ipv6):
        return self.security_group.revoke_ingress(
            IpPermissions=[
                {
                    "FromPort": ingress_rule["FromPort"],
                    "IpProtocol": ingress_rule["IpProtocol"],
                    "Ipv6Ranges": [
                        {"CidrIpv6": ipv6["CidrIpv6"]},
                    ],
                    "ToPort": ingress_rule["ToPort"],
                },
            ]
        )

    def remove_ingress_rule(self, ingress_rule):
        for ipv4 in ingress_rule["IpRanges"]:
            self.remove_ingress_rule_for_ipv4(ingress_rule, ipv4)
        for ipv6 in ingress_rule["Ipv6Ranges"]:
            self.remove_ingress_rule_for_ipv6(ingress_rule, ipv6)
        return

    def delete_ingress_rules_that_do_not_exist_anymore(self, ingress_rules):
        # Let's be honest, AWS API for security groups is shit.
        # The ingress and egress rules objects have a poor programmatic structure.
        # And the SDK doesn't help either
        # Iterating rules object
        for index, ingress_rule in enumerate(ingress_rules):
            if not self.port_combination_exists(ingress_rule["FromPort"], ingress_rule["ToPort"]):
                self.remove_ingress_rule(ingress_rule)
                ingress_rules.pop(index)
                continue
            # Iterating IPv4 addresses
            for ipv4 in ingress_rule["IpRanges"]:
                if ipv4["CidrIp"] not in self.cloudflare_ip_addresses_v4:
                    self.remove_ingress_rule_for_ipv4(ingress_rule, ipv4)
                else: # Our rule already exists in the security group
                    self.remove_ipv4_rule_map_entry(ipv4["CidrIp"], ingress_rule["FromPort"], ingress_rule["ToPort"])
            # Iterating IPv6 addresses
            for ipv6 in ingress_rule["Ipv6Ranges"]:
                if ipv6["CidrIpv6"] not in self.cloudflare_ip_addresses_v6:
                    self.remove_ingress_rule_for_ipv6(ingress_rule, ipv6)
                else: # Our rule already exists in the security group
                    self.remove_ipv6_rule_map_entry(ipv6["CidrIpv6"], ingress_rule["FromPort"], ingress_rule["ToPort"])
        return

    def remove_ipv4_rule_map_entry(self, cidr, from_port, to_port):
        for index, rule in enumerate(self.ipv4_rule_map):
            if rule["cidr"] == cidr and rule["from_port"] == from_port and rule["to_port"] == to_port:
                self.ipv4_rule_map.pop(index)
                # return as soon as the rule is found because there would be only one occurence in rule map
                return
        return

    def remove_ipv6_rule_map_entry(self, cidr, from_port, to_port):
        for index, rule in enumerate(self.ipv6_rule_map):
            if rule["cidr"] == cidr and rule["from_port"] == from_port and rule["to_port"] == to_port:
                self.ipv6_rule_map.pop(index)
                # return as soon as the rule is found because there would be only one occurence in rule map
                return
        return

    def insert_remaining_ingress_rules(self):
        for rule in self.ipv4_rule_map:
            self.security_group.authorize_ingress(
                IpPermissions=[
                    {
                        "FromPort": rule["from_port"],
                        "IpProtocol": "tcp",
                        "IpRanges": [
                            {"CidrIp": rule["cidr"], "Description": ""},
                        ],
                        "ToPort": rule["to_port"],
                    },
                ]
            )
        for rule in self.ipv6_rule_map:
            self.security_group.authorize_ingress(
                IpPermissions=[
                    {
                        "FromPort": rule["from_port"],
                        "IpProtocol": "tcp",
                        "Ipv6Ranges": [
                            {"CidrIpv6": rule["cidr"], "Description": ""},
                        ],
                        "ToPort": rule["to_port"],
                    },
                ]
            )
        return
