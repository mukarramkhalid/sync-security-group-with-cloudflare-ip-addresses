# Specify security group id and ports below.
# Each cloudflare IP address will be added for each port from-to combination.
# Caution: Any extra rules will be deleted from the specified security group.
# Only cloudflare IP addresses with the given combination of ports will remain

security_group_id = "sg-xxxxxxxxxxxxxxxxx"
ports = [
    {"from": 80, "to": 80},
    {"from": 443, "to": 443},
]

# No need to change anything below this line.
# But feel free to return any resonse.
import json
import copy
import boto3
import urllib3


def lambda_handler(event, context):
    security_group = SecurityGroup(security_group_id, ports)
    security_group.sync_with_cloudflare_ipaddresses()
    return {"statusCode": 200, "body": "Success"}


class SecurityGroup:
    """SecurityGroup Class"""

    cloudflare_ip_addresses_v4 = []

    cloudflare_ip_addresses_v6 = []

    ipv4_rule_map = []

    ipv6_rule_map = []

    security_group = None

    ports = []

    def __init__(self, security_group_id, ports):
        self.cloudflare_ip_addresses_v4 = []
        self.cloudflare_ip_addresses_v6 = []
        self.ipv4_rule_map = []
        self.ipv6_rule_map = []
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
        # Let's be honest, AWS API for security groups sucks.
        # The ingress and egress rules objects have a poor programmatic structure.
        # And the SDK doesn't help either
        # Iterating rules object
        temp_list = copy.deepcopy(ingress_rules)
        for ingress_rule in temp_list:
            if not self.port_combination_exists(ingress_rule["FromPort"], ingress_rule["ToPort"]):
                self.remove_ingress_rule(ingress_rule)
                ingress_rules.remove(ingress_rule)
                continue
            # Iterating IPv4 addresses
            for ipv4 in ingress_rule["IpRanges"]:
                if ipv4["CidrIp"] not in self.cloudflare_ip_addresses_v4:
                    self.remove_ingress_rule_for_ipv4(ingress_rule, ipv4)
                else: # Our rule already exists in the security group
                    self.ipv4_rule_map.remove({"cidr": ipv4["CidrIp"], "from_port": ingress_rule["FromPort"], "to_port": ingress_rule["ToPort"]})
            # Iterating IPv6 addresses
            for ipv6 in ingress_rule["Ipv6Ranges"]:
                if ipv6["CidrIpv6"] not in self.cloudflare_ip_addresses_v6:
                    self.remove_ingress_rule_for_ipv6(ingress_rule, ipv6)
                else: # Our rule already exists in the security group
                    self.ipv6_rule_map.remove({"cidr": ipv6["CidrIpv6"], "from_port": ingress_rule["FromPort"], "to_port": ingress_rule["ToPort"]})
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
