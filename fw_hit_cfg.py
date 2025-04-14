from common_cfg import *
import common_utils
from common_utils import *

import re
from string import Template
from getpass import getuser, getpass

data_type = 'Firewall'
sys_name = 'fw.hit'
log_file = mk_day_dir(source=data_type) + fr'\{sys_name}.log'
common_utils.my_logger = my_logger = set_logger(file=log_file)

cfg_file = f'{sys_name}.cfg.yaml'
if not check_dirs(dirs=[job_dir + fr'\{cfg_file}']):
    exit(0)

cfg_data = read_yaml_file(file=job_dir + fr'\{cfg_file}')
fw_broken_list = [fw.strip() for fw in cfg_data['fw_broken_list'].strip().split('\n')]
fw_ip_list = [fw.strip() for fw in cfg_data['fw_ip_list'].strip().split('\n')]
fw_ip_list = [re.sub(r' +', ' ', line.strip()).split(' ') for line in fw_ip_list if line.strip()]
fw_ip_list = [(fw, ip) for fw, ip in fw_ip_list if fw not in fw_broken_list]
fw_list = [fw for fw, ip in fw_ip_list]

cmds_template = Template("""
password:
$pwd
Press Return to begin session.

$fw>
en
Password:
$enable_pwd
$fw#
term pager 0
$fw#
show access-list
$fw#
""")
timeout_long = 1200
timeout_short = 30

acl_start_regex = r"access-list (?P<name>.+); \d+ elements; name hash: .+"

fw_acl_hit_cols = """
acl_name
type
line_num
remark
action
protocol
svc_object_grp
svc_object
src_object_grp
src_object
src_host
src_network	
src_mask
src_any
dst_object_grp
dst_object
dst_host
dst_network	
dst_mask
dst_any
dst_port
dst_port_range_start
dst_port_range_end
dst_port_grp	
dst_port_object
dst_icmp_type
hit_count
""".strip().split('\n')
fw_acl_hit_cols = [col.strip() for col in fw_acl_hit_cols]

"""
entry_protocol_icmp
entry_protocol
entry_src_fqdn	
entry_src_range_start
entry_src_range_end
entry_src_host
entry_src_network
entry_src_mask
entry_src_any
entry_src_fqdn_state	
entry_dst_fqdn	
entry_dst_range_start	
entry_dst_range_end
entry_dst_host
entry_dst_network
entry_dst_mask
entry_dst_any
entry_dst_fqdn_state
entry_icmp_type
entry_icmp_code
entry_port
entry_port_less_than	
entry_port_greater_than
entry_port_range_start
entry_port_range_end
entry_hit_count
entry_state
"""

net_obj_map = {
    'All-Addresses': 'any',
    'All-IPv4-Addresses': 'any4',
}

svc_protocol_port_map = {
    'IP': ('ip', ''),
    'ICMP': ('icmp', ''),
    'PIM': ('pim', ''),
    'TCP': ('tcp', ''),
    'UDP': ('udp', ''),
    'Bootpc': ('udp', 'bootpc'),
    'Bootps': ('udp', 'bootps'),
    'Citrix-ICA': ('tcp', 'citrix-ica'),
    'DHCP-Relay': ('udp', 'bootps'),
    'DNS-UDP': ('udp', 'domain'),
    'DNS-TCP': ('tcp', 'domain'),
    'FTP': ('tcp', 'ftp'),
    'FTP-Data': ('tcp', 'ftp-data'),
    'HTTP': ('tcp', 'www'),
    'HTTPS': ('tcp', 'https'),
    'IMAP4': ('tcp', 'imap4'),
    'LDAP': ('tcp', 'ldap'),
    'LDAPS': ('tcp', 'ldaps'),
    'MS-SQL-Server': ('tcp', '1433'),
    'MS-SQL-Monitor': (['tcp', 'udp'], '1434'),
    'Microsoft-ds': (['tcp', 'udp'], '445'),
    'Nbsession': ('tcp', 'netbios-ssn'),
    'Nbdatagram': ('udp', 'netbios-ns'),  # CSM definition TCP 137 is name service, 
    'Nbname': ('udp', 'netbios-dgm'),  # CSM definition TCP 138 is datagram service, 
    'NFS-TCP': ('tcp', 'nfs'),
    'NTP-TCP': ('tcp', '123'),
    'NTP-UDP': ('udp', 'ntp'),
    'SIP': (['tcp', 'udp'], 'sip'),
    'SMTP': ('tcp', 'smtp'),
    'SNMP': ('udp', 'snmp'),
    'SNMP-Trap': ('udp', 'snmptrap'),
    'SSH': ('tcp', 'ssh'),
    'Sun-RPC-TCP': ('tcp', 'sunrpc'),
    'Syslog': ('udp', 'syslog'),
    'Telnet': ('tcp', 'telnet'),
    'TFTP-TCP': ('tcp', '69'),
}

protocol_port_svc_map = {  # port range
    'udp:67': 'bootps',
    'udp:69': 'tftp',
    'tcp:80': 'www',
    'tcp:443': 'https',
    'tcp:1494': 'citrix-ica',
    'tcp:1521': 'sqlnet',
}

usr = getuser()
enable_pwd = getpass('adm pwd:')
rsa_pin = getpass('RSA PIN(4):')
