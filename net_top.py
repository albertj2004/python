import re
import os
import json
import pandas as pd
import ipaddress
from ipaddress import IPv4Network
from ntc_templates.parse import parse_output
from common_utils import file_up_to_date, set_logger, file2str, str2file, run_task
import net_top_cfg
from pyvis.network import Network
import networkx as nx
"""
nxos:
terminal length 0
show version
show ip interface vrf all
"""

def get_subnet_hosts(**kwargs):
    ip = kwargs.get('ip')
    mask = kwargs.get('mask')
    # mask = ipaddress.IPv4Network(f'0.0.0.0/{mask}', strict=False).prefixlen
    network = IPv4Network(f'{ip}/{mask}', strict=False)
    return list(network.hosts())    

dev_if_cols = net_top_cfg.dev_if_cols
link_cols = net_top_cfg.link_cols

def dev_if_ip_db_2_link(**kwargs):
    ip_db = kwargs.get('dev_if_ip_db').fillna('')
    ip_db = ip_db[ip_db['netmask'] != '']
    ip_db = ip_db[(ip_db['netmask'].astype(str).str.startswith('255.'))]
    ip_db = ip_db[~ip_db['netmask'].astype(str).str.contains('.*255$')]
    ip_db = ip_db[~ip_db['ipaddress'].str.startswith('127')]
    ip_db['ifName'] = ip_db['ifName'].apply(lambda x: x.split('/')[-1] if '/' in x else x)

    # ip_db = ip_db[ip_db['netmask'] == '255.255.255.252'].sort_values(by='ipaddress')
    link_db = pd.DataFrame(columns=link_cols)
    for row in ip_db.itertuples():
        dev, dev_if, ip, mask = row.device, row.ifName, row.ipaddress, row.netmask
        mask = ipaddress.IPv4Network(f'0.0.0.0/{mask}', strict=False).prefixlen
        my_logger.info(f"\n{dev, dev_if, ip, mask}")
        if mask < 24:
            continue
        dev_prefix = dev[:-1]
        subnet_hosts = get_subnet_hosts(ip=ip, mask=mask)
        subnet_hosts = [str(h) for h in subnet_hosts]
        if ip in subnet_hosts:
            subnet_hosts.remove(ip)
        same_subnet_hosts = [str(h) for h in subnet_hosts]
        nei_db = ip_db[ip_db['ipaddress'].isin(same_subnet_hosts)]
        # nei_db = ip_db[(ip_db['ipaddress'].isin(subnet_hosts)) & (ip_db['device'].str.startswith(dev_prefix))]
        adj_flag = False
        if len(nei_db) == 1:
            adj_flag = True
        else:
            nei_db = nei_db[nei_db['device'].str.contains('agg')]
            nei_db = nei_db[~nei_db['ifName'].str.contains('mgmt')]
            if len(nei_db):
                adj_flag = True
                # ['a', 'a_if', 'a_ip', 'a_mask', 'b', 'b_if', 'b_ip', 'b_mask']
            else:
                my_logger.info(sorted(nei_db['device'].tolist()))
        if adj_flag:
            assert len(nei_db) <= 2
            new_adj = nei_db[dev_if_cols].rename(columns={'device': 'b', 'ifName': 'b_if', 'ipaddress': 'b_ip', 'netmask': 'b_mask'})
            new_adj[link_cols[:4]] = [dev, dev_if, ip, mask]
            link_db = pd.concat([link_db, new_adj], ignore_index=True)
    return link_db

def get_data_by_json(**kwargs):
    json_file = kwargs.get('json_file')
    with open(json_file, 'r') as f:
        data_dict = json.load(f)
    total = data_dict['data']['objects'][0]['data_total']
    print(f"{total} items")
    data = data_dict['data']['objects'][0]['data']
    return pd.DataFrame(data)

os_map = {
    'cisco_nxos': 'Cisco Nexus Operating System (NX-OS) Software',
    'cisco_asa': 'Cisco Adaptive Security Appliance Software'
}

dev_ip_if_cmd_map = {
    'cisco_nxos': 'show ip interface vrf all',
    'cisco_asa': 'show interface'
}

dev_cols_map = {
    'cisco_nxos': ['interface', 'ip_address', 'subnet'],  # , 'link'
    'cisco_asa': ['interface', 'ip_address', 'netmask'],  # , 'link'
}

dev_cols_rename_map = {
    'cisco_nxos': {'interface': 'ifName', 'ip_address': 'ipaddress'},  # , 'link'
    'cisco_asa': {'interface': 'ifName', 'ip_address': 'ipaddress'},
}

def get_dev_os(**kwargs):
    info = kwargs.get('info')
    for os, os_regex in os_map.items():
        if re.search(re.escape(os_regex), info):
            return os
    return ''

def get_dev_info(**kwargs):
    dev = kwargs.get('dev')
    dev_os = kwargs.get('dev_os')
    info = kwargs.get('info')
    cmd = kwargs.get('cmd')
    dev = re.search(fr"^(.*)# {cmd}", info, re.MULTILINE).group(1)
    cmd_regex = fr"{dev}# {cmd}(.*){dev}# "
    m = re.search(cmd_regex, info, re.DOTALL)
    if m:
        m = m.group(1).split(f"{dev}#")[0]
        m = re.sub(r"System name .*", "", m)
    else:
        m = ''
    return m

def get_dev_if_ip_by_cmd(**kwargs):
    dev_db = kwargs.get('dev_db')
    data_dir = kwargs.get('data_dir')
    no_snmp_dev_list = sorted(dev_db[dev_db['snmp_state'] != 'up']['name'].tolist())
    dev_if_ip_db = pd.DataFrame(columns=net_top_cfg.dev_if_cols)  # ['device', 'ifName', 'ipaddress', 'netmask']
    for dev in no_snmp_dev_list:
        dev_file = data_dir + fr"\{dev}.log"
        if os.path.exists(dev_file):
            print(dev)
            info = file2str(file=dev_file)
            dev_os = get_dev_os(info=info)
            if dev_os:
                info = get_dev_info(dev=dev, dev_os=dev_os, info=info, cmd=dev_ip_if_cmd_map[dev_os])
                df = pd.DataFrame(parse_output(platform=dev_os, command=dev_ip_if_cmd_map[dev_os], data=info))[dev_cols_map[dev_os]].rename(columns=dev_cols_rename_map[dev_os])
                df['device'] = dev
                if dev_os == 'cisco_nxos':
                    df['netmask'] = df['subnet'].apply(lambda x:  ipaddress.IPv4Network(x, strict=False).netmask)
            dev_if_ip_db = pd.concat([dev_if_ip_db, df[net_top_cfg.dev_if_cols]])
    return dev_if_ip_db

def link_db_2_graph(**kwargs):
    link_db = kwargs.get('link_db').fillna('')
    """    
    for node in pd.concat([link_db['a'], link_db['b']]).unique():
        net.add_node(node)
    edges = []
    for _, row in link_db.iterrows():
        edges.append((row['a'], row['b'], {'label': f'{row["a"]}:{row["a_if"]} - {row["b"]}:{row["b_if"]}'}))
    net.add_edges(edges)
    net = Network(directed=False)
    """
    link_db['label'] = link_db["a"].astype(str) + ":" + link_db["a_if"].astype(str) + "<->" + link_db["b"].astype(str) +":" + link_db["b_if"].astype(str)
    G = nx.from_pandas_edgelist(link_db.fillna(""), 'a', 'b', edge_attr=['label'], create_using=nx.MultiGraph())
    net = Network(height='1200px', directed=True, notebook=True)  # cdn_resources='in_line'
    net.toggle_physics(False)
    net.show_buttons(filter_=['physics'])
    net.from_nx(G)
    net.show('network_with_ports.html')

if __name__ == '__main__':
    data_dir = net_top_cfg.data_dir
    my_logger = set_logger(file=data_dir + fr'\net_top.log')
    json_file = data_dir + fr"\top.dev.json"
    dev_db = get_data_by_json(json_file=json_file)
    # dev_db.to_excel(data_dir + fr"\top.dev.xlsx", index=False)

    dev_if_ip_db = get_dev_if_ip_by_cmd(dev_db=dev_db, data_dir=data_dir)

    json_file = data_dir + fr"\top.ip.json"
    ip_mask_db = get_data_by_json(json_file=json_file)
    # device, ipaddress, netmask
    ip_mask_db = ip_mask_db.rename(columns={'cdt_device.name': 'device'}).drop(columns=['id'])
    # ip_mask_db.to_excel(data_dir + fr"\top.ip.mask.xlsx", index=False)

    json_file = data_dir + fr"\top.ip.address.json"
    ip_db = get_data_by_json(json_file=json_file)
    # cdt_device.name, cdt_port.id, cdt_port.ifName, cdt_port.ifDescr
    ip_db = ip_db.rename(columns={'cdt_device.name': 'device', 'cdt_port.ifName': 'ifName', 'cdt_port.ifDescr': 'ifDescr'}).drop(columns=['id', 'cdt_port.id'])
    # ip_db.to_excel(data_dir + fr"\top.ip.address.xlsx", index=False)
    ip_db2 = pd.merge(ip_db, ip_mask_db, on=['deviceid', 'device', 'ipaddress'], how='outer')

    combined_dev_if_ip_db = pd.concat([dev_if_ip_db, ip_db2[net_top_cfg.dev_if_cols]])
    # combined_dev_if_ip_db.to_excel(data_dir + fr"\top.dev_if_ip.xlsx", index=False)

    # link_db = dev_if_ip_db_2_link(dev_if_ip_db=combined_dev_if_ip_db)
    # link_db.to_excel(data_dir + fr"\top.link.xlsx", index=False)
    link_db = pd.read_excel(data_dir + fr"\top.link.xlsx")
    link_db_2_graph(link_db=link_db)
