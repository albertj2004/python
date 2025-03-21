import os
import re
import shutil
from pathlib import Path
from getpass import getuser, getpass
from datetime import datetime, timedelta
import requests
import openpyxl
import pandas as pd
import urllib3
# from parallel import parallel_func
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from common_utils import set_logger, file_up_to_date, str2file, file2str
from f5_cfg import f5_adm_list, data_dir, share_dir

my_logger = None

"""
https://clouddocs.f5.com/api/icontrol-rest/#
"""

ltm_obj_url_map = {
    'vs':  '/mgmt/tm/ltm/virtual',
    'pool': '/mgmt/tm/ltm/pool',
    'rule': '/mgmt/tm/ltm/rule',
    'profile': '/mgmt/tm/ltm/profile',
    # vs profile /mgmt/tm/ltm/virtual/~Common~Exchange_2016.app~Exchange_2016_combined_http/profiles
    'self': '/mgmt/tm/net/self',
    'monitor': '/mgmt/tm/ltm/monitor',
    'node': '/mgmt/tm/ltm/node',
    'persistence': '/mgmt/tm/ltm/persistence',
    'policy': '/mgmt/tm/ltm/policy',
}
ltm_obj_attr_map = {
    'vs': ['profiles', 'policies'],
    'pool': ['members'],
}
link_objs = ['persistence', 'profile', 'monitor']
dns_type_list = ['a', 'aaaa', 'cname', 'mx', 'naptr', 'srv']
gtm_obj_url_map = {
    'dc':  '/mgmt/tm/gtm/datacenter',
    'top':  '/mgmt/tm/gtm/topology',
    'dns':  '/mgmt/tm/gtm/wideip',
    'pool':  '/mgmt/tm/gtm/pool',
    'prober_pool':  '/mgmt/tm/gtm/prober-pool',
    'server':  '/mgmt/tm/gtm/server',
    'listener':  '/mgmt/tm/gtm/listener',
    'monitor':  '/mgmt/tm/gtm/monitor',
    # 'distributed-app':  '/mgmt/tm/gtm/distributed-app',
    # 'link':  '/mgmt/tm/gtm/link',
    # 'rule':  '/mgmt/tm/gtm/rule',
}
gtm_obj_attr_map = {
    'server': ['devices', 'virtual-servers'],
    'prober-pool': ['members'],
}
bigiq_obj_url_map = {
    'dev': '/mgmt/shared/resolver/device-groups/cm-bigip-allBigIpDevices/devices/',
    'ltm_vs': '/mgmt/cm/adc-core/working-config/ltm/virtual/',
    'ltm_pool': '/mgmt/cm/adc-core/working-config/ltm/pool/',
    'gtm_dns_a': '/mgmt/cm/dns/current-config/wideip/a',
    'gtm_pool': '/mgmt/cm/dns/current-config/pool/a',
    'gtm_server': '/mgmt/cm/dns/current-config/server',
    'gtm_prober_pool':'/mgmt/cm/dns/current-config/prober-pool',
    'gtm_dc': '/mgmt/cm/dns/current-config/datacenter',
    'gtm_top': '/mgmt/cm/dns/current-config/topology',
}

def get_token(dev, **kwargs):
    login_provider = kwargs.get('login_provider', 'tmos')  # ISE-TACACS
    username = kwargs.get('user')
    password = kwargs.get('pwd')
    debug = kwargs.get('debug')
    body = {
        "username": username,
        "password": password,
        "loginProviderName": login_provider
    }
    print(f'\n{dev}: login')
    try:
        token_response = requests.post(f'https://{dev}/mgmt/shared/authn/login', verify=False, json=body, timeout=10).json()
    except Exception as e:
        token_response = {'error': 'login timeout'}
    token = ''
    if 'token' in token_response.keys():
        token = token_response['token']['token']
    else:
        token = str(token_response)
        if debug:
            my_logger.info(f"\n{dev}:{token_response}")
    """
    refresh_token = ''
    if 'refreshToken' in token_response.keys():
        refresh_token = token_response['refresh_token']['token']
    """
    return dev, token  #, refresh_token

def request_info(**kwargs):
    url = kwargs.get('url')
    token = kwargs.get('token')
    headers = {"X-F5-Auth-Token": token}
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        info = response.json()
        assert type(info) is dict
        if 'items' in info.keys():            
            items = info['items']
        else:
            items = [info]
    else:
        my_logger.info(response.text)
        items = []
    return items

def get_bigiq_info(dev, **kwargs):
    data_dir = kwargs.get('dir', '.')
    token = kwargs.get('token')
    excel_file = data_dir + fr'\bigiq.xlsx'
    if file_up_to_date(file=excel_file):
        print(f"{Path(excel_file).name} up to date")
        return

    writer = pd.ExcelWriter(excel_file, mode='w')        
    for obj, url in bigiq_obj_url_map.items():
        items = request_info(url=f'https://{dev}/{url}', token=token)
        if not items:
            continue
        df = pd.DataFrame(items)
        df.to_excel(writer, sheet_name=obj, index=False)

    writer.close()
    print(f"save {Path(excel_file).name}")

def get_gtm_info(**kwargs):
    data_dir = kwargs.get('dir', '.')
    dev = kwargs.get('dev')
    token = kwargs.get('token')
    excel_file = data_dir + fr'\{dev}.xlsx'
    if file_up_to_date(file=excel_file):
        print(f"{Path(excel_file).name} up to date")
        return
    writer = pd.ExcelWriter(excel_file, mode='w')
    for obj, url in gtm_obj_url_map.items():
        items = request_info(url=f'https://{dev}/{url}', token=token)
        if not items:
            continue        
        df = pd.DataFrame(items)
        df.to_excel(writer, sheet_name=obj, index=False)
        if obj in ['dns', 'pool']:
            for dns_type in dns_type_list:
                # pool/a
                items = request_info(url=f'https://{dev}/{url}/{dns_type}', token=token)
                if not items:
                    continue
                df1 = pd.DataFrame(items)
                df1.to_excel(writer, sheet_name=f'{obj}.{dns_type}', index=False)

                if obj == 'pool':
                    for _attr in ['members']:
                        _df = pd.DataFrame()
                        for fullPath in df1.fullPath:
                            items = request_info(url=f"https://{dev}/{url}/{dns_type}/{fullPath.replace('/', '~')}/{_attr}", token=token)
                            if not items:
                                continue
                            attr_df = pd.DataFrame(items)
                            attr_df[obj] = fullPath
                            _df = pd.concat([_df, attr_df])
                        _df.to_excel(writer, sheet_name=f'{obj}.{dns_type}.{_attr}', index=False)


        """
        pool.a: membersReference
        mgmt/tm/gtm/pool/a/~Common~appd.test_Pool/members
        
        devicesReference: server/~Common~server1/devices
        virtualServersReference: server/~Common~server1/virtual-servers
        fullPath

        """
        if obj in gtm_obj_attr_map.keys():
            for _attr in gtm_obj_attr_map[obj]:
                _df = pd.DataFrame()
                for fullPath in df.fullPath:
                    items = request_info(url=f"https://{dev}/{url}/{fullPath.replace('/', '~')}/{_attr}", token=token)
                    if not items:
                        continue
                    attr_df = pd.DataFrame(items)
                    attr_df[obj] = fullPath
                    _df = pd.concat([_df, attr_df])
                _df.to_excel(writer, sheet_name=f'{obj}.{_attr}', index=False)

        if obj in link_objs:
            _df = pd.DataFrame()
            for reference in df.reference:
                if type(reference) is str:
                    reference = eval(reference)
                url = reference['link'].replace('localhost', dev)
                items = request_info(url=url, token=token)
                if not items:
                    continue
                _df = pd.concat([_df, pd.DataFrame(items)])
            _df = _df.drop(columns=secret_cols, errors='ignore')
            _df.to_excel(writer, sheet_name=f'{obj}.data', index=False)

    writer.close()
    print(f"save {Path(excel_file).name}")
    return

secret_cols = ['certKeyChain', 'passphrase', 'insertCookiePassphrase']

def get_ltm_info(**kwargs):
    data_dir = kwargs.get('dir', '.')
    dev = kwargs.get('dev')
    token = kwargs.get('token')
    excel_file = data_dir + fr'\{dev}.xlsx'
    if file_up_to_date(file=excel_file):
        print(f"{Path(excel_file).name} up to date")
        return

    writer = pd.ExcelWriter(excel_file, mode='w')
    for obj, url in ltm_obj_url_map.items():
        items = request_info(url=f'https://{dev}/{url}', token=token)
        if not items:
            continue
        df = pd.DataFrame(items)
        df.to_excel(writer, sheet_name=obj, index=False)

        if obj in ltm_obj_attr_map.keys():
            for _attr in ltm_obj_attr_map[obj]:
                _df = pd.DataFrame()
                for fullPath in df.fullPath:
                    items = request_info(url=f"https://{dev}/{url}/{fullPath.replace('/', '~')}/{_attr}", token=token)
                    if not items:
                        continue
                    attr_df = pd.DataFrame(items)
                    attr_df[obj] = fullPath
                    _df = pd.concat([_df, attr_df])
                _df.to_excel(writer, sheet_name=f'{obj}.{_attr}', index=False)

        """
        if obj == 'vs':
            _df = pd.DataFrame()
            # profile_detail_df = pd.DataFrame()
            for fullPath in df.fullPath:
                items = request_info(url=f"https://{dev}/{url}/{fullPath.replace('/', '~')}/profiles", token=token)
                if not items:
                    continue
                _df = pd.concat([_df, pd.DataFrame(items)])
            _df.to_excel(writer, sheet_name='vs_profile', index=False)

        if obj == 'pool':
            _df = pd.DataFrame()
            for fullPath in df.fullPath:
                items = request_info(url=f"https://{dev}/{url}/{fullPath.replace('/', '~')}/members", token=token)
                if not items:
                    continue
                _df = pd.concat([_df, pd.DataFrame(items)])
            _df.to_excel(writer, sheet_name='member', index=False)
        """
        if obj in link_objs:
            _df = pd.DataFrame()
            for reference in df.reference:
                if type(reference) is str:
                    reference = eval(reference)
                url = reference['link'].replace('localhost', dev)
                items = request_info(url=url, token=token)
                if not items:
                    continue                
                _df = pd.concat([_df, pd.DataFrame(items)])
            _df = _df.drop(columns=secret_cols, errors='ignore')
            _df.to_excel(writer, sheet_name=f'{obj}.data', index=False)

    writer.close()
    print(f"save {Path(excel_file).name}")

def get_pools_by_rule(**kwargs):
    rule = kwargs.get('rule')
    df = kwargs.get('df')
    rule_text = df.loc[df['fullPath'] == rule, 'apiAnonymous'].iloc[0]
    pools = re.findall(r'^ +pool (/.+)$', rule_text, flags=re.MULTILINE)  # pool /Common/Exchange_2016.app/Exchange_2016_owa_pool7
    return pools

def get_pools_by_rules(**kwargs):
    rules = kwargs.get('rules')
    df = kwargs.get('df')
    pools = []
    for rule in rules:
        pools += get_pools_by_rule(rule=rule, df=df)
    return pools

def get_members_by_pool(**kwargs):
    pool = kwargs.get('pool')
    df = kwargs.get('df')
    pool_in_member = pool.replace('/', '~')
    return df.loc[df['selfLink'].str.contains(fr"/{pool_in_member}/")]

def process_gtm_info_p1(**kwargs):
    data_dir = kwargs.get('dir', '.')
    dev = kwargs.get('dev')

    p1_file = data_dir + fr'\{dev}.p1.csv'
    if file_up_to_date(file=p1_file):
        print(f"{Path(p1_file).name} up to date")
        return

    info_file = data_dir + fr'\{dev}.xlsx'
    
    top_cols = ['name']    
    top = pd.read_excel(info_file, sheet_name='top').fillna('')[top_cols]
    # ldns: subnet 172.18.60.160/32 server: datacenter /Common/HO_Datacentre
    top['dc'] = top['name'].apply(lambda x: x.split('datacenter')[1].strip())
    top['subnet'] = top['name'].apply(lambda x: x.split(' server: ')[0].split(' ')[-1].strip())
    top_cols = ['dc', 'subnet']
    top = top[top_cols]

    dns_cols = ['name', 'partition', 'poolLbMode', 'pools']
    dns = pd.read_excel(info_file, sheet_name='dns.a').fillna('')[dns_cols]
    dns.rename(columns={'name': 'dns', 'partition': 'dns.partition'}, inplace=True)
    dns['pools'] = dns['pools'].apply(eval)
    dns = dns.explode('pools')
    dns['pool'] = dns['pools'].apply(lambda x: '/' + x['partition'] + '/' + x['name'])
    # dns['pool.partition'] = dns['pools'].apply(lambda x: x['partition'])
    dns.drop(['pools'], axis=1, inplace=True)
    # assert dns[dns['pool.partition'] != 'Common'].empty
    
    pool_cols = ['fullPath', 'loadBalancingMode', 'alternateMode', 'fallbackMode']  # normal, static, last resort
    pool = pd.read_excel(info_file, sheet_name='pool.a').fillna('')[pool_cols]
    pool.rename(columns={'fullPath': 'pool'}, inplace=True)
    
    pool_member_cols = ['fullPath',	'pool']
    pool_member = pd.read_excel(info_file, sheet_name='pool.a.members').fillna('')[pool_member_cols]
    pool_member['server'] = pool_member['fullPath'].apply(lambda x: x.split(':')[0])
    pool_member['vs'] = pool_member['fullPath'].apply(lambda x:  x.split(':')[1] if ':' in x else '')
    pool_member_cols = ['pool', 'server', 'vs']
    pool_member = pool_member[pool_member_cols]

    server_cols = ['fullPath', 'datacenter', 'product']
    server = pd.read_excel(info_file, sheet_name='server').fillna('')[server_cols]
    server.rename(columns={'fullPath': 'server'}, inplace=True)

    vs_cols = ['name',	'destination', 'server']
    vs = pd.read_excel(info_file, sheet_name='server.virtual-servers').fillna('')[vs_cols]
    vs.rename(columns={'name': 'vs'}, inplace=True)

    gtm = pd.merge(dns, pool, on='pool')
    gtm = pd.merge(gtm, pool_member, on='pool')
    gtm = pd.merge(gtm, vs, on=['server', 'vs'])
    gtm = pd.merge(gtm, server, on=['server'])
    """
    with pd.ExcelWriter(p1_file, mode='w') as writer:
        top.to_excel(writer, sheet_name='dc.top', index=False)
        gtm.to_excel(writer, sheet_name='gtm', index=False)
    """
    gtm.to_csv(p1_file, index=False)
    print(f"save {Path(p1_file).name}")    

def process_ltm_info_p1(**kwargs):
    data_dir = kwargs.get('dir', '.')
    dev = kwargs.get('dev')

    p1_file = data_dir + fr'\{dev}.p1.csv'
    if file_up_to_date(file=p1_file):
        print(f"{Path(p1_file).name} up to date")
        return

    info_file = data_dir + fr'\{dev}.xlsx'
    vs = pd.read_excel(info_file, sheet_name='vs').fillna('')
    member = pd.read_excel(info_file, sheet_name='pool.members').fillna('')
    rule = pd.read_excel(info_file, sheet_name='rule').fillna('')    
    
    cols = ['vs', 'ip', 'protocol', 'port', 'pool', 'member', 'node ip', 'node port']    
    ltm = pd.DataFrame(columns=cols)
    i = 0
    for item in vs.itertuples():
        vs_fullPath = item.fullPath
        # /Common/203.8.222.103:443
        # /Common/2400:c500:203:202::111.80
        # /Common/10.42.84.250%2:443
        vs_ip_port = item.destination.split('/')[-1]
        if re.search(r'(\d+\.){3}\d+(%\d+)?:\d+', vs_ip_port):
            vs_ip, vs_port = vs_ip_port.split(':')
        else:
            vs_ip, vs_port = vs_ip_port.split('.')
        vs_protocol = item.ipProtocol
        if 'pool' in vs.columns:
            vs_pool = item.pool
        else:
            vs_pool = ''
        if vs_pool:
            vs_pools = [vs_pool]
        else:
            if 'rules' in vs.columns:
                rules = item.rules
            else:
                rules = ''
            if rules:
                vs_pools = get_pools_by_rules(rules=eval(rules), df=rule)
            else:
                vs_pools = []
                my_logger.info(f"{dev} {vs_fullPath} no pool or rules")
        for vs_pool in vs_pools:
            pool_member = get_members_by_pool(pool=vs_pool, df=member)
            if pool_member.empty:
                my_logger.info(f"{dev} {vs_pool} no member")
            else:
                for item in pool_member.itertuples():
                    pool_node, node_port = item.name.split(':')
                    node_ip = item.address
                    ltm.loc[i] = [vs_fullPath, vs_ip, vs_protocol, vs_port, vs_pool, pool_node, node_ip, node_port]
                    i += 1        
    # with pd.ExcelWriter(p1_file, mode='w') as writer:
    #   ltm.to_excel(writer, sheet_name='ltm', index=False)
    ltm.to_csv(p1_file, index=False)
    print(f"save {Path(p1_file).name}")

"""
def get_f5_tokens(**kwargs):
    hosts = kwargs.get('hosts')
    user = kwargs.get('user')
    pwd = kwargs.get('pwd')
    csv = kwargs.get('csv')
    debug = kwargs.pop('debug', False)
    max_worker = kwargs.pop('max_worker', 10)
    results = parallel_func(func=get_token, args=[(host,) for host in hosts], kwargs={'user': user, 'pwd': pwd, 'debug': debug, 'max_worker': max_worker})
    test_report = "dev,token,refresh_token\n"
    test_report += '\n'.join([f"{dev},{token},{refresh_token}" for dev, token, refresh_token in results])
    str2file(str=test_report, file=csv)
"""
"""
def get_f5_data(**kwargs):
    token_csv = kwargs.get('csv')
    hosts = kwargs.get('hosts')
    user = kwargs.get('user')
    pwd = kwargs.get('pwd')
    if file_up_to_date(file=token_csv):
        print(token_csv, 'up to date')
    else:
        get_f5_tokens(hosts=hosts, user=user, pwd=pwd, csv=token_csv)

    token_df = pd.read_csv(token_csv)
    token_df = token_df[token_df['token']!='']
    for item in token_df.itertuples():
        dev = item.dev
        token = item.token
        if '-ltm-' in dev:
            get_info_func = get_ltm_info    
            # process_p1_func = process_ltm_info_p1
        else:
            assert '-gtm-' in dev
            get_info_func = get_gtm_info
            # process_p1_func = process_gtm_info_p1
        get_info_func(dev=dev, token=token, dir=data_dir)
        # process_ltm_info_p1(dev=dev, dir=data_dir)
""" 
def get_f5_data(**kwargs):
    # exclude_list = kwargs.get('exclude_list')
    hosts = kwargs.get('hosts')
    data_dir = kwargs.get('dir')
    login_type = kwargs.get('login_type', 'rsa')
    csv = data_dir + fr'\f5.login.report.csv'
    if os.path.exists(csv):
        test_report = file2str(file=csv)
    else:
        test_report = ''
    if not test_report:
        test_report = "dev,token\n"
    
    user = getuser()
    if login_type in ['adm']:
        pwd = getpass('adm:')
    else:
        rsa_pin = getpass('rsa PIN:')
    for host in hosts:
        if host in test_report:
            print(f"{host} done")
            continue
        if login_type in ['adm']:
            dev, token = get_token(host, user=user, pwd=pwd, debug=True)
        else:
            dev, token = get_token(host, user=user, pwd=rsa_pin + getpass('rsa:'), debug=True)
        line = f"{dev},{token if token[0] == '{' else ''}\n"
        test_report += line
        str2file(str=line, file=csv, mode='a')
        if token and token[0] != '{':
            if '-ltm-' in dev:
                get_f5_info_func = get_ltm_info                
            else:
                assert '-gtm-' in dev
                get_f5_info_func = get_gtm_info
            get_f5_info_func(dev=dev, token=token, dir=data_dir)

def map_excel_sheet_name(excel_file):
    map_dict = {
        'vs.profiles': 'vs_profile',
        'pool.members': 'member',
        'profile.data': 'profile_list'
    }
    ss = openpyxl.load_workbook(excel_file)
    for k, v in map_dict.items():
        if k in ss.sheetnames:
            continue
        ss_sheet = ss[v]
        ss_sheet.title = k
    ss.save(excel_file)

def process_f5_data(**kwargs):
    data_dir = kwargs.get('dir')
    hosts = kwargs.get('hosts')
    pending_hosts = []
    for host in hosts:
        excel_file = data_dir + fr"\{host}.xlsx"
        if os.path.exists(excel_file):
            # print(host, df.loc[host, 'auth'])
            if '-ltm-' in host:
                # map_excel_sheet_name(excel_file)                
                process_func = process_ltm_info_p1 
            else:
                assert '-gtm-' in host
                process_func = process_gtm_info_p1 
            process_func(dev=host, dir=data_dir)
        else:
            pending_hosts.append(host)
            my_logger.info(f"no {excel_file}")
    # print(pending_hosts)
    return pending_hosts

if __name__ == '__main__':
    # my_logger = set_logger(file=data_dir + fr'\f5.api.log')
    f5_non_prd_csv = 'f5.non-prod.connect.report.csv'
    # exclude_regex=r'-(prd|pv|vpr)-'
    df = pd.read_csv(f5_non_prd_csv).fillna('').set_index('host')
    hosts = sorted(df[(df['result'] == True)].index.tolist())
    adm_hosts = [h for h in hosts if h.split('.')[0] in f5_adm_list]
    rsa_hosts = [h for h in hosts if h not in adm_hosts]
    # for login_type, f5_hosts in zip(['adm', 'rsa'], [adm_hosts, rsa_hosts]):
    #     get_f5_data(hosts=f5_hosts, dir=data_dir, login_type=login_type)
    my_logger = set_logger(file=data_dir + fr'\f5.process.log')
    process_f5_data(dir=data_dir, hosts=hosts)
    shutil.copytree(data_dir, share_dir, dirs_exist_ok=True)  # overwrite
