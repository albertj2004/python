import os
import re
from datetime import datetime
from pathlib import Path
import requests
import pandas as pd
from glob import glob
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from common_utils import *
import f5_cfg
from f5_cfg import *

data_dir = None
my_logger = None
svc_usr, svc_pwd = None, None

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
        token_response = {'error': e}
    token = ''
    if 'token' in token_response.keys():
        token = token_response['token']['token']
    else:
        token = str(token_response)
        if debug:
            my_logger.info(f"{dev}:{token}")
    """
    refresh_token = ''
    if 'refreshToken' in token_response.keys():
        refresh_token = token_response['refresh_token']['token']
    """
    return token  #, refresh_token

def request_info(**kwargs):
    url = kwargs.get('url')
    token = kwargs.get('token')
    headers = {"X-F5-Auth-Token": token}
    items = []
    try:
        response = requests.get(url, headers=headers, verify=False)
        if response.status_code == 200:
            info = response.json()
            assert type(info) is dict
            if 'items' in info.keys():            
                items = info['items']
            else:
                items = [info]
        else:
            my_logger.info(f'{url}\n{response.status_code}\n{response.text}')
    except Exception as e:
        my_logger.info(f'{url}\n{e}')
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
                        if len(_df):
                            _df.to_excel(writer, sheet_name=f'{obj}.{dns_type}.{_attr}', index=False)

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
                if len(_df):
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
            if len(_df):
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
        if items:
            df = pd.DataFrame(items)
            df.to_excel(writer, sheet_name=obj, index=False)
        else:
            my_logger.info(f'{dev} {obj} empty')
            if obj in ['vs']:
                writer.close()
                if os.path.exists(excel_file):
                    my_logger.info(f'del {excel_file}')
                    os.remove(excel_file)
                return
            else:
                continue

        if obj in ltm_obj_attr_map.keys():
            for _attr in ltm_obj_attr_map[obj]:
                _df = pd.DataFrame()
                for fullPath in df.fullPath:
                    req_url = f"https://{dev}/{url}/{fullPath.replace('/', '~')}/{_attr}"
                    items = request_info(url=req_url, token=token)
                    if not items:
                        if _attr not in ['policies']:
                            my_logger.info(f'{dev} {obj} {_attr} {fullPath} empty')
                        continue
                    """
                    if _attr in ['policies']:
                        my_logger.info(f'{dev} {obj} {_attr} {fullPath}')
                    """
                    attr_df = pd.DataFrame(items)
                    attr_df[obj] = fullPath
                    _df = pd.concat([_df, attr_df])
                if len(_df):
                    _df.to_excel(writer, sheet_name=f'{obj}.{_attr}', index=False)

        if obj in link_objs:
            _df = pd.DataFrame()
            for reference in df.reference:
                if type(reference) is str:
                    reference = eval(reference)
                req_url = reference['link'].replace('localhost', dev)
                items = request_info(url=req_url, token=token)
                if not items:
                    my_logger.info(f'{dev} {obj} {re.search(r'/([^/]+)\?', req_url).group(1)} empty')
                    continue                
                _df = pd.concat([_df, pd.DataFrame(items)])
            if len(_df):
                _df = _df.drop(columns=secret_cols, errors='ignore')
                _df.to_excel(writer, sheet_name=f'{obj}.data', index=False)
    
    writer.close()
    print(f"save {Path(excel_file).name}")

def get_pools_by_rule(**kwargs):
    rule = kwargs.get('rule')
    df = kwargs.get('df')
    rule_text = df.loc[df['fullPath'] == rule, 'apiAnonymous'].iloc[0]
    pools = re.findall(r'^ +pool (/.+)$', rule_text, flags=re.MULTILINE)
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
    dns.drop(['pools'], axis=1, inplace=True)
    
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
    ltm.to_csv(p1_file, index=False)
    print(f"save {Path(p1_file).name}")

def get_f5_data(**kwargs):
    devs = kwargs.get('devs')
    data_dir = kwargs.get('dir')   
    for dev in devs:
        fname = fr'{dev}.xlsx'
        if file_up_to_date(file=data_dir + fr'\{fname}'):
            print(f"{fname} up to date")
            continue
        token = get_token(dev, user=svc_usr, pwd=svc_pwd, debug=True)
        if token and token[0] != '{':
            if '-ltm-' in dev:
                get_f5_info_func = get_ltm_info         
            else:
                assert '-gtm-' in dev
                get_f5_info_func = get_gtm_info
            get_f5_info_func(dev=dev, token=token, dir=data_dir)

def process_f5_data(**kwargs):
    data_dir = kwargs.get('dir')
    devs = kwargs.get('devs')
    pending_devs = []
    for dev in devs:
        excel_file = data_dir + fr"\{dev}.xlsx"
        if os.path.exists(excel_file):
            if '-ltm-' in dev:
                process_func = process_ltm_info_p1 
            else:
                assert '-gtm-' in dev
                process_func = process_gtm_info_p1 
            try:
                process_func(dev=dev, dir=data_dir)
            except Exception as e:
                my_logger.info(f'{dev}: {e}')
        else:
            pending_devs.append(dev)
            my_logger.info(f"no {excel_file}")
    return pending_devs

def get_all_f5_ip(**kwargs):
    data_dir = kwargs.get('data_dir')
    cols = ['f5', 'type', 'name', 'ip', 'protocol', 'port']
    f5_ip_df = pd.DataFrame(columns=cols)
    for f in glob(data_dir + fr'\*.xlsx'):
        f5 = Path(f).name.split('.')[0]
        if '-ltm-' in f5:
            try:
                df = pd.read_excel(f, sheet_name='self')[['fullPath', 'address']].rename(columns={'fullPath': 'name', 'address': 'ip'})
                df['ip'] = df['ip'].apply(lambda x: x.split('/')[0].split('%')[0])
                df = df.assign(f5=f5, type='self', protocol='', port='')
                f5_ip_df = pd.concat([f5_ip_df, df])
            except Exception as e:
                my_logger.info(f'{f}: {e}')
    
    for f in glob(data_dir + fr'\*.p1.csv'):
        f5 = Path(f).name.split('.')[0]
        try:
            if '-ltm-' in f5:
                df = pd.read_csv(f).rename(columns={'vs': 'name'}).sort_values(by='name').drop_duplicates()
                df = df[[col for col in cols if col in df.columns]]
                df['ip'] = df['ip'].apply(lambda x: x.split('%')[0])
                df = df.assign(f5=f5, type='vs')
                f5_ip_df = pd.concat([f5_ip_df, df])
        except Exception as e:
            my_logger.info(f'{f}: {e}')
    
    if len(f5_ip_df):
        f5_ip_df.to_excel(data_dir + fr'\mddr.f5.xlsx', index=False)
    
    return f5_ip_df

def f5_job(**kwargs):
    global data_dir, my_logger, svc_usr, svc_pwd
    svc_usr, svc_pwd = get_svc_cred(file=cred_dir + fr'\{svc_cred_file}')
    if not all([svc_usr, svc_pwd]):
        return

    my_logger = f5_cfg.my_logger
    kwargs['source'] = data_type
    data_dir = mk_day_dir(**kwargs)
    my_logger.info(f'\nstart: {datetime.now().replace(microsecond=0)}')
    get_f5_data(dir=data_dir, devs=f5_working_list)
    process_f5_data(dir=data_dir, devs=f5_working_list)
    get_all_f5_ip(data_dir=data_dir)
    my_logger.info(f'end: {datetime.now().replace(microsecond=0)}')

if __name__ == '__main__':
    """
    svc_usr, svc_pwd = get_svc_cred(file=cred_dir + fr'\{svc_cred_file}')
    my_logger = f5_cfg.my_logger
    data_dir = mk_day_dir(source='F5')
    f5_working_list = ['f5_1']
    get_f5_data(dir=data_dir, devs=f5_working_list)
    """
    f5_job()
