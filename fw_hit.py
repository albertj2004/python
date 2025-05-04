import os
import re
import gzip
import pandas as pd
import wexpect
from pathlib import Path
import ipaddress
from getpass import getpass
from ntc_templates.parse import parse_output
from common_cfg import *
from common_utils import *
import fw_hit_cfg
from fw_hit_cfg import *

data_dir = None
my_logger = None
svc_usr, svc_pwd = None, None

def get_fw_hit_cnt(**kwargs):
    fw_ip_list = kwargs.get('fw_ip_list')
    for fw, ip in fw_ip_list:
        try:
            print(f'{fw} start')
            fname = data_dir + fr'\{fw}.gz'
            if file_up_to_date(file=fname):
                print(f"{Path(fname).name} up to date")
                continue

            cmds = cmds_template.substitute(pwd=rsa_pin + getpass('RSA Token(6):'), fw=fw, enable_pwd=enable_pwd)
            expect_send_list = [line.strip() for line in cmds.strip().split('\n')]
            child = wexpect.spawn(f'{putty_exe} -P 22 {usr}@{ip}')
            cmd_state = 'expect'
            timeout = timeout_short
            for line in expect_send_list:
                if cmd_state == 'expect':
                    child.expect(line, timeout=timeout)
                    cmd_state = 'send'
                else:
                    child.sendline(line)
                    cmd_state = 'expect'
                    timeout = timeout_long if line in ['show access-list'] else timeout_short

            with gzip.open(fname, "wt") as f:
                f.write(child.before)
            child.sendline('exit')
            child.wait()
        except Exception as e:
            my_logger.info(f'{fw}:\n{e}')

def get_acl_output(txt):
    m = re.search(acl_start_regex, txt)
    assert m
    acl_name = m.group('name')
    acl_output_regex = fr"^access-list {acl_name} line \d+ .+hitcnt=\d+.+$"
    acl_output = '\n'.join(re.findall(acl_output_regex, txt, flags=re.MULTILINE))
    return acl_output

def parse_dev_info(**kwargs):
    data_dir = kwargs.get('dir')
    dev = kwargs.get('dev')
    cmd = kwargs.get('cmd')
    fsuffix = kwargs.get('suffix', cmd)
    fname = data_dir + fr'\{dev}.{fsuffix}.xlsx'
    if os.path.exists(fname):
        return
    dev_os = kwargs.get('dev_os')
    info_file = f'{dev}.gz'
    info_file = data_dir + fr"\{info_file}"
    with gzip.open(info_file, "rt") as f:
        info = f.read()
    info = get_acl_output(info)     
    my_logger.info(f"{dev} start:")
    try:
        pd.DataFrame(parse_output(platform=dev_os, command=cmd, data=info))[fw_acl_hit_cols].to_excel(fname, index=False)
    except Exception as e:
        my_logger.info(f"{dev}:\n{e}")
    
def parse_fw_sh_acl_all(**kwargs):
    data_dir = kwargs.get('dir')
    fw_list = kwargs.get('fw_list')
    cmd = 'show access-list'
    kwargs_list = []
    for fw in fw_list:
        kwargs_list.append({'dir': data_dir, 'dev': fw, 'dev_os': 'cisco_asa', 'cmd': cmd, 'suffix': 'acl.hit'})
    parallel_func(func=parse_dev_info, kwargs=kwargs_list, max_worker=len(fw_list))

def explode_csm_fw_rule(**kwargs):
    func = 'explode_csm_fw_rule'
    data_dir = kwargs.get('dir')
    dev = kwargs.get('dev')
    out_fname = data_dir + fr"\{dev}.csm.p0.explode.xlsx"
    if file_up_to_date(file=out_fname):
        my_logger.info(f"{Path(out_fname).name} up to date")
        return

    fname = fr"{dev}.DeviceAccessRuleUnifiedFirewallPolicy.p0.xlsx"
    df = pd.read_excel(data_dir + fr"\{fname}", "policy")
    df = df[df['isEnabled'] == True]
    cols = ['sources', 'destinations', 'services']
    for col in cols:
        df[col] = df[col].apply(lambda x: x if type(x) is list else eval(x))
        df = df.explode(col)
    df.to_excel(out_fname, index=False)
    print(f'{dev, func} completed')

def service_2_protocol_svc(row):
    service = row['services']
    protocol, port = '', ''
    if service in svc_protocol_port_map.keys():
        protocol, port = svc_protocol_port_map[service]
    else:
        if re.fullmatch(r'^(tcp|udp) \d+$', service):
            protocol, port = service.split(' ')
            k = protocol + ':' + port
            if k in protocol_port_svc_map.keys():
                port = protocol_port_svc_map[k]
        elif re.fullmatch(r'^(tcp|udp) (\d+)-(\d+)$', service):
            protocol, port_range = service.split(' ')
            port_start, port_end = port_range.split('-')
            k = protocol + ':' + port_start
            if k in protocol_port_svc_map.keys():
                port_start = protocol_port_svc_map[k]
            k = protocol + ':' + port_end
            if k in protocol_port_svc_map.keys():
                port_end = protocol_port_svc_map[k]
            port = port_start + '-' + port_end
        else:
            port = service
    return pd.Series([protocol, port])

def net_obj_2_fw_cfg(**kwargs):
    net_obj = kwargs.get('net_obj')
    full_flag = kwargs.get('full_flag', True)
    if re.fullmatch(r'(\d+.){3}\d+/\d+', net_obj):
        ip_net = ipaddress.IPv4Network(net_obj, strict=False)
        info = f"{ip_net.network_address} {ip_net.netmask}"
    elif re.fullmatch(r'(\d+.){3}\d+', net_obj):
        if full_flag:
            info = "host " + net_obj
        else:
            info = net_obj
    else:
        if full_flag:
            info = "object.* " + re.escape(net_obj)
        else:
            info = net_obj
    return info

def net_obj_2_cfg(net_obj, **kwargs):
    full_flag = kwargs.get('full_flag', True)
    if net_obj in net_obj_map.keys():
        cfg = net_obj_map[net_obj]
    else: 
        cfg = net_obj_2_fw_cfg(net_obj=net_obj, full_flag=full_flag)
    return cfg
    
def map_explode_csm_fw_rule_2_cfg(**kwargs):
    func = 'map_explode_csm_fw_rule_2_cfg'
    data_dir = kwargs.get('dir')
    dev = kwargs.get('dev')
    out_fname = data_dir + fr"\{dev}.csm.p0.explode.2.cfg.xlsx"
    if file_up_to_date(file=out_fname):
        my_logger.info(f"{Path(out_fname).name} up to date")
        return
        
    fname = fr"{dev}.csm.p0.explode.xlsx"
    df = pd.read_excel(data_dir + fr"\{fname}")
    df['sources'] = df['sources'].apply(net_obj_2_cfg, full_flag=False, axis=1)
    df['destinations'] = df['destinations'].apply(net_obj_2_cfg, full_flag=False, axis=1)
    df[['protocol', 'svc']] = df.apply(service_2_protocol_svc, axis=1)
    df = df.explode('protocol')
    df.to_excel(out_fname, index=False)
    print(f'{dev, func} completed')

def concat_svc(row):
    port_start = row['dst_port_range_start']
    if port_start:
        port_end = row['dst_port_range_end']
        result = f"{port_start}-{port_end}"
    else:
        result = ''.join(row)
    return result

def concat_src(row):    	
    nw = row['src_network']
    if nw:        
        result = f"{nw} {row['src_mask']}"
    else:
        result = ''.join(row)
    return result

def concat_dst(row):	
    nw = row['dst_network']
    if nw:        
        result = f"{nw} {row['dst_mask']}"
    else:
        result = ''.join(row)
    return result

def concat_hit_file_src_dst_svc(**kwargs):
    func = 'concat_hit_file_src_dst_svc'
    data_dir = kwargs.get('dir')
    dev = kwargs.get('dev')
    out_fname = data_dir + fr"\{dev}.acl.hit.2.rule.xlsx"
    if file_up_to_date(file=out_fname):
        my_logger.info(f"{Path(out_fname).name} up to date")
        return

    fname = fr"{dev}.acl.hit.xlsx"
    df = pd.read_excel(data_dir + fr"\{fname}", dtype=str)
    svc_dst_cols = ['dst_port', 'dst_port_range_start', 'dst_port_range_end', 'dst_port_grp', 'dst_port_object', 'dst_icmp_type']
    src_cols = [col for col in df.columns if 'src' in col]
    dst_cols = list(set([col for col in df.columns if 'dst' in col]) - set(svc_dst_cols))
    svc_cols = [col for col in df.columns if 'svc' in col] + svc_dst_cols
    df['sources'] = df[src_cols].fillna('').apply(concat_src, axis=1)
    df['destinations'] = df[dst_cols].fillna('').apply(concat_dst, axis=1)
    df['svc'] = df[svc_cols].fillna('').apply(concat_svc, axis=1)    
    df.to_excel(out_fname, index=False)
    print(f'{dev, func} completed')

def concat_explode_csm_fw_rule_cfg_n_hit(**kwargs):
    func = 'concat_explode_csm_fw_rule_cfg_n_hit'
    data_dir = kwargs.get('dir')     
    dev = kwargs.get('dev')
    
    out_fname = data_dir + fr"\{dev}.hit.vs.csm.xlsx"
    if file_up_to_date(file=out_fname):
        my_logger.info(f"{Path(out_fname).name} up to date")
        return

    csm_2_hit_file = fr"{dev}.csm.p0.explode.2.cfg.xlsx"
    csm_2_hit_df = pd.read_excel(data_dir + fr"\{csm_2_hit_file}")
    hit_2_rule_file = fr"{dev}.acl.hit.2.rule.xlsx"
    hit_2_rule_df = pd.read_excel(data_dir + fr"\{hit_2_rule_file}")
    
    match_cols = ['sources', 'destinations', 'protocol', 'svc']
    cols = ['line_num'] + match_cols + ['hit_count', 'action']

    df = pd.merge(csm_2_hit_df[match_cols + ['gid']], hit_2_rule_df[cols], on=match_cols, how='right')
    df[['gid', 'line_num'] + match_cols + ['hit_count', 'action']].to_excel(out_fname, index=False)
    print(f'{dev, func} completed')

def get_acl_output(txt):
    m = re.search(acl_start_regex, txt)
    assert m
    acl_name = m.group('name')
    acl_output_regex = fr"^access-list {acl_name} line \d+ .+hitcnt=\d+.+$"
    acl_output = '\n'.join(re.findall(acl_output_regex, txt, flags=re.MULTILINE))
    return acl_output

def parse_dev_info(**kwargs):
    data_dir = kwargs.get('dir')
    dev = kwargs.get('dev')
    cmd = kwargs.get('cmd')
    fsuffix = kwargs.get('suffix', cmd)
    fname = data_dir + fr'\{dev}.{fsuffix}.xlsx'
    if file_up_to_date(file=fname):
        my_logger.info(f"{Path(fname).name} up to date")
        return
    dev_os = kwargs.get('dev_os')
    info_file = f'{dev}.txt'
    info_file = data_dir + fr"\{info_file}"
    info = file2str(file=info_file)   
    info = get_acl_output(info)     
    my_logger.info(f"{dev} start:")
    try:
        pd.DataFrame(parse_output(platform=dev_os, command=cmd, data=info))[fw_acl_hit_cols].to_excel(fname, index=False)
    except Exception as e:
        my_logger.info(f"{dev}:\n{e}")

def hitcnt_pipeline(**kwargs):
    dev = kwargs.get('dev')
    data_dir = kwargs.get('dir')
    concat_hit_file_src_dst_svc(dir=data_dir, dev=dev)
    explode_csm_fw_rule(dir=data_dir, dev=dev)
    map_explode_csm_fw_rule_2_cfg(dir=data_dir, dev=dev)
    concat_explode_csm_fw_rule_cfg_n_hit(dir=data_dir, dev=dev)
    
def check_result_up_to_date(**kwargs):
    data_dir = kwargs.get('dir')
    devs = kwargs.get('devs')
    result = True
    for dev in devs:
        if not file_up_to_date(file=data_dir + fr'\{dev}.acl.hit.xlsx'):
            result = False
            break
    return result
    
def fw_hit_job(**kwargs):
    if not check_result_up_to_date(dir=data_dir, devs=fw_list):
        svc_usr, svc_pwd, enable_pwd = get_svc_cred(file=cred_dir + fr'\{svc_cred_file}', enable_pwd_flag=True)
        if all([svc_usr, svc_pwd, enable_pwd]):
            get_fw_hit_cnt(fw_ip_list=fw_ip_list)
            parse_fw_sh_acl_all(fw_list=fw_list, dir=data_dir, suffix='acl.hit')
            kwargs_list = [{'dir': data_dir, 'dev': fw, 'suffix': 'acl.hit'} for fw in fw_list]
            parallel_func(func=hitcnt_pipeline, kwargs=kwargs_list, max_worker=len(fw_list))

if __name__ == '__main__':
    rsa_pin = getpass('RSA PIN(4):')
    my_logger.info(f'\nstart: {datetime.now().replace(microsecond=0)}')
    fw_hit_job()
    my_logger.info(f'end: {datetime.now().replace(microsecond=0)}')

