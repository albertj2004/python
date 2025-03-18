import re
import os
from glob import glob
import shutil
import getpass
import requests
import xmltodict
from time import sleep
from pathlib import Path
from math import ceil
import pandas as pd
from datetime import datetime, timedelta
import urllib3
from common_utils import file_up_to_date, set_logger, file2str, str2file, run_task
import csm_cfg
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

my_logger = None
exit_flag = False
session = None
cookie = ''
max_policy_rules = 500
excel_cell_text_lmt = 32767
dev_exclude_regex = r'[_-](sys|admin|prd)(_|-|$)'  # (fss|ps|rits|swf)
# policy_list = ['DeviceAccessRuleUnifiedFirewallPolicy']
policy_obj_types = [
    'NetworkPolicyObject', 
    'ServicePolicyObject', 
    'PortListPolicyObject', 
    'InterfaceRolePolicyObject',
    'IdentityUserGroupPolicyObject',
    'TimeRangePolicyObject',
    'SecurityGroupPolicyObject',
    ]

def get_policy_types():
    policy_type_str = """
    DeviceAccessRuleFirewallPolicy Used to configure ACLs.
    DeviceAccessRuleUnifiedFirewallPolicy Used to configure Unified ACLs.
    DeviceBGPRouterPolicy Routing protocol.
    DeviceNATTimeoutsRouterPolicy Used for configuring Router NAT.
    DeviceNATTransOptionsFirewallPolicy Used for configuring Firewall NAT.
    DeviceStaticRoutingFirewallPolicy Used for configuring Firewall NAT.
    DeviceStaticRoutingRouterPolicy Used in configuring Router static route.
    InterfaceNAT64ManualFirewallPolicy Used for configuring NAT64 policy
    InterfaceNATAddressPoolFirewallPolicy Used for configuring Firewall NAT.
    InterfaceNATDynamicRulesFirewallPolicy Used for configuring Firewall NAT.
    InterfaceNATDynamicRulesRouterPolicy Used for configuring Router NAT.
    InterfaceNATManualFirewallPolicy Used for configuring Firewall NAT.
    InterfaceNATObjectFirewallPolicy Used for configuring Firewall NAT.
    InterfaceNATPolicyDynamicRulesFirewallPolicy Used for configuring Firewall NAT.
    InterfaceNATRouterPolicy Used for configuring Router NAT.
    InterfaceNATStaticRulesFirewallPolicy Used for configuring Firewall NAT.
    InterfaceNATStaticRulesRouterPolicy Used for configuring Router NAT.
    InterfaceNATTransExemptionsFirewallPolicy Used for configuring Firewall NAT.
    """
    return re.findall(r"^ *(\w+)", policy_type_str, flags=re.MULTILINE)

def init_session(**kwargs):
    global session
    csm = kwargs.get('csm')
    headers = {
        "Host": csm,
        'Content-Type': 'application/xml', 
        'Accept': 'application/xml', 
    }
    session = requests.Session()
    session.headers.update(headers)

def csm_post(**kwargs):
    global session
    retry = kwargs.get('retry', 0)
    debug = kwargs.get('debug', False)
    code_flag = kwargs.get('code_flag', False)
    save_cookie = kwargs.get('save_cookie', False)
    cookie_file = kwargs.get('cookie_file', 'cookie.txt')
    csm = kwargs.get('csm', csm_cfg.csm)
    svc = kwargs.get('svc', 'configservice')  # utilservice 
    url_func = kwargs.get('url_func')
    if svc:
        _url = kwargs.get('url', f"https://{csm}/nbi/{svc}/{url_func}")
    else:  # login/logout
        _url = kwargs.get('url', f"https://{csm}/nbi/{url_func}")
    xml_func = kwargs.get('xml_func', url_func)
    xml_args = kwargs.get('xml_args', '')
    startIndex = kwargs.get('startIndex', 0)
    if startIndex:
        xml_args = f"<startIndex>{startIndex}</startIndex>{xml_args}"
    _xml = f"""
    <?xml version="1.0" encoding="UTF-8"?>
    <csm:{xml_func} xmlns:csm="csm">
    <protVersion>1.0</protVersion>
    <reqId>123</reqId>
    {xml_args}
    </csm:{xml_func}>
    """
    _xml = '\n'.join([line.strip() for line in _xml.strip().split('\n')])
    if debug:
        print(_url)
        print(_xml)
    result = ''

    try:
        for i in range(retry + 1):        
            response = session.post(_url, data=_xml, verify=False)
            result = response.text
            response_code = response.status_code
            if response_code == 200:
                print(f"\n{url_func} successful!")
                if save_cookie:
                    cookie = response.cookies.get_dict()['asCookie']
                    print(f"cookie: {cookie}")
                    str2file(file=cookie_file, str=cookie)
            else:
                my_logger.info(f"\n{url_func} failed: {response_code}")
                my_logger.info(result)
            
            if not retry or "<error>" not in result or i + 1 > retry:
                break
            my_logger.info(f"Retry after error: {i + 1}")

    except Exception as e:
        my_logger.info(f"Error occurred during {url_func}: {e}")

    if code_flag:
        if response_code == 200:
            return True
        else:
            return False
    else:
        return result

def csm_ping(**kwargs):
    global session, cookie
    cookie_file = kwargs.get('cookie_file', 'cookie.txt')
    cookie_file = Path(cookie_file)
    if os.path.exists(cookie_file):
        file_cookie = file2str(file=cookie_file)
        if file_cookie != cookie:
            cookie = file_cookie
            print(f'\nLoad cookie from file: {cookie}')
    else:
        if cookie:
            str2file(str=cookie, file=cookie_file)
            print(f'\nSave cookie to file: {cookie}')
        else:
            print('\nNo cookie')
            return False
    
    init_session(**kwargs)
    print(f"add cookie to session: {cookie}")
    csm = kwargs.get('csm')
    session.cookies.set('asCookie', cookie, path='/', domain=f'{csm}.local')        
    
    url_func = 'ping'
    xml_func = 'pingRequest'
    return csm_post(svc='', url_func=url_func, xml_func=xml_func, code_flag=True)

def csm_Login(**kwargs):
    init_session(**kwargs)
    cookie_file = kwargs.get('cookie_file')
    url_func = 'login'
    xml_func = 'loginRequest'
    xml_args = f"""
    <username>{getpass.getuser()}</username>
    <password>{getpass.getpass("RSA PIN+Token:")}</password>
    """.strip()
    return csm_post(svc='', url_func=url_func, xml_func=xml_func, xml_args=xml_args, code_flag=True, save_cookie=True, cookie_file=cookie_file)

def csm_Logout(**kwargs):
    if csm_ping(**kwargs):
        url_func = 'logout'
        xml_func = 'logoutRequest'
        csm_post(svc='', url_func=url_func, xml_func=xml_func, code_flag=True)

def csm_keep_alive(**kwargs):
    if not csm_ping(**kwargs):
        csm_Login(**kwargs)
    t_now = datetime.now().replace(microsecond=0)
    print(f"{str(t_now)}")
    next_t_1m = t_now.replace(second=0) + timedelta(minutes=1)
    sleep_sec = (next_t_1m - t_now).seconds
    sleep(sleep_sec)
    while True:
        if exit_flag:
            csm_Logout()
            break
        
        sleep(600)
        t_now = datetime.now().replace(microsecond=0)
        my_logger.info(f"{str(t_now)}")
        if not csm_ping(**kwargs):
            break

def csm_GetServiceInfo():
    url_func = 'GetServiceInfo'
    xml_func = 'getServiceInfoRequest'
    return csm_post(url_func=url_func, xml_func=xml_func)

def csm_GetGroupList(**kwargs):
    retry = kwargs.get('retry', 3)
    url_func = 'getGroupList'
    xml_func = 'groupListRequest'
    xml_args = '<includeEmptyGroups>false</includeEmptyGroups>'
    return csm_post(url_func=url_func, xml_func=xml_func, xml_args=xml_args, retry=retry)
    
def csm_GetDeviceListByCapability(**kwargs):
    retry = kwargs.get('retry', 3)
    url_func = 'getDeviceListByType'
    xml_func = 'deviceListByCapabilityRequest'
    dev_cap = kwargs.get('dev_cap', '*')  # firewall, ids, router, switch
    xml_args = f'<deviceCapability>{dev_cap}</deviceCapability>'
    return csm_post(url_func=url_func, xml_func=xml_func, xml_args=xml_args, retry=retry)

def csm_GetDeviceListByGroup(**kwargs):
    url_func = 'getDeviceListByGroup'
    xml_func = 'deviceListByGroupRequest'
    grp_path = kwargs.get('grp_path')
    item_str = ''
    for item in grp_path.split('/'):
        item_str += f'<pathItem>{item}</pathItem>'
    xml_args = f"<deviceGroupPath>{item_str}</deviceGroupPath>"
    return csm_post(url_func=url_func, xml_func=xml_func, xml_args=xml_args)

def csm_ExecDeviceReadOnlyCLICmds(**kwargs):  # no authorization
    dev = kwargs.get('dev')
    sh_cmd = kwargs.get('sh_cmd', 'version')
    svc = 'utilservice'
    url_func = 'execDeviceReadOnlyCLICmds'
    xml_func = 'execDeviceReadOnlyCLICmdsRequest'
    xml_args = f"""<deviceReadOnlyCLICmd>
    <deviceName>{dev}</deviceName>
    <cmd>show</cmd>
    <argument>{sh_cmd}</argument>
    </deviceReadOnlyCLICmd>"""
    return csm_post(svc=svc, url_func=url_func, xml_func=xml_func, xml_args=xml_args)

def csm_GetDeviceConfigByGID(**kwargs):  # no authorization
    gid = kwargs.get('gid')
    url_func = 'getDeviceConfigByGID'
    xml_func = 'deviceConfigByGIDRequest'
    xml_args = f'<gid>{gid}</gid>'
    return csm_post(url_func=url_func, xml_func=xml_func, xml_args=xml_args)

def csm_GetDeviceConfigByName(**kwargs):  # no authorization
    dev = kwargs.get('dev')
    url_func = 'getDeviceConfigByName'
    xml_func = 'deviceConfigByNameRequest'
    xml_args = f'<name>{dev}</name>'
    return csm_post(url_func=url_func, xml_func=xml_func, xml_args=xml_args)

def csm_GetPolicyListByDeviceGID(**kwargs):  # all types
    url_func = 'getPolicyListByDeviceGID'
    xml_func = 'policyListByDeviceGIDRequest'
    gid = kwargs.get('gid')
    xml_args = f'<gid>{gid}</gid>'
    return csm_post(url_func=url_func, xml_func=xml_func, xml_args=xml_args)

def csm_GetPolicyConfigByName(**kwargs):  # policy name, not dev name
    url_func = 'getPolicyConfigByName'
    xml_func = 'policyConfigByNameRequest'
    policy_name = kwargs.get('policy_name')
    policy_type = kwargs.get('policy_type', 'DeviceAccessRuleFirewallPolicy')
    xml_args = f'<name>{policy_name}</name><policyType>{policy_type}</policyType>'
    return csm_post(url_func=url_func, xml_func=xml_func, xml_args=xml_args)

def csm_GetPolicyConfigByDeviceGID(**kwargs):  # dev gid + policy type
    url_func = 'getPolicyConfigById'
    xml_func = 'policyConfigByDeviceGIDRequest'
    debug = kwargs.get('debug', False)
    gid = kwargs.get('gid')
    policy_type = kwargs.get('policy_type','DeviceAccessRuleUnifiedFirewallPolicy')
    startIndex = kwargs.get('startIndex', 0)
    xml_args = f'<gid>{gid}</gid><policyType>{policy_type}</policyType>'
    return csm_post(url_func=url_func, xml_func=xml_func, xml_args=xml_args, startIndex=startIndex, debug=debug)

def csm_GetSharedPolicyNamesByType(**kwargs):
    url_func = 'getSharedPolicyListByType'
    xml_func = 'policyNamesByTypeRequest'
    policy_type = kwargs.get('policy_type')
    xml_args = f'<policyType>{policy_type}</policyType>'
    return csm_post(url_func=url_func, xml_func=xml_func, xml_args=xml_args)

def obj_type_name_2_xml_args(obj_type_names):
    xml_args = ''
    for obj_type, obj_name_list in obj_type_names.items():
        obj_name_str = ''
        for obj_name in obj_name_list:
            obj_name_str += f'<name>{obj_name}</name>'
        xml_args += f'<{obj_type}>{obj_name_str}</{obj_type}>'
    return xml_args

def csm_GetPolicyObject(**kwargs):
    url_func = 'getPolicyObject'
    xml_func = 'getPolicyObjectRequest'
    obj_type_names = kwargs.get('obj_type_names')  # {'networkPolicyObject': ['obj1', 'obj2']}
    xml_args = obj_type_name_2_xml_args(obj_type_names)
    return csm_post(url_func=url_func, xml_func=xml_func, xml_args=xml_args)

def csm_GetPolicyObjectByGID(**kwargs):
    url_func = 'getPolicyObjectByGID'
    xml_func = 'getPolicyObjectByGID'
    obj_gid_list = kwargs.get('obj_gid_list')
    xml_args = ''
    for obj_gid in obj_gid_list:
        xml_args += f'<gid>{obj_gid}</gid>'
    return csm_post(url_func=url_func, xml_func=xml_func, xml_args=xml_args)

def csm_GetPolicyObjectsListByType(**kwargs):
    url_func = 'getPolicyObjectsListByType'
    xml_func = 'policyObjectsListByTypeRequest'
    obj_type = kwargs.get('obj_type')
    xml_args = f'<policyObjectType>{obj_type}</policyObjectType>'
    return csm_post(url_func=url_func, xml_func=xml_func, xml_args=xml_args)

def csm_GetHitcountDetailsByGID(**kwargs):
    url_func = 'getHitcountDetailsByGID'
    xml_func = 'hitCountRequest'
    dev_gid = kwargs.get('dev_gid')
    policy_type = kwargs.get('policy_type', 'DeviceAccessRuleUnifiedFirewallPolicy')
    policy_rule_gid_list = kwargs.get('policy_rule_gid_list')
    policy_rules_str = ''
    for policy_rule_gid in policy_rule_gid_list[:max_policy_rules]:
        policy_rules_str += f"<policyRuleGID>{policy_rule_gid}</policyRuleGID>"
    xml_args = f"""
    <deviceGID>{dev_gid}</deviceGID>
    <policyType>{policy_type}</policyType>
    """ + policy_rules_str
    return csm_post(url_func=url_func, xml_func=xml_func, xml_args=xml_args)

def xml2df(**kwargs):
    xml_file = kwargs.get('xml_file')
    save_csv = kwargs.get('save_csv', True)
    csv = kwargs.get('csv', xml_file[:-3] + 'csv')
    xpath = kwargs.get('xpath')
    ns = kwargs.get('ns', {'ns1':'csm'})
    df = pd.read_xml(xml_file, xpath=xpath, namespaces=ns)
    if save_csv:
        df.to_csv(csv, index=False)
    return df

# xml2df(xml_file='csm_group_list.xml', xpath="//deviceGroup", ns={'ns1':'csm'}, csv='csm_group_list.csv')
# xml2df(xml_file='csm_device_list.xml', xpath="//deviceId")

def csm_get_group_dev_list(**kwargs):
    data_dir = kwargs.get('dir')
    cmd_list = [
        (csm_GetGroupList, data_dir + fr'\csm.groups.xml'),
        (csm_GetDeviceListByCapability, data_dir + fr'\csm.devices.xml'),
    ]
    
    for func, fname in cmd_list:
        if file_up_to_date(file=fname):
            print(f"{Path(fname).name} up to date")
            continue
        
        str2file(file=fname, str=func())

def csm_get_all_shared_policy(**kwargs):  # policy name / dev map
    data_dir = kwargs.get('dir')
    policy_types = get_policy_types()
    for policy_type in policy_types:
        result = csm_GetSharedPolicyNamesByType(policy_type=policy_type)
        if 'baseError' not in result:
            fname = data_dir + fr'\csm.{policy_type}.xml'
            str2file(file=fname, str=result)

def csm_get_dev_policy(**kwargs):
    data_dir = kwargs.get('dir')
    dev = kwargs.get('dev')
    gid = kwargs.get('gid')
    result = csm_GetPolicyListByDeviceGID(gid=gid)
    xml_file = fr'{data_dir}\{dev}.policy.xml'
    str2file(file=xml_file, str=result)
    if ' failed:' in result:
        my_logger.info(f"\n{dev} policy error")
        return
    
    with open(xml_file) as fd:
        doc = xmltodict.parse(fd.read(), process_namespaces=True)
    
    dev_policy_dict = doc['csm:policyListDeviceResponse']['policyList']
    if not dev_policy_dict or 'policyDesc' not in dev_policy_dict.keys():
        my_logger.info(f"\n{dev} no policy")
        return
    
    dev_policy_items = dev_policy_dict['policyDesc']
    if type(dev_policy_items) is dict:
        dev_policy_items = [dev_policy_items]
    df = pd.DataFrame(dev_policy_items)
    dev_policy_types = df['type'].tolist()
    print(f"\n{dev} policy types:\n{dev_policy_types}")
    
    for policy_type in dev_policy_types:
        # if policy_type in policy_list:
        page = 0
        startIndex = 0
        fname = data_dir + fr'\{dev}.{policy_type}.{page}.xml'
        if file_up_to_date(file=fname):
            print(f"{Path(fname).name} up to date")
            continue
        while True:
            result = csm_GetPolicyConfigByDeviceGID(gid=gid, policy_type=policy_type, startIndex=startIndex)
            doc = xmltodict.parse(result, process_namespaces=True)
            reply = doc['csm:policyConfigDeviceResponse']
            if 'endIndex' in reply.keys():
                str2file(file=fname, str=result)
                page += 1
                startIndex = reply['endIndex']
                fname = data_dir + fr'\{dev}.{policy_type}.{page}.xml'
            else:
                str2file(file=fname, str=result)
                break

def csm_get_all_policy_objects(**kwargs):
    data_dir = kwargs.get('dir')
    for policy_obj_type in policy_obj_types:
        result = csm_GetPolicyObjectsListByType(obj_type=policy_obj_type)
        fname = data_dir + fr'\csm.{policy_obj_type}.xml'
        str2file(file=fname, str=result)

def csm_devices_2_df(**kwargs):
    debug = kwargs.get('debug', False)
    xml_file = kwargs.get('xml_file')
    csv_file = kwargs.get('csv', xml_file[:-3] + 'csv')
    with open(xml_file) as fd:
        doc = xmltodict.parse(fd.read(), process_namespaces=True)
    _list = doc['csm:deviceListResponse']['deviceId']
    df = pd.DataFrame(_list)
    df.to_csv(csv_file, index=False)
    print(f'{Path(xml_file).name} -> {Path(csv_file).name}')
    return df

def csm_groups_2_df(**kwargs):
    save_csv = kwargs.get('save_csv', True)
    debug = kwargs.get('debug', False)
    xml_file = kwargs.get('xml_file')
    csv_file = kwargs.get('csv', xml_file[:-3] + 'csv')
    with open(xml_file) as fd:
        doc = xmltodict.parse(fd.read(), process_namespaces=True)
    L2_list = doc['csm:groupListResponse']['deviceGroup']['deviceGroup']
    df = pd.DataFrame()
    assert type(L2_list) is list
    for L2_item in L2_list:
        assert type(L2_item) is dict
        for L2_item_k, L2_item_v in L2_item.items():
            if L2_item_k in ['gid']:
                L2_gid = L2_item_v
                if debug:
                    print(L2_item_k, L2_item_v)
            if L2_item_k in ['path']:
                L2_path = L2_item_v
                if debug:
                    print(L2_item_k, L2_item_v)
            if L2_item_k in ['deviceGroup']:
                if type(L2_item_v) is dict:
                    L3_list = [L2_item_v]
                else:
                    type(L2_item_v) is list
                    L3_list = L2_item_v
                for L3_item in L3_list:
                    assert type(L3_item) is dict
                    for L3_item_k, L3_item_v in L3_item.items():
                        if L3_item_k in ['gid']:
                            L3_gid = L3_item_v
                            if debug:
                                print(L3_item_k, L3_item_v)
                        if L3_item_k in ['path']:
                            L3_path = L3_item_v
                            if debug:
                                print(L3_item_k, L3_item_v)
                        if L3_item_k in ['deviceGroup']:
                            if type(L3_item_v) is list:
                                L4_list = L3_item_v
                            else:
                                assert type(L3_item_v) is dict
                                L4_list = [L3_item_v]
                            for L4_item in L4_list:
                                assert type(L4_item) is dict
                                for L4_item_k, L4_item_v in L4_item.items():
                                    if L4_item_k in ['gid']:
                                        L4_gid = L4_item_v
                                        if debug:
                                            print(L4_item_k, L4_item_v)
                                    if L4_item_k in ['path']:
                                        L4_path = L4_item_v
                                        if debug:
                                            print(L4_item_k, L4_item_v)
                                    if L4_item_k in ['device']:
                                        L5_list = L4_item_v
                                        assert type(L5_list) is list

                                        dev_df = pd.DataFrame(L5_list)
                                        dev_df[['L2_gid', 'L2_path', 'L3_gid', 'L3_path','L4_gid', 'L4_path']] = L2_gid, L2_path, L3_gid, L3_path, L4_gid, L4_path
                                        dev_df['L2_gid'] = L2_gid
                                        df = pd.concat([df, dev_df])                                    
                                        """                    
                                        for L5_item in L5_list:
                                            assert type(L5_item) is dict
                                            for L5_item_k, L5_item_v in L5_item.items():
                                                if L5_item_k in ['gid', 'name']:
                                                    if debug:
                                                        my_logger.info(L5_item_k, L5_item_v)
                                        """
                                        # my_logger.info('\n')
                                if debug:
                                    print('\n')
                            # my_logger.info('\n')
                    # my_logger.info('\n')
                # my_logger.info('\n')
        if debug:
            print('\n')
    
    if save_csv:
        df.to_csv(csv_file, index=False)
        print(f'{Path(xml_file).name} -> {Path(csv_file).name}')
    return df

def csm_obj_2_df(**kwargs):
    debug = kwargs.get('debug', False)
    xml_file = kwargs.get('xml_file')
    csv_file = kwargs.get('csv', xml_file[:-3] + 'csv')
    xml_obj_type = kwargs.get('xml_obj_type')
    df = pd.DataFrame()
    with open(xml_file) as fd:
        doc = xmltodict.parse(fd.read(), process_namespaces=True)    
    obj_list = doc['csm:policyObjectConfigResponse']['policyObject'][xml_obj_type]
    df = pd.DataFrame(obj_list)
    df.to_csv(csv_file, index=False)
    print(f'{Path(xml_file).name} -> {Path(csv_file).name}')
    return df

def save_item_in_ext_file(**kwargs):
    data_dir = kwargs.get('dir')
    dev = kwargs.get('dev')
    df = kwargs.get('df')
    item_name = kwargs.get('item')  # 'refGIDs'
    if item_name in df.columns:
        mega_df = df[df[item_name].astype(str).str.len() >= excel_cell_text_lmt]
        if not mega_df.empty:
            for item in mega_df.itertuples(): 
                data = eval(f"item.{item_name}")
                ext_file = fr"{item.gid}.{item_name}.txt"
                ext_file_full = data_dir + fr"\{ext_file}"
                if os.path.exists(ext_file_full):
                    assert file2str(file=ext_file_full) == str(data)
                else:
                    str2file(str=str(data), file=ext_file_full)
                df.loc[item.Index, item_name] = str({'ext_file': ext_file})
    return df

def load_item_from_ext_file(x, data_dir=None):
    assert data_dir
    if x and type(eval(x)) is dict:
        x_var = eval(x)
        if 'ext_file' in x_var.keys():
            assert len(x_var) == 1
            return eval(file2str(file=data_dir + fr"\{x_var['ext_file']}"))
    return x                

def csm_dev_policy_2_sheet(**kwargs):
    data_dir = kwargs.get('dir')
    dev = kwargs.get('dev')
    xml_file = Path(data_dir + fr'\{dev}.policy.xml')
    if not os.path.exists(xml_file):
        my_logger.info(f"\n{dev} no {xml_file.name}")
        return
    with open(xml_file) as fd:
        doc = xmltodict.parse(fd.read(), process_namespaces=True)    
    policy_list = doc['csm:policyListDeviceResponse']['policyList']
    # df = xml2df(xml_file=f'{dev}.policy.xml', xpath="//policyDesc", save_csv=False).dropna()
    if not policy_list:
        my_logger.info(f"\n{dev} no policy")
        return
    
    policy_items = policy_list['policyDesc']
    if type(policy_items) is dict:
        policy_items = [policy_items]
    df = pd.DataFrame(policy_items)
    if df.empty:
        my_logger.info(f"\n{dev} no policy")
        return

    dev_policy_types = df['type'].tolist()
    print(f"\n{dev} policy types:\n{dev_policy_types}")
    
    # policy_types = ['DeviceAccessRuleUnifiedFirewallPolicy']  # get_policy_types()    
    for policy_type in dev_policy_types:
        if not policy_type:  #  or policy_type not in policy_types:
            my_logger.info(f"skip {policy_type}")
            continue

        excel_file = data_dir + fr'\{dev}.{policy_type}.xlsx'
        if file_up_to_date(file=excel_file):
            print(f"{Path(excel_file).name} up to date")
            continue
        
        writer = pd.ExcelWriter(excel_file, mode='w')
        policy_items = []
        obj_list = {}
        for obj_type in policy_obj_types:
            obj_list[obj_type] = []

        for xml_file in glob(data_dir + fr'\{dev}.{policy_type}.*xml'):
            with open(xml_file) as fd:
                doc = xmltodict.parse(fd.read(), process_namespaces=True)    
            xml_policy_type = policy_type[0].lower() + policy_type[1:]
            if '64' in xml_policy_type:
                # NAT policy name map
                # InterfaceNAT64ManualFirewallPolicy -> interfaceNATManualFirewallPolicy
                # InterfaceNAT64ObjectFirewallPolicy -> interfaceNAT64ObjectFirewallPolicy
                xml_policy_type = xml_policy_type.replace('NAT64Manual', 'NATManual')
            xml_policy_items = doc['csm:policyConfigDeviceResponse']['policy']
            if not xml_policy_items or xml_policy_type not in xml_policy_items.keys():
                my_logger.info(f"{dev} no {policy_type}")
                continue

            xml_policy_items = xml_policy_items[xml_policy_type]
            if type(xml_policy_items) is dict:
                xml_policy_items = [xml_policy_items]
            policy_items += xml_policy_items

            xml_policy_obj_dict = doc['csm:policyConfigDeviceResponse']['policyObject']
            if xml_policy_obj_dict:
                for obj_type in policy_obj_types:
                    xml_obj_type = obj_type[0].lower() + obj_type[1:]
                    if xml_obj_type in xml_policy_obj_dict.keys():
                        xml_obj_list = xml_policy_obj_dict[xml_obj_type]
                        if type(xml_obj_list) is dict:
                            xml_obj_list = [xml_obj_list]
                        if not obj_list[obj_type]:
                            obj_list[obj_type] = xml_obj_list
                        else:
                            obj_list[obj_type] += xml_obj_list
                            obj_list[obj_type] = [eval(t) for t in {str(d) for d in obj_list[obj_type]}]  # de-dup
        sheet_name = 'policy'
        policy_df = pd.DataFrame(policy_items)
        policy_df.to_excel(writer, sheet_name=sheet_name, index=False)
        print(f'{Path(excel_file).name}')
        for obj_type in policy_obj_types:
            obj_df = pd.DataFrame(obj_list[obj_type])
            # refGIDs: 2142 lines, exceed excel cell limit of 32767
            save_item_in_ext_file(**kwargs, df=obj_df, item='refGIDs')
            sheet_name = obj_type
            if not obj_df.empty:
                obj_df.to_excel(writer, sheet_name=sheet_name, index=False)
                print(f'{sheet_name}')

        writer.close()

def csm_get_gid_dev_items(**kwargs):
    save_csv = kwargs.get('save_csv', True)
    data_dir = kwargs.get('dir')
    xml_file = kwargs.get('xml_file', 'csm.groups.xml')
    xml_file = data_dir + fr'\{xml_file}'
    df = csm_groups_2_df(xml_file=xml_file, save_csv=save_csv)[['gid', 'name']].drop_duplicates().sort_values('name', key=lambda col: col.str.lower())
    return list(df.itertuples(index=False, name=None))

def csm_all_dev_policy_2_sheet(**kwargs):
    gid_dev_items = kwargs.get('gid_dev_items')
    dev_regex = kwargs.get('dev_regex')
    for gid, dev in gid_dev_items:
        if re.search(dev_exclude_regex, dev) or (dev_regex and not re.search(dev_regex, dev)):
            my_logger.info(f"\nskip {dev}")
            continue
        csm_dev_policy_2_sheet(**kwargs, dev=dev, gid=gid)

def csm_get_info(**kwargs):
    csm = kwargs.get('csm')
    data_dir = kwargs.get('dir')
    dev_regex = kwargs.get('dev_regex')
    mode = kwargs.get('mode')
    if not csm_ping(csm=csm, cookie_file=data_dir + fr'\cookie.txt'):
        return
    if mode in ['all']:
        csm_get_all_shared_policy(**kwargs)
        csm_get_all_policy_objects(**kwargs)
    csm_get_group_dev_list(**kwargs)
    gid_dev_items = csm_get_gid_dev_items(**kwargs)
    for gid, dev in gid_dev_items:        
        if re.search(dev_exclude_regex, dev) or (dev_regex and not re.search(dev_regex, dev)):
            my_logger.info(f"\nskip {dev}")
            continue
        csm_get_dev_policy(**kwargs, dev=dev, gid=gid)

def get_dev_policy_hit_xml(**kwargs):
    data_dir = kwargs.get('dir')
    policy_type = kwargs.get('policy_type', 'DeviceAccessRuleUnifiedFirewallPolicy')
    gid_dev_items=csm_get_gid_dev_items(dir=data_dir, save_csv=False)
    for gid, dev in gid_dev_items:
        dev_policy_file = data_dir + fr"\{dev}.{policy_type}.xlsx"
        if not os.path.exists(dev_policy_file):
            my_logger.info(f"No {dev_policy_file}")
            continue
        policy_rule_gid_list = pd.read_excel(dev_policy_file, sheet_name='policy')['gid'].tolist()
        policy_rule_gid_list = sorted(list(set(policy_rule_gid_list)))
        policy_rule_gid_len = len(policy_rule_gid_list)
        batches = ceil(policy_rule_gid_len/max_policy_rules)
        for i in range(batches):
            batch_policy_rule_gid_list = policy_rule_gid_list[max_policy_rules * i: max_policy_rules * (i + 1)]
            result = csm_GetHitcountDetailsByGID(dev_gid=gid, policy_type=policy_type, policy_rule_gid_list=batch_policy_rule_gid_list)
            xml_file = data_dir + fr"\{dev}.{policy_type}.batch{i + 1}.xml"
            str2file(file=xml_file, str=result)

"""
int 
{'gid': '00000000-0000-0000-0000-000000000213'}

src/dst 
{'networkObjectGIDs': {'gid': '00000000-0000-0000-0000-000000000100'}}
{'networkObjectGIDs': {'gid': ['00000000-0000-0000-0003-466038615247', '00000000-0000-0000-0003-466038615262']}}
{'ipData': ['10.99.40.90', '10.99.40.91', '10.99.140.91', '10.99.40.93']}

svc 
{'serviceObjectGIDs': {'gid': '00000000-0000-0000-0000-000000001041'}}
{'serviceParameters': [{'protocol': 'tcp', 'sourcePort': None, 'destinationPort': {'port': '445'}}, {'protocol': 'tcp', 'sourcePort': None, 'destinationPort': {'port': '135'}}]}
"""
def map_gid_in_policy(**kwargs):
    df = kwargs.get('df')
    sub_df = kwargs.get('sub_df')
    cols = ['gid', 'orderId','description','isEnabled','direction','permit','sectionName','policyName',
    'ruleNo','interfaceRoleObjectGIDs', 'sources', 'destinations', 'services']
    new_df = df[cols].fillna('')
    def map_gid(x):
        if not x:
            return []  # rule not enabled has empty obj
        x = eval(x)
        assert type(x) is dict
        assert len(x) in [1, 2]        
        gid_items = []
        info_items = []
        obj_type = ''
        if 'gid' in x.keys():
            obj_type = 'int'
            gid_items = x['gid']
            df = sub_df['InterfaceRolePolicyObject']
        else:
            for k, v in x.items():
                if k in ['ipData', 'serviceParameters']:
                    if not obj_type:                    
                        obj_type = 'net' if k == 'ipData' else 'svc'
                    if k == 'ipData':
                        if type(v) is str:
                            v = [v]
                    else:
                        if type(v) is dict:
                            v = [v]
                        for i in v:
                            assert i['sourcePort'] is None or i['sourcePort']['port'] == "1-65535"
                        v = [i['protocol'] + " " + i['destinationPort']['port'] for i in v]
                    info_items += v
                else:
                    assert k in ['networkObjectGIDs', 'serviceObjectGIDs']
                    if not obj_type:                    
                        obj_type = 'net' if 'net' in k else 'svc'
                    gid_items = v['gid']
                    if k in ['networkObjectGIDs']:
                        df = sub_df['NetworkPolicyObject']
                    else:
                        df = sub_df['ServicePolicyObject']
        
        if not gid_items:
            return info_items

        if type(gid_items) is not list:
            gid_items = [gid_items]
        for gid in gid_items:
            _df = df[df['gid'] == gid]
            if _df.empty:
                _df = df[df['parentGID'] == gid]
            if len(_df) != 1:
                assert len(_df) == 0
                my_logger.info(f"gid not found: {gid}")
                info_items.append(gid)
            else:
                name = _df['name'].iloc[0]
                if not name and obj_type == 'int':
                    name = _df['comment'].iloc[0]
                    if not name:
                        name = _df['pattern'].iloc[0]
                info_items.append(name)

        return info_items
    
    for item in ['interfaceRoleObjectGIDs', 'sources', 'destinations', 'services']:
        new_df[item] = new_df[item].apply(map_gid)
    return new_df

def policy_p0_render_gid_reference(**kwargs):  # L1 obj name, match fw config
    dev_regex = kwargs.get('dev_regex')
    data_dir = kwargs.get('dir')
    policy_type = kwargs.get('policy_type', 'DeviceAccessRuleUnifiedFirewallPolicy')
    
    print(f"\npolicy_p0_render_gid_reference\n")

    csv_file = data_dir + fr"\csm.groups.csv"
    df = pd.read_csv(csv_file)[['gid', 'name']].drop_duplicates().sort_values('name', key=lambda col: col.str.lower())
    gid_dev_items = list(df.itertuples(index=False, name=None))
    for gid, dev in gid_dev_items:
        if re.search(dev_exclude_regex, dev) or (dev_regex and not re.search(dev_regex, dev)):
            my_logger.info(f"skip {dev}")
            continue
        dev_policy_file = data_dir + fr"\{dev}.{policy_type}.xlsx"
        new_dev_policy_file = dev_policy_file[:-4] + "p0.xlsx"
        if file_up_to_date(file=new_dev_policy_file):
            print(f"{Path(new_dev_policy_file).name} up to date")
            continue
        
        print(f"{Path(dev_policy_file).name}")
        xls = pd.ExcelFile(dev_policy_file)
        name_func_items = [
            ('InterfaceRolePolicyObject', None),
            ('PortListPolicyObject', None),
            ('ServicePolicyObject', None),
            ('NetworkPolicyObject', None),
            ('policy', map_gid_in_policy),
        ]
        new_df = {}
        for name, func in name_func_items:
            df = pd.read_excel(xls, name).fillna('')
            if func:
                new_df[name] = func(dir=data_dir, df=df, sub_df=new_df)
            else:
                new_df[name] = df

        with pd.ExcelWriter(new_dev_policy_file, mode='w') as writer:
            for name, _ in name_func_items:
                new_df[name].to_excel(writer, sheet_name=name, index=False)

def render_refGIDs(x):        
    result = ''
    if x:
        x_var = eval(x) if type(x) is str else x
        if type(x_var) is list:  # [{'gid':[gid1, gid2]}]
            if len(x_var) == 1:
                x_var = x_var[0]
                assert type(x_var) is dict
        if type(x_var) is dict:
            result = x_var['gid']            
    if not result: 
        result = x
    if result and type(result) is not list:
        result = [result] 
    return result

def render_nw(**kwargs):
    data_dir = kwargs.get('dir')
    df = kwargs.get('df')
    if 'fqdnData' in df.columns:
        fqdn_flag = True
        cols = ['gid', 'parentGID', 'name',	'comment', 'refGIDs', 'subType', 'ipData', 'fqdnData']
    else:
        fqdn_flag = False
        cols = ['gid',	'parentGID', 'name',	'comment', 'refGIDs', 'subType', 'ipData']
    new_df = df[cols].fillna('')
    new_df['info'] = ''
    new_df['refGIDs'] = new_df['refGIDs'].apply(load_item_from_ext_file, data_dir=data_dir)
    new_df['refGIDs'] = new_df['refGIDs'].apply(render_refGIDs)
    new_df['ipData'] = new_df['ipData'].apply(lambda x: x if not x else [x] if type(x) is str else eval(x))
    new_df.loc[new_df['ipData'] != '', 'info'] = new_df[new_df['ipData'] != ''].apply(lambda line: {line['name']: line['ipData']}, axis=1)
    
    if fqdn_flag:
        new_df['fqdnData'] = new_df['fqdnData'].apply(lambda x: x if not x else eval(x)['value'])
        new_df.loc[new_df['fqdnData'] != '', 'info'] = new_df[new_df['fqdnData'] != ''].apply(lambda line: {line['name']: line['fqdnData']}, axis=1)

    ref_df = new_df[new_df['refGIDs'] != '']
    # 00000000-0000-0000-0001-005022349850| L1 refGID 00000000-0000-0000-0004-458176072473
    for item in ref_df.itertuples():  # line of top level
        info = {}
        print(f"level 0 {item.gid, item.name}")
        for gid in item.refGIDs:  # L1 refGIDs  
            level = 1
            _df = new_df[new_df['gid'] == gid]  # line of gid in refGIDs
            if _df.empty:
                _df = new_df[new_df['parentGID'] == gid]
                print(f"{gid} in parentGID")
            assert len(_df) == 1
            # if len(_df) != 1:
            #     pass
            name = _df['name'].iloc[0]            
            print(f"level {level} {gid, name}")

            sub_gid_table = []
            while True:
                sub_refGIDs = _df['refGIDs'].iloc[0]
                if sub_refGIDs:  # L2 refGIDs and further
                    level += 1
                    for sub_gid in sub_refGIDs:
                        sub_gid_table.append((level, sub_gid))
                        print(f"push level {level} {sub_gid}")
                ipData = _df['ipData'].iloc[0]
                if ipData:
                    info.setdefault(name, [])
                    info[name] += ipData
                else:
                    if fqdn_flag:
                        fqdnData = _df['fqdnData'].iloc[0]
                        if fqdnData:
                            info.setdefault(name, [])                            
                            info[name] += fqdnData
                
                if sub_gid_table:
                    level, sub_gid = sub_gid_table.pop(0)
                    _df = new_df[new_df['gid'] == sub_gid]
                    if _df.empty:
                        _df = new_df[new_df['parentGID'] == sub_gid]
                        print(f"{sub_gid} in parentGID")
                    assert len(_df) == 1
                    name = _df['name'].iloc[0]
                    print(f"pop level {level} {sub_gid, name}")
                else:
                    break
        new_df.loc[item.Index, 'info'] = [info]                
    return new_df

def render_int(**kwargs):
    df = kwargs.get('df')
    cols = ['gid', 'parentGID', 'name',	'pattern', 'comment']
    new_df = df[cols].fillna('')    
    
    def _map_int(line):
        name_items = ['name', 'pattern', 'comment']
        for name in name_items:
            if line[name] != '':
                return line[name] 
        return ''

    new_df['info'] = new_df.apply(_map_int, axis=1)
    return new_df

def render_po(**kwargs):
    df = kwargs.get('df')
    cols = ['gid',	'name',	'comment', 'port']
    new_df = df[cols].fillna('')
    new_df['port'] = new_df['port'].apply(lambda x: (int(eval(x)['startPort']['portNum']), int(eval(x)['endPort']['portNum'])))
    new_df['info'] = new_df.apply(lambda line: {line['name']: line['port']}, axis=1)
    return new_df

def render_svc_para(x):  # x is list
    result = []
    if x:
        for i in x:
            if 'destinationPort' in i.keys() and 'port' in i['destinationPort'].keys():
                svc = f"{i['protocol']}:{i['destinationPort']['port']}"
            else:
                svc = f"{i['protocol']}"
            result.append(svc)
    return result

def render_svc(**kwargs):
    df = kwargs.get('df')
    cols = ['gid',	'name',	'comment', 'refGIDs', 'subType', 'serviceParameters']
    new_df = df[cols].fillna('')
    new_df['refGIDs'] = new_df['refGIDs'].apply(lambda x: eval(x)['gid'] if x and type(eval(x)) is dict else x)
    new_df['refGIDs'] = new_df['refGIDs'].apply(lambda x: [x] if x and type(x) is not list else x)
    new_df['serviceParameters'] = new_df['serviceParameters'].apply(lambda x: x if not x else eval(x) if type(eval(x)) is list else [eval(x)])
    new_df['serviceParameters'] = new_df['serviceParameters'].apply(render_svc_para)
    new_df.loc[new_df['serviceParameters'] != '', 'info'] = new_df[new_df['serviceParameters'] != ''].apply(lambda line: {line['name']: line['serviceParameters']}, axis=1)

    ref_df = new_df[new_df['refGIDs'] != '']
    for item in ref_df.itertuples():
        info = {}
        for gid in item.refGIDs:
            _df = new_df[new_df['gid'] == gid]
            assert len(_df) == 1
            name = _df['name'].iloc[0]
            serviceParameters = _df['serviceParameters'].iloc[0]
            if serviceParameters:
                info[name] = serviceParameters
        new_df.loc[item.Index, 'info'] = [info]                
    return new_df

def render_policy(**kwargs):
    df = kwargs.get('df')
    sub_df = kwargs.get('sub_df')
    cols = ['gid', 'orderId','description','isEnabled','direction','permit','sectionName','policyName',
    'ruleNo','interfaceRoleObjectGIDs', 'sources', 'destinations', 'services']
    new_df = df[cols].fillna('')

    # {'serviceParameters': [{'protocol': 'tcp', 'sourcePort': None, 'destinationPort': {'port': '445'}}, 
    # {'protocol': 'tcp', 'sourcePort': None, 'destinationPort': {'port': '135'}}]}

    # {'serviceObjectGIDs': {'gid': '00000000-0000-0000-0000-502511174239'}, 
    # 'serviceParameters': {'protocol': 'tcp', 'sourcePort': None, 'destinationPort': {'port': '18891'}}}    
    def map_gid(x):
        x = eval(x)
        assert type(x) is dict and len(x) <= 2
        # non_gid_dict = None
        gid_items = []
        if 'gid' in x.keys():
            df = sub_df['InterfaceRolePolicyObject']
            gid_items = x['gid']
        else:
            for k, v in x.items():
                if k in ['ipData', 'serviceParameters']:
                    if k in ['ipData']:
                        if type(v) is str:
                            v = [v]                            
                        # assert type(v) is list                            
                        return v
                    else:
                        if type(v) is dict:
                            v = [v]
                        assert type(v) is list                            
                        return render_svc_para(v)
                    # non_gid_dict = {k:v}
                else:
                    assert k in ['networkObjectGIDs', 'serviceObjectGIDs']
                    gid_items = v['gid']
                    if k in ['networkObjectGIDs']:
                        df = sub_df['NetworkPolicyObject']
                    else:
                        df = sub_df['ServicePolicyObject']
        
        assert len(gid_items)
        if type(gid_items) is not list:
            gid_items = [gid_items]
        info_items = []
        for gid in gid_items:
            _df = df[df['gid'] == gid]
            if _df.empty:
                _df = df[df['parentGID'] == gid]
            if len(_df) != 1:
                print(gid)
                info_items.append(gid)
            else:
                info_items.append(_df['info'].iloc[0])
        # if non_gid_dict:
        #     info_items.append(non_gid_dict)
        return info_items
    
    for item in ['interfaceRoleObjectGIDs', 'sources', 'destinations', 'services']:
        new_df[item] = new_df[item].apply(map_gid)
    return new_df

def policy_p1_render_gid_reference(**kwargs):  # leaf obj and content
    dev_regex = kwargs.get('dev_regex')
    data_dir = kwargs.get('dir')
    policy_type = kwargs.get('policy_type', 'DeviceAccessRuleUnifiedFirewallPolicy')

    print(fr"\policy_p1_render_gid_reference\n")

    csv_file = data_dir + fr"\csm.groups.csv"
    df = pd.read_csv(csv_file)[['gid', 'name']].drop_duplicates().sort_values('name', key=lambda col: col.str.lower())
    gid_dev_items = list(df.itertuples(index=False, name=None))
    name_func_items = [
        ('InterfaceRolePolicyObject', render_int),
        ('PortListPolicyObject', render_po),
        ('ServicePolicyObject', render_svc),
        ('NetworkPolicyObject', render_nw),
        ('policy', render_policy),
    ]
    for gid, dev in gid_dev_items:
        if (dev_exclude_regex and re.search(dev_exclude_regex, dev)) or (dev_regex and not re.search(dev_regex, dev)):
            my_logger.info(f"skip {dev}")
            continue
        
        dev_policy_file = data_dir + fr"\{dev}.{policy_type}.xlsx"
        if not os.path.exists(dev_policy_file):
            my_logger.info(f"No {Path(dev_policy_file).name}")
            continue        
        
        print(f"{dev}")
        new_dev_policy_file = data_dir + fr"\{dev}.{policy_type}.p1.xlsx"
        if file_up_to_date(file=new_dev_policy_file):
            print(f"{Path(new_dev_policy_file).name} up to date")
            continue

        xls = pd.ExcelFile(dev_policy_file)
        new_df = {}
        for name, func in name_func_items:
            df = pd.read_excel(xls, name).fillna('')
            new_df[name] = func(dir=data_dir, df=df, sub_df=new_df)

        with pd.ExcelWriter(new_dev_policy_file, mode='w') as writer:
            for name, _ in name_func_items:
                for item in ['refGIDs', 'sources',	'destinations', 'info']:
                    save_item_in_ext_file(**kwargs, dev=dev, df=new_df[name], item=item)
                new_df[name].to_excel(writer, sheet_name=name, index=False)

"""
def extract_ip(x):
    result = ['']
    ip_regex = r"\d+(\.\d+){3}"  # '192.1.1.1' '10.0.0.0/8'
    m = re.findall(fr"'({ip_regex}|{ip_regex}/{ip_regex}|{ip_regex}/\d+|::/0)'", x)
    if m:
        result = [i[0] for i in m]
    return result

def extract_port(x):
    result = ['']
    port_regex = r"'((ip|icmp|tcp|udp)(:[^']*)?)'"  # '192.1.1.1'
    m = re.findall(port_regex, x)
    if m:
        result = [i[0] for i in m]
    return result
"""

def extract_ip_port(**kwargs):
    df = kwargs.get('df')
    cols = ['gid', 'orderId','description','isEnabled','direction','permit','sectionName','policyName',
    'ruleNo','interfaceRoleObjectGIDs', 'sources', 'destinations', 'services']
    new_df = df[cols].fillna('')

    def extract_info_v2(x):
        def _from_dict(v_dict):
            _result = []
            for k, v in v_dict.items():
                if type(v) is str:
                    assert v[0] not in ['[', '{']
                    _result.append(v)
                else:
                    assert type(v) is list
                    _result += v
            return _result

        def _from_list(v_list):
            _result = []
            for _item in v_list:
                if type(_item) is str:
                    if _item == '':
                        pass
                    elif _item[0] == '{':
                        _result += _from_dict(eval(_item))
                    else:
                        _result.append(_item)
                elif type(_item) is list:  # sources: [[{}], [{}]]
                    _result += _from_list(_item)
                else:
                    assert type(_item) is dict
                    _result += _from_dict(_item)
            return _result

        result = []
        if type(x) is dict:
            result += _from_dict(x)
        elif type(x) is list:
            result += _from_list(x)
        else:
            assert type(x) is str
            if x[0] == '{':
                result += _from_dict(eval(x))
            else:
                assert x[0] == '['
                result += _from_list(eval(x))
        return result
    
    for item in ['sources', 'destinations']:
        # new_df[item] = new_df[item].apply(extract_ip)
        new_df[item] = new_df[item].apply(extract_info_v2)  # test
    for item in ['services']:
        # new_df[item] = new_df[item].apply(extract_port)
        new_df[item] = new_df[item].apply(extract_info_v2)  # test
    return new_df

def policy_p2_render_ip_port(**kwargs):  # content only for traffic match
    dev_regex = kwargs.get('dev_regex')
    data_dir = kwargs.get('dir')
    policy_type = kwargs.get('policy_type', 'DeviceAccessRuleUnifiedFirewallPolicy')

    print(f"\policy_p2_render_ip_port\n")

    csv_file = data_dir + fr"\csm.groups.csv"
    df = pd.read_csv(csv_file)[['gid', 'name']].drop_duplicates().sort_values('name', key=lambda col: col.str.lower())
    gid_dev_items = list(df.itertuples(index=False, name=None))
    for gid, dev in gid_dev_items:
        if re.search(dev_exclude_regex, dev) or (dev_regex and not re.search(dev_regex, dev)):
            my_logger.info(f"skip {dev}")
            continue
        
        dev_policy_file = data_dir + fr"\{dev}.{policy_type}.p1.xlsx"
        if not os.path.exists(dev_policy_file):
            my_logger.info(f"No {Path(dev_policy_file).name}")
            continue        
        
        print(f"{dev}")
        new_dev_policy_file = data_dir + fr"\{dev}.{policy_type}.p2.xlsx"
        if file_up_to_date(file=new_dev_policy_file):
            print(f"{Path(new_dev_policy_file).name} up to date")
            continue

        xls = pd.ExcelFile(dev_policy_file)
        name_func_items = [
            ('policy', extract_ip_port),
        ]
        new_df = {}
        for name, func in name_func_items:
            df = pd.read_excel(xls, name).fillna('')
            new_df[name] = func(df=df, sub_df=new_df)

        with pd.ExcelWriter(new_dev_policy_file, mode='w') as writer:
            for name, _ in name_func_items:
                # save_item_in_ext_file(df=new_df[name], item='refGIDs')
                # save_item_in_ext_file(df=new_df[name], item='info')
                new_df[name].to_excel(writer, sheet_name=name, index=False)

def csm_job(**kwargs):
    data_dir = kwargs.get('dir')
    t_now = datetime.now().replace(microsecond=0, second=0)
    print(f"{str(t_now)}")
    csm_get_info(**kwargs)
    csm_all_dev_policy_2_sheet(dir=data_dir, gid_dev_items=csm_get_gid_dev_items(dir=data_dir))

def copy_files(**kwargs):
    dst_dir = kwargs.get('dst_dir')
    src_files = kwargs.get('src_files')
    for file in glob(src_files):
        shutil.copy(file, dst_dir)

def csm_post_process(**kwargs):
    data_dir = kwargs.get('dir')
    dst_dir = kwargs.get('dst_dir', data_dir)
    dev_regex = kwargs.get('dev_regex')
    process_stages = [
        policy_p0_render_gid_reference, 
        policy_p1_render_gid_reference, 
        policy_p2_render_ip_port,
        ]
    stages = kwargs.get('stages', len(process_stages))
    for process_func in process_stages[:stages]:
        process_func(**kwargs)
    # copy_files(src_files=data_dir + fr'\*.txt', dst_dir=dst_dir)  # over 32k
    # copy_files(src_files=data_dir + fr'\*.xlsx', dst_dir=dst_dir)

if __name__ == '__main__':
    data_dir = csm_cfg.data_dir
    share_dir = csm_cfg.share_dir
    non_prd_regex = csm_cfg.non_prd_regex
    my_logger = set_logger(file=data_dir + fr'\csm_api.log')
    csm_job(csm=csm_cfg.csm, dir=data_dir, dev_regex=non_prd_regex)
    shutil.copytree(data_dir, share_dir, dirs_exist_ok=True)  # overwrite
    # [os.remove(f) for f in glob(fr"{data_dir}\*.xml") if 'csm.groups.xml' != Path(f).name]
    # [os.remove(f) for f in glob(fr"{data_dir}\*") if not re.search(non_prd_regex, Path(f).name) and f[-4:] != '.log']
    # csm_post_process(dir=local_dir, dev_regex='npd', stages=1)
    exit(0)

    # csm_Logout(csm=csm, cookie_file=cur_dir + fr'\cookie.txt')
    # exit()
    
