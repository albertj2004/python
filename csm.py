import re
import os
from glob import glob
import requests
import xmltodict
from pathlib import Path
import pandas as pd
from datetime import datetime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from common_utils import *
from csm_cfg import *

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

def init_session(csm):
    global session
    headers = {
        "Host": csm,
        'Content-Type': 'application/xml', 
        'Accept': 'application/xml', 
    }
    session = requests.Session()
    session.headers.update(headers)

def csm_post(**kwargs):
    global session, cookie
    retry = kwargs.get('retry', 0)
    code_flag = kwargs.get('code_flag', False)
    svc = kwargs.get('svc', 'configservice')
    url_func = kwargs.get('url_func')
    if svc:
        _url = kwargs.get('url', f"https://{csm}/nbi/{svc}/{url_func}")
    else:
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
    result = ''
    try:
        for i in range(retry + 1):        
            response = session.post(_url, data=_xml, verify=False)
            response_code = response.status_code
            if response_code == 200:
                result = response.text
                if url_func in ['login']:
                    cookie = response.cookies.get_dict()['asCookie']
            else:
                my_logger.info(f"{_url}\n{_xml}\n{response_code}\n{result}")
            
            if "<error>" not in response.text or i + 1 > retry:
                break
            my_logger.info(f"Retry after error: {i + 1}")
    except Exception as e:
        my_logger.info(f"{_url}\n{e}")

    if code_flag:
        if response_code == 200:
            return True
        else:
            return False
    else:
        return result

def csm_ping(csm):
    global session, cookie    
    init_session(csm)
    session.cookies.set('asCookie', cookie, path='/', domain=f'{csm}.local')
    url_func = 'ping'
    xml_func = 'pingRequest'
    return csm_post(svc='', url_func=url_func, xml_func=xml_func, code_flag=True)

def csm_Login(csm, usr, pwd):
    init_session(csm)
    url_func = 'login'
    xml_func = 'loginRequest'
    xml_args = f"""
    <username>{usr}</username>
    <password>{pwd}</password>
    """.strip()
    return csm_post(svc='', url_func=url_func, xml_func=xml_func, xml_args=xml_args, code_flag=True)

def csm_Logout(csm):
    if csm_ping(csm):
        url_func = 'logout'
        xml_func = 'logoutRequest'
        csm_post(svc='', url_func=url_func, xml_func=xml_func, code_flag=True)
 
def csm_GetGroupList(**kwargs):
    retry = kwargs.get('retry', 3)
    url_func = 'getGroupList'
    xml_func = 'groupListRequest'
    xml_args = '<includeEmptyGroups>false</includeEmptyGroups>'
    return csm_post(url_func=url_func, xml_func=xml_func, xml_args=xml_args, retry=retry)
   
def csm_groups_2_df(xml_str):
    df = pd.DataFrame()
    doc = xmltodict.parse(xml_str, process_namespaces=True)
    L2_list = doc['csm:groupListResponse']['deviceGroup']['deviceGroup']
    for L2_item in L2_list:
        for L2_item_k, L2_item_v in L2_item.items():
            if L2_item_k in ['gid']:
                L2_gid = L2_item_v
            if L2_item_k in ['path']:
                L2_path = L2_item_v
            if L2_item_k in ['deviceGroup']:
                if type(L2_item_v) is dict:
                    L3_list = [L2_item_v]
                else:
                    type(L2_item_v) is list
                    L3_list = L2_item_v
                for L3_item in L3_list:
                    for L3_item_k, L3_item_v in L3_item.items():
                        if L3_item_k in ['gid']:
                            L3_gid = L3_item_v
                        if L3_item_k in ['path']:
                            L3_path = L3_item_v
                        if L3_item_k in ['deviceGroup']:
                            if type(L3_item_v) is list:
                                L4_list = L3_item_v
                            else:
                                L4_list = [L3_item_v]
                            for L4_item in L4_list:
                                for L4_item_k, L4_item_v in L4_item.items():
                                    if L4_item_k in ['gid']:
                                        L4_gid = L4_item_v
                                    if L4_item_k in ['path']:
                                        L4_path = L4_item_v
                                    if L4_item_k in ['device']:
                                        L5_list = L4_item_v
                                        dev_df = pd.DataFrame(L5_list)
                                        dev_df[['L2_gid', 'L2_path', 'L3_gid', 'L3_path','L4_gid', 'L4_path']] = L2_gid, L2_path, L3_gid, L3_path, L4_gid, L4_path
                                        dev_df['L2_gid'] = L2_gid
                                        df = pd.concat([df, dev_df])
    return df

def csm_get_group_dev_list(**kwargs):
    data_dir = kwargs.get('dir')
    fname = data_dir + fr'\csm.groups.xlsx'
    if not file_up_to_date(file=fname):
        try:
            csm_groups_2_df(xml_str=csm_GetGroupList()).to_excel(fname, index=False)
        except Exception as e:
            my_logger.info(e)

def csm_get_gid_dev_items(**kwargs):
    data_dir = kwargs.get('dir')
    df = pd.read_excel(data_dir + fr'\csm.groups.xlsx')
    if len(df):
        df = df[['gid', 'name']].drop_duplicates().sort_values('name', key=lambda col: col.str.lower())
        return list(df.itertuples(index=False, name=None))
    else:
        return []

def csm_GetPolicyListByDeviceGID(**kwargs):
    url_func = 'getPolicyListByDeviceGID'
    xml_func = 'policyListByDeviceGIDRequest'
    gid = kwargs.get('gid')
    xml_args = f'<gid>{gid}</gid>'
    return csm_post(url_func=url_func, xml_func=xml_func, xml_args=xml_args)

def csm_GetPolicyConfigByDeviceGID(**kwargs):
    url_func = 'getPolicyConfigById'
    xml_func = 'policyConfigByDeviceGIDRequest'
    debug = kwargs.get('debug', False)
    gid = kwargs.get('gid')
    policy_type = kwargs.get('policy_type','DeviceAccessRuleUnifiedFirewallPolicy')
    startIndex = kwargs.get('startIndex', 0)
    xml_args = f'<gid>{gid}</gid><policyType>{policy_type}</policyType>'
    return csm_post(url_func=url_func, xml_func=xml_func, xml_args=xml_args, startIndex=startIndex, debug=debug)

def csm_get_dev_policy(**kwargs):
    data_dir = kwargs.get('dir')
    dev = kwargs.get('dev')
    gid = kwargs.get('gid')
    result = csm_GetPolicyListByDeviceGID(gid=gid)
    if not result:
        my_logger.info(f"{dev} policy error")
        return
    xml_file = fr'{data_dir}\{dev}.policy.xml'
    str2file(file=xml_file, str=result)    
    doc = xmltodict.parse(result, process_namespaces=True)
    dev_policy_dict = doc['csm:policyListDeviceResponse']['policyList']
    if not dev_policy_dict or 'policyDesc' not in dev_policy_dict.keys():
        return
    dev_policy_items = dev_policy_dict['policyDesc']
    if type(dev_policy_items) is dict:
        dev_policy_items = [dev_policy_items]
    df = pd.DataFrame(dev_policy_items)
    dev_policy_types = df['type'].tolist()
    for policy_type in dev_policy_types:
        page = 0
        startIndex = 0
        fname = data_dir + fr'\{dev}.{policy_type}.{page}.xml'
        if file_up_to_date(file=fname):
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

def save_item_in_ext_file(**kwargs):
    data_dir = kwargs.get('dir')
    df = kwargs.get('df')
    item_name = kwargs.get('item')
    if item_name in df.columns:
        mega_df = df[df[item_name].astype(str).str.len() >= excel_cell_text_lmt]
        if len(mega_df):
            for item in mega_df.itertuples(): 
                data = eval(f"item.{item_name}")
                ext_file = fr"{item.gid}.{item_name}.txt"
                ext_file_full = data_dir + fr"\{ext_file}"
                if not os.path.exists(ext_file_full):
                    str2file(str=str(data), file=ext_file_full)
                df.loc[item.Index, item_name] = str({'ext_file': ext_file})
    return df

def csm_dev_policy_2_sheet(**kwargs):
    data_dir = kwargs.get('dir')
    dev = kwargs.get('dev')
    fname = data_dir + fr'\{dev}.DeviceAccessRuleUnifiedFirewallPolicy.xlsx'
    if file_up_to_date(file=fname):
        return
    xml_file = Path(data_dir + fr'\{dev}.policy.xml')
    if not os.path.exists(xml_file):
        return
    with open(xml_file) as fd:
        doc = xmltodict.parse(fd.read(), process_namespaces=True)    
    policy_list = doc['csm:policyListDeviceResponse']['policyList']
    if not policy_list:
        return
    policy_items = policy_list['policyDesc']
    if type(policy_items) is dict:
        policy_items = [policy_items]
    df = pd.DataFrame(policy_items)
    if df.empty:
        return
    dev_policy_types = df['type'].tolist()
    for policy_type in dev_policy_types:
        if not policy_type:
            continue
        excel_file = data_dir + fr'\{dev}.{policy_type}.xlsx'
        if file_up_to_date(file=excel_file):
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
                xml_policy_type = xml_policy_type.replace('NAT64Manual', 'NATManual')
            xml_policy_items = doc['csm:policyConfigDeviceResponse']['policy']
            if not xml_policy_items or xml_policy_type not in xml_policy_items.keys():
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
        for obj_type in policy_obj_types:
            obj_df = pd.DataFrame(obj_list[obj_type])
            save_item_in_ext_file(**kwargs, df=obj_df, item='refGIDs')
            sheet_name = obj_type
            if len(obj_df):
                obj_df.to_excel(writer, sheet_name=sheet_name, index=False)
        writer.close()

def csm_get_info(**kwargs):
    data_dir = kwargs.get('dir')
    dev_regex = kwargs.get('dev_regex')
    if not csm_ping():
        return
    csm_get_group_dev_list(**kwargs)
    gid_dev_items = csm_get_gid_dev_items(**kwargs)
    for gid, dev in gid_dev_items:        
        if re.search(dev_exclude_regex, dev) or (dev_regex and not re.search(dev_regex, dev)):
            continue
        if file_up_to_date(file=data_dir + fr'\{dev}.DeviceAccessRuleUnifiedFirewallPolicy.xlsx'):
            continue
        csm_get_dev_policy(**kwargs, dev=dev, gid=gid)
        csm_dev_policy_2_sheet(**kwargs, dev=dev, gid=gid)
    [f.unlink() for f in Path(data_dir).glob("*.xml")]

def check_result_up_to_date(**kwargs):
    gid_dev_items = kwargs.get('gid_dev_items')
    dev_regex = kwargs.get('dev_regex')
    data_dir = kwargs.get('dir')
    if not gid_dev_items:
        return False
    result = True
    for gid, dev in gid_dev_items:
        if re.search(dev_exclude_regex, dev) or (dev_regex and not re.search(dev_regex, dev)):
            continue
        if not file_up_to_date(file=data_dir + fr'\{dev}.DeviceAccessRuleUnifiedFirewallPolicy.xlsx'):
            result = False
            break
    return result

def csm_job():
    if not check_result_up_to_date(dir=data_dir, dev_regex=dev_regex, gid_dev_items=csm_get_gid_dev_items(dir=data_dir)):        
        svc_usr, svc_pwd = get_svc_cred(file=cred_dir + fr'\{svc_cred_file}')
        if all([svc_usr, svc_pwd]):
            if csm_Login(csm, svc_usr, svc_pwd):
                csm_get_info(dir=data_dir, dev_regex=dev_regex)
                csm_Logout(csm)
            else:
                my_logger.info(f'Login failed.')

if __name__ == '__main__':
    session = None
    cookie = ''
    my_logger.info(f'\nstart: {datetime.now().replace(microsecond=0)}')
    csm_job()
    my_logger.info(f'end: {datetime.now().replace(microsecond=0)}')
