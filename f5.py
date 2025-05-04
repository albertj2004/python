import os
from datetime import datetime
from time import sleep
import requests
import pandas as pd
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from common_utils import *
from f5_cfg import *

def get_token(dev, **kwargs):
    login_provider = kwargs.get('login_provider', 'tmos')
    username = kwargs.get('user')
    password = kwargs.get('pwd')
    body = {
        "username": username,
        "password": password,
        "loginProviderName": login_provider
    }
    try:
        token_response = requests.post(f'https://{dev}/mgmt/shared/authn/login', verify=False, json=body, timeout=login_timeout_sec).json()
    except Exception as e:
        token_response = {'error': e}
    token = ''
    if 'token' in token_response.keys():
        token = token_response['token']['token']
    else:
        token = str(token_response)
    return token

def request_info(**kwargs):
    url = kwargs.get('url')
    token = kwargs.get('token')
    retry = kwargs.get('retry', 3)
    headers = {"X-F5-Auth-Token": token}
    items = []
    last_exception = None
    for i in range(retry):
        try:
            response = requests.get(url, headers=headers, verify=False, timeout=get_timeout_sec)
            if response.status_code == 200:
                last_exception = None
                info = response.json()
                if 'items' in info.keys():            
                    items = info['items']
                else:
                    items = [info]
                break
            else:
                last_exception = Exception(response.text)
        except Exception as e:
            last_exception = e
            sleep(1)
    if last_exception:
        my_logger.info(f'{url}\n{last_exception}')
        raise last_exception
    return items

def get_gtm_info(**kwargs):
    data_dir = kwargs.get('dir', '.')
    dev = kwargs.get('dev')
    token = kwargs.get('token')
    excel_file = data_dir + fr'\{dev}.xlsx'
    if file_up_to_date(file=excel_file):
        return
    try:
        with pd.ExcelWriter(excel_file, mode='w') as writer:
            for obj, url in gtm_obj_url_map.items():
                if url:
                    if '/' not in url:
                        url = f'gtm/{url}'
                else:
                    url = f'gtm/{obj}'
                url = f'mgmt/tm/{url}'
                items = request_info(url=f'https://{dev}/{url}', token=token)
                if items:
                    df = pd.DataFrame(items)
                    df.to_excel(writer, sheet_name=obj, index=False)
                else:
                    if obj in critical_obj_list:
                        writer.close()
                        if os.path.exists(excel_file):
                            my_logger.info(f'del {excel_file}')
                            os.remove(excel_file)
                        return
                    else:
                        continue
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
    except Exception as e:
        my_logger.info(f'del {excel_file}')
        os.remove(excel_file)

def get_ltm_info(**kwargs):
    data_dir = kwargs.get('dir', '.')
    dev = kwargs.get('dev')
    token = kwargs.get('token')
    excel_file = data_dir + fr'\{dev}.xlsx'
    if file_up_to_date(file=excel_file):
        return
    try:
        with pd.ExcelWriter(excel_file, mode='w') as writer:
            for obj, url in ltm_obj_url_map.items():
                if url:
                    if '/' not in url:
                        url = f'ltm/{url}'
                else:
                    url = f'ltm/{obj}'
                url = f'mgmt/tm/{url}'
                items = request_info(url=f'https://{dev}/{url}', token=token)
                if items:
                    df = pd.DataFrame(items)
                    df.to_excel(writer, sheet_name=obj, index=False)
                else:
                    if obj in critical_obj_list:
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
                        req_url = reference['link'].replace('localhost', dev)
                        items = request_info(url=req_url, token=token)
                        if not items:
                            continue                
                        _df = pd.concat([_df, pd.DataFrame(items)])
                    if len(_df):
                        _df = _df.drop(columns=secret_cols, errors='ignore')
                        _df.to_excel(writer, sheet_name=f'{obj}.data', index=False)
    except Exception as e:
        my_logger.info(f'del {excel_file}')
        os.remove(excel_file)

def get_single_f5_data(dev, **kwargs):
    usr = kwargs.get('usr')
    pwd = kwargs.get('pwd')
    data_dir = kwargs.get('dir')
    fname = fr'{dev}.xlsx'
    if file_up_to_date(file=data_dir + fr'\{fname}'):
        return
    token = get_token(dev, user=usr, pwd=pwd)
    if token and token[0] != '{':
        if '-ltm-' in dev:
            get_f5_info_func = get_ltm_info         
        else:
            get_f5_info_func = get_gtm_info
        get_f5_info_func(dev=dev, token=token, dir=data_dir)
    else:
        my_logger.info(f'{dev}: {token}')

def f5_job():
    svc_usr, svc_pwd = get_svc_cred(file=cred_dir + fr'\{svc_cred_file}')
    if all([svc_usr, svc_pwd]):
        for dev in f5_working_list:
            get_single_f5_data(dev, dir=data_dir, usr=svc_usr, pwd=svc_pwd)

if __name__ == '__main__':
    my_logger.info(f'\nstart: {datetime.now().replace(microsecond=0)}')
    f5_job()
    my_logger.info(f'end: {datetime.now().replace(microsecond=0)}')
