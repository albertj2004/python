from datetime import datetime
import requests 
from requests.auth import HTTPBasicAuth
import pandas as pd
from io import StringIO
from common_utils import *
from faddom_cfg import *

def export_data(**kwargs):
    usr = kwargs.get('usr')
    pwd = kwargs.get('pwd')
    url = kwargs.get('url')
    status = False
    try:
        response = requests.get(url, auth=HTTPBasicAuth(usr, pwd), verify=False, timeout=get_timeout_sec)
        result = response.text 
        if response.status_code == 200:
            status = True
        else:
            my_logger.info(f'{url}\n{result}')
    except Exception as e:
        result = e
        my_logger.info(f'{url}\n{result}')
    return status, result 

def export_faddom_data(**kwargs):
    svr = kwargs.get('svr')
    usr = kwargs.get('usr')
    pwd = kwargs.get('pwd')
    api_map = kwargs.get('api_map')
    excel_file = data_dir + fr'\faddom.xlsx'
    with pd.ExcelWriter(excel_file, mode='w') as writer:
        for name, api in api_map.items():
            url = f"https://{svr}/WebServices{api}"
            status, result = export_data(usr=usr, pwd=pwd, url=url)
            if status:
                df = pd.read_csv(StringIO(result))
                df.to_excel(writer, sheet_name=name, index=False)

def faddom_job(**kwargs):
    if not file_up_to_date(file=data_dir + fr'\faddom.xlsx'):
        svc_usr, svc_pwd = get_svc_cred(file=cred_dir + fr'\{svc_cred_file}')
        if all([svc_usr, svc_pwd]):
            export_faddom_data(svr=svr, usr=svc_usr, pwd=svc_pwd, api_map=api_map)
    
if __name__ == '__main__':
    my_logger.info(f'\nstart: {datetime.now().replace(microsecond=0)}')
    faddom_job()
    my_logger.info(f'end: {datetime.now().replace(microsecond=0)}')
