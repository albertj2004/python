from datetime import datetime
from pathlib import Path
import requests 
from requests.auth import HTTPBasicAuth
import pandas as pd
from io import StringIO
from common_utils import *
import faddom_cfg
from faddom_cfg import *

def export_data(**kwargs):
    usr = kwargs.get('usr')
    pwd = kwargs.get('pwd')
    url = kwargs.get('url')
    status = False
    try:
        response = requests.get(url, auth=HTTPBasicAuth(usr, pwd), verify=False)
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
    if file_up_to_date(file=excel_file):
        print(f"{Path(excel_file).name} up to date")
        return

    with pd.ExcelWriter(excel_file, mode='w') as writer:
        for name, api in api_map.items():
            print(f'export {name}...')
            url = f"https://{svr}/WebServices{api}"
            status, result = export_data(usr=usr, pwd=pwd, url=url)
            if status:
                df = pd.read_csv(StringIO(result))
                df.to_excel(writer, sheet_name=name, index=False)

def faddom_job(**kwargs):
    global data_dir, my_logger, svc_usr, svc_pwd
    # svc_usr, svc_pwd = get_svc_cred(file=cred_dir + fr'\{svc_cred_file}')
    svc_usr, svc_pwd = get_svc_cred(file=cred_dir + fr'\{svc_cred_file}', mode='manual', save_flag=True)
    if not all([svc_usr, svc_pwd]):
        return

    my_logger = faddom_cfg.my_logger
    kwargs['source'] = data_type
    data_dir = mk_day_dir(**kwargs)
    my_logger.info(f'\nstart: {datetime.now().replace(microsecond=0)}')
    export_faddom_data(svr=svr, usr=svc_usr, pwd=svc_pwd, api_map=api_map)
    my_logger.info(f'end: {datetime.now().replace(microsecond=0)}')
    
if __name__ == '__main__':
    faddom_job()
