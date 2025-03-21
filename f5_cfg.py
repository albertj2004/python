import os
from datetime import datetime

share_dir = f'D:\F5'
data_dir=f'D:\F5'
os.makedirs(data_dir, exist_ok=True)

f5_adm_list = """
ltm_1
ltm_2
""".strip().split('\n')
f5_adm_list = [h.strip() for h in f5_adm_list]

broken_dev_list = """
ltm_3
""".strip().split('\n')
broken_dev_list = [h.strip() for h in broken_dev_list]


set F5=gtm
set USER=<>
set PWD=<>
curl -k -X POST "https://%F5%/mgmt/shared/authn/login" ^
-H "Content-Type: application/json" ^
-d "{\"username\":\"%USER%\",\"password\":\"%PWD%\",\"loginProviderName\":\"tmos\"}"
"""
