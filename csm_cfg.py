import os
from datetime import datetime

csm = 'csm'
today = datetime.now().strftime('%Y%m%d')
share_dir = f'D:\csm\data\{today}\csm'
data_dir=f'D:\data\{today}\csm'
os.makedirs(data_dir, exist_ok=True)
