from common_cfg import *
import common_utils
from common_utils import *

data_type = 'Firewall'
sys_name = 'csm'
log_file = mk_day_dir(source=data_type) + fr'\{sys_name}.log'
common_utils.my_logger = my_logger = set_logger(file=log_file)

csm = 'csm'
dev_regex = 'fw'
dev_exclude_regex = r'[_-](sys|admin|prd)(_|-|$)'
svc_cred_file = f'{sys_name}.cred'
