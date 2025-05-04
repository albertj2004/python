from common_cfg import *
import common_utils
from common_utils import *

data_type = 'Firewall'
svc_name = 'csm'
data_dir = mk_day_dir(source=data_type)
log_file = data_dir + fr'\{svc_name}.log'
common_utils.my_logger = my_logger = set_logger(file=log_file)

csm = 'csmho'
dev_regex = '.*'
dev_exclude_regex = r'[_-](sys|admin)(_|-|$)'
svc_cred_file = f'{svc_name}.cred'

max_policy_rules = 500
excel_cell_text_lmt = 32767
policy_obj_types = [
    'NetworkPolicyObject', 
    'ServicePolicyObject', 
    'PortListPolicyObject', 
    'InterfaceRolePolicyObject',
    'IdentityUserGroupPolicyObject',
    'TimeRangePolicyObject',
    'SecurityGroupPolicyObject',
    ]
