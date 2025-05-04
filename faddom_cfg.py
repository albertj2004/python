from common_cfg import *
import common_utils
from common_utils import *

data_type = 'Faddom'
svc_name = 'faddom'
data_dir = mk_day_dir(source=data_type)
log_file = mk_day_dir(source=data_type) + fr'\{svc_name}.log'
common_utils.my_logger = my_logger = set_logger(file=log_file)

svr = 'faddom'
api_map = {
'ipgroup': '/clusters/exportIpGroups',
'vm': '/discovery/vmware/exportVMwareVms', 
'topology': '/export/exportTopologyToCSV?runGlobalFilters=False'
}
get_timeout_sec = 600
svc_cred_file = f'{svc_name}.cred'
