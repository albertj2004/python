from common_cfg import *
import common_utils
from common_utils import *

data_type = 'Faddom'
sys_name = 'faddom'
log_file = mk_day_dir(source=data_type) + fr'\{sys_name}.log'
common_utils.my_logger = my_logger = set_logger(file=log_file)

svr = 'faddom'
api_map = {
'ipgroup': '/clusters/exportIpGroups',
'vm': '/discovery/vmware/exportVMwareVms', 
'topology': '/export/exportTopologyToCSV?runGlobalFilters=False'
}
svc_cred_file = f'{sys_name}.cred'
