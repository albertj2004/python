from common_cfg import *
import common_utils
from common_utils import *

data_type = 'F5'
sys_name = 'f5'
log_file = mk_day_dir(source=data_type) + fr'\{sys_name}.log'
common_utils.my_logger = my_logger = set_logger(file=log_file)

cfg_file = f'{sys_name}.cfg.yaml'
if not check_dirs(dirs=[job_dir + fr'\{cfg_file}']):
    exit(0)

cfg_data = read_yaml_file(file=job_dir + fr'\{cfg_file}')
f5_broken_list = [f5.strip() for f5 in cfg_data['f5_broken_list'].strip().split('\n')]
f5_list = [f5.strip().split('.')[0] for f5 in cfg_data['f5_list'].strip().split('\n')]
f5_list = sorted(set(f5_list))
f5_working_list = [f5 for f5 in f5_list if f5 not in f5_broken_list]
f5_working_list = sorted(set(f5_working_list))

bigiq_obj_url_map = ltm_obj_url_map = {
    'vs':  '/mgmt/tm/ltm/virtual',
    'pool': '/mgmt/tm/ltm/pool',
    'rule': '/mgmt/tm/ltm/rule',
    'profile': '/mgmt/tm/ltm/profile',
    'self': '/mgmt/tm/net/self',
    'monitor': '/mgmt/tm/ltm/monitor',
    'node': '/mgmt/tm/ltm/node',
    'persistence': '/mgmt/tm/ltm/persistence',
    'policy': '/mgmt/tm/ltm/policy',
}

ltm_obj_attr_map = {
    'vs': ['profiles', 'policies'],
    'pool': ['members'],
}

link_objs = ['persistence', 'profile', 'monitor']

dns_type_list = ['a', 'aaaa', 'cname', 'mx', 'naptr', 'srv']

gtm_obj_url_map = {
    'dc':  '/mgmt/tm/gtm/datacenter',
    'top':  '/mgmt/tm/gtm/topology',
    'dns':  '/mgmt/tm/gtm/wideip',
    'pool':  '/mgmt/tm/gtm/pool',
    'prober_pool':  '/mgmt/tm/gtm/prober-pool',
    'server':  '/mgmt/tm/gtm/server',
    'listener':  '/mgmt/tm/gtm/listener',
    'monitor':  '/mgmt/tm/gtm/monitor',
}

gtm_obj_attr_map = {
    'server': ['devices', 'virtual-servers'],
    'prober-pool': ['members'],
}

svc_cred_file = f'{sys_name}.cred'
