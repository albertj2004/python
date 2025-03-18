from common_utils import set_logger 
from csm_cfg import csm, data_dir
import csm_api
from csm_api import csm_keep_alive, csm_ping

if __name__ == '__main__':
    log_file = data_dir + fr'\csm_session.log'    
    csm_api.my_logger = set_logger(file=log_file)
    csm_ping(csm=csm, cookie_file=data_dir + fr'\cookie.txt')
    # csm_Logout(cookie_file=local_dir + fr'\cookie.txt')
    csm_keep_alive(csm=csm, cookie_file=data_dir + fr'\cookie.txt')
