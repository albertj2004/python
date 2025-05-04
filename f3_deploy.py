import os
import shutil
import subprocess
import py_compile

app_map = {
    'common': ['common_cfg.py', 'common_utils.py'],
    'faddom': ['faddom_cfg.py', 'faddom.py'],
    'f5': ['f5.cfg.yaml', 'f5_cfg.py', 'f5.py'],
    'csm': ['csm_cfg.py', 'csm.py'],
    # 'fw': ['fw.hit.cfg.yaml', 'fw_hit_cfg.py', 'fw_hit.py'],
    'f3': ['common_cfg.py', 'f3.py']
}

job_dir = fr'D:\data\job'
def build_app_pyz(app_name, add_common=True):
    temp_dir = fr'{job_dir}\{app_name}'
    print(temp_dir)
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    os.makedirs(temp_dir, exist_ok=True)
    name_list = [app_name]
    if add_common:
        name_list += ['common']
    for name in name_list:
        for fname in app_map[name]:
            if not os.path.exists(fname):
                print(f'no {fname}')
                shutil.rmtree(temp_dir)
                exit(0)
                
            if fname[-4:] in ['yaml']:
                shutil.copyfile(fname, job_dir + fr'\{fname}')
                print(f'copy {fname}')
            else:
                pyc_file = temp_dir + fr'\{fname}c'
                py_compile.compile(fname, cfile=pyc_file, optimize=2)
    
    cmd_list = [
        fr'python -m zipapp {temp_dir} -m {app_name}:{app_name}_job -o {job_dir}\{app_name}.py'
    ]
    for cmd in cmd_list:
        print(cmd)
        subprocess.run(cmd, cwd=job_dir, shell=True)
    shutil.rmtree(temp_dir)

for app_name in app_map.keys():
    if app_name != 'common':
        if app_name in ['f3']:
            build_app_pyz(app_name, add_common=False)
        else:
            build_app_pyz(app_name)
