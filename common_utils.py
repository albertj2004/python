import os
import sys
from glob import glob
import shutil
import logging
import threading
from time import sleep
from pathlib import Path
from datetime import datetime, timedelta
import threading
from concurrent.futures import ThreadPoolExecutor
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def set_logger(**kwargs):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    # formatter = logging.Formatter('%(asctime)s| %(message)s', '%Y%m%d %H:%M:%S')
    formatter = logging.Formatter('%(message)s')
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.DEBUG)
    stdout_handler.setFormatter(formatter)

    log_file = kwargs.get('file', 'csm.log')
    log_file = Path(log_file)
    # if os.path.exists(log_file):
    #     os.remove(log_file)
        
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stdout_handler)
    return logger                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        

def file_up_to_date(**kwargs):
    fname = kwargs.get('file')
    return os.path.exists(fname) and datetime.now() - datetime.fromtimestamp(os.path.getmtime(fname)) < timedelta(hours=12)

def copy_files(**kwargs):
    dst_dir = kwargs.get('dst_dir')
    src_files = kwargs.get('src_files')
    for file in glob(src_files):
        shutil.copy(file, dst_dir)

def str2file(**kwargs):
    fname = kwargs.get('file')
    v_str = kwargs.get('str')
    mode = kwargs.get('mode', 'w')
    with open(fname, mode) as f:
        f.write(str(v_str))
    print(f"\nsave {fname}")

def file2str(**kwargs):
    fname = kwargs.get('file')
    with open(fname, "r") as f:
        print(f"\nread {fname}")
        return f.read()

def run_task(task_info, daemon=False):  # run_task((func, (a1, a2), {'k1': v1, 'k2': v2}))
    task_args, task_kwargs = (), {}
    if callable(task_info):
        task_func = task_info
    else:
        task_func = task_info[0]
        if len(task_info) > 1:
            task_args = task_info[1]
        if len(task_info) > 2:
            task_kwargs = task_info[2]
    if task_args:
        thread_instance = threading.Thread(target=task_func, args=task_args, kwargs=task_kwargs, daemon=daemon)
    else:
        thread_instance = threading.Thread(target=task_func, kwargs=task_kwargs, daemon=daemon)
    thread_instance.start()
    return thread_instance

def task(name, **kwargs):
    duration = kwargs.get('duration')
    print(f"Task {name} starting.")
    sleep(duration)
    result = f"Task {name} completed after {duration} seconds."
    print(result)
    return result

def parallel_func(**kwargs):
    func_list = kwargs.get('func')
    args_list = kwargs.get('args')
    kwargs_list = kwargs.get('kwargs')
    max_worker = kwargs.pop('max_worker', 10)

    if args_list and type(args_list) is not list:
        assert type(args_list) is tuple
    if kwargs_list and type(kwargs_list) is not list:
        assert type(kwargs_list) is dict
    total = max(len(func_list) if type(func_list) is list else 0, len(args_list) if type(args_list) is list else 0, len(kwargs_list) if type(kwargs_list) is list else 0)

    if type(func_list) is not list:
        func_list = [func_list] * total
    
    if args_list:
        if type(args_list) is not list:
            args_list = [args_list] * total
    else:
        args_list = [()] * total
    if kwargs_list:
        if type(kwargs_list) is not list:
            kwargs_list = [kwargs_list] * total
    else:
        kwargs_list = [{}] * total
    
    with ThreadPoolExecutor() as executor:        
        q, results = [], []
        run = 0
        for func, args, kwargs in zip(func_list, args_list, kwargs_list):
            q.append(executor.submit(func, *args, **kwargs))
            run += 1
            if run == max_worker:
                completed_q = []
                while True:
                    for p in q:
                        if p.done():
                            completed_q.append(p)
                            results.append(p.result())
                            run -= 1
                    if run < max_worker:
                        break
                    else:
                        sleep(1)
                [q.remove(p) for p in completed_q]
        if q:
            results += [p.result() for p in q]
    return results
