import os
import subprocess
from common_cfg import job_dir

job_code_map = {
    'Faddom': 'faddom.py', 
    'F5': 'f5.py',
    'CSM': 'csm.py'
}
python_exe = 'python'

def f3_job():
    job_pid_map = []
    for job, code in job_code_map.items():
        if os.path.exists(job_dir + fr'\{code}'):
            job_pid_map.append((job, subprocess.Popen([python_exe, code], cwd=job_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)))

    for job, pid in job_pid_map:
        stdout, stderr = pid.communicate()
        if pid.returncode == 0:
            print(f"Job {job} success")
        else:
            print(f"Job {job} fail:\n{stderr.decode()}")

if __name__ == '__main__':
    # python -m zipapp csm -m f3_job:run_jobs -o dist\f3_job.pyz
    f3_job()
