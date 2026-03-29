import psutil as ps
import detection_engine as deng

for process in ps.process_iter():
    pid = None
    try:
        pid = process.pid
        name = process.name()
        cmd = process.cmdline()
        if not cmd:
            cmd_str = "N/A"
        else:
            cmd_str = " ".join(map(str, cmd))

        is_suspicious, comment = deng.detect_suspicious(name, cmd_str)
        if is_suspicious:
            print(f"PID: {pid} | Name: {name} | CMD: {cmd_str}")
            print(f"[!] {comment}")
    except (ps.AccessDenied, ps.NoSuchProcess):
        print(f"PID: {pid} | Access denied or process has ended")

