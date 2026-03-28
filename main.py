import psutil as ps

for process in ps.process_iter():
    try:
        pid = process.pid
        name = process.name()
        cmd = process.cmdline()
        if not cmd:
            cmd_str = "N/A"
        else:
            cmd_str = " ".join(map(str, cmd))

        print(f"PID: {pid} | Name: {name} | CMD: {cmd_str}\n")
    except (ps.AccessDenied, ps.NoSuchProcess):
        print(f"PID: {process.pid} | Access denied or process has ended")

