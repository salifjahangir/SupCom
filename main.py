import psutil as ps
import detection_engine as deng
import time

# Defining a set to hold the PID values already seen.
pids_seen = set()
#Defining the dictionary for holding command strings along with their list of timestamps.
cmd_tracked = {}
# Defining a set to hold the commands that have already been flagged for suspicious behaviour.
cmd_alerted = set()
# Initializing an object for tracking suspicious behaviour of commands.
detect_behaviour = deng.BehaviourDetector()
while True:
    for process in ps.process_iter():
        pid = None

        try:
            pid = process.pid
            name = process.name()
            cmd = process.cmdline()

            if pid not in pids_seen:
                pids_seen.add(pid)
                start_time = time.time()
            else:
                continue
            # Storing process command as a string.
            if not cmd:
                cmd_str = "N/A"
            else:
                cmd_str = " ".join(map(str, cmd))

            is_suspicious, comment = deng.detect_suspicious(name, cmd_str)
            if is_suspicious:
                print(f"PID: {pid} | Name: {name} | CMD: {cmd_str}")
                print(f"[!] {comment}")

                # Detecting burst behaviour of suspicious commands.
                if cmd_str == "N/A":
                    continue
                else:
                    suspicious_behaviour = detect_behaviour.process(cmd_str, start_time)
                    if suspicious_behaviour:
                        print(f"Suspicious behaviour of command detected | Command: {cmd_str}")
                        
        except (ps.AccessDenied, ps.NoSuchProcess):
            print(f"PID: {pid} | Access denied or process has ended")

