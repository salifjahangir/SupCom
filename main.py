import psutil as ps
import detection_engine as deng
import logger
import time
import datetime

# Defining a set to hold the PID values already seen.
pids_seen = set()
# Initializing an object for tracking suspicious behaviour of commands.
detect_behaviour = deng.BehaviourDetector()

# Setting preference for creating logs.
while True:
    logging_preference = input("Do you want to log findings? (y/n)")
    if logging_preference.lower() == 'y':
        logging_enabled = True
        break
    elif logging_preference.lower() == 'n':
        logging_enabled = False
        break
    else:
        print("Retry with valid input!")

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
                formatted_time = datetime.datetime.now()
            else:
                continue
            # Storing process command as a string.
            if not cmd:
                cmd_str = "N/A"
            else:
                cmd_str = " ".join(map(str, cmd))

            # Checking for suspicion based on command string.
            is_suspicious, comment = deng.detect_suspicious(name, cmd_str)
            if is_suspicious:
                print(f"PID: {pid} | Name: {name} | CMD: {cmd_str}")
                print(f"[!] {comment}")

                # Detecting burst behaviour of suspicious commands.
                if cmd_str == "N/A":
                    continue
                else:
                    suspicious_behaviour = detect_behaviour.detect(cmd_str, start_time)
                    if suspicious_behaviour:
                        behaviour_comment = "Suspicious repeated behaviour of command detected"
                        print(f"{behaviour_comment} | Command: {cmd_str}")
                        if logging_enabled:
                            logger.log_event(name, cmd_str, pid, formatted_time, behaviour_comment)
                    else:
                        if logging_enabled:
                            logger.log_event(name, cmd_str, pid, formatted_time, comment)
                        
        except (ps.AccessDenied, ps.NoSuchProcess):
            print(f"PID: {pid} | Access denied or process has ended")

    time.sleep(1)

