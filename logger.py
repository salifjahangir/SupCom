def log_event(name, command, pid, timestamp, comment):
    filename = 'logfile.txt'
    with open(filename, 'a') as file_object:
        file_object.write(f"""-------------------------------------------------\n
{str(timestamp)}
Name: {name}
Command: {command}
PID: {str(pid)}
Comment: {comment}\n
-------------------------------------------------\n""")
        
        
