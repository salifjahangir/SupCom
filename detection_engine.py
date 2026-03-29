def detect_suspicious(name, command):
    flagged_keywords = ['-enc', 'base64']
    name = name.lower()
    command = command.lower()

    for flag in flagged_keywords:
        if flag in command:
            if "powershell" in name:
                return (True, "Powershell with encoded command detected")
            else:
                return (True, "Encoded command detected")
    
    return (False, "No suspicious process detected")

