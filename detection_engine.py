from string import ascii_letters, digits


base64_chars = set(ascii_letters+digits+"+/=")
def _base64_char_check(word):
    """Helper function for checking for base64 string patterns"""
    for char in word:
        if char not in base64_chars:
            return False
        
    has_letter = any(letter in ascii_letters for letter in word)
    has_number = any(number in digits for number in word)
    has_symbol = any(symbol in "+/=" for symbol in word)

    if has_letter and has_number and has_symbol:
        return True
    else:
        return False
    

def detect_suspicious(name, command):
    """flags suspicious processes and keywords"""
    flagged_keywords = ['-enc', 'base64']
    name = name.lower()
    command = command.lower()
    command_words = command.split()

    for flag in flagged_keywords:
        if flag in command:
            if "powershell" in name:
                return (True, "PowerShell with encoded command detected")
            else:
                return (True, "Encoded command detected")
    
    for word in command_words:
        if len(word) > 20 and _base64_char_check(word):
            return (True, "Potential Base64 encoded command detected")
        
    
    return (False, "No suspicious process detected")


class BehaviourDetector:
    """Class for handling detection of suspicious burst commands."""
    def __init__(self):
        self.cmd_tracked = {}
        self.cmd_alerted = set()
        self.time_threshold = 5
        self.max_events = 3

    def process(self, command, start_time):
        if command not in self.cmd_tracked:
            self.cmd_tracked[command] = []
        timestamps = self.cmd_tracked[command]
        if len(timestamps) == self.max_events:
            timestamps.pop(0)
            timestamps.append(start_time)

        else:
            timestamps.append(start_time)

        if len(timestamps) == self.max_events:
            if (timestamps[-1] - timestamps[0] <= self.time_threshold):
                if command not in self.cmd_alerted:
                    self.cmd_alerted.add(command)
                    return True
                else:
                    return False
            else:
                return False
        else:
            return False
                

        



