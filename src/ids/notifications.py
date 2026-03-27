import os
import sys

# Notification script for MacOS
def notification(timestamp:str, message:str): 
    command = f'''
    osascript -e 'display notification "{message}" with title "{timestamp}"'
    '''
    os.system(command)
