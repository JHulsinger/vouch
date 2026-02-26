import subprocess
import time
import sys

sessions = ["agent-hooks", "agent-eab", "agent-keys", "agent-mandatory", "agent-renew-expiry", "agent-renew-hook"]

print("Monitoring agent sessions...", flush=True)
while True:
    try:
        output = subprocess.check_output(["tmux", "ls"], text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        output = "" # no sessions running
        
    running = []
    for s in sessions:
        if s in output:
            running.append(s)
            
    if not running:
        print("\nAll agents finished!", flush=True)
        break
        
    print(f"Still running: {', '.join(running)}", flush=True)
    time.sleep(10)
