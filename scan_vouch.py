import os
import json
import re

def scan_vouch():
    vouch_src = "/Users/jon/vouch/src"
    units = []
    
    for root, dirs, files in os.walk(vouch_src):
        for file in files:
            if file.endswith(".rs"):
                path = os.path.join(root, file)
                rel_path = os.path.relpath(path, "/Users/jon/vouch")
                
                with open(path, 'r') as f:
                    content = f.read()
                
                # Extract basic dependencies (mod/use)
                deps = []
                for line in content.split('\n'):
                    if line.startswith('use ') or line.startswith('mod '):
                        # Simple regex for crate/module imports
                        match = re.search(r'(?:use|mod)\s+([a-zA-Z0-9_:]+)', line)
                        if match:
                            dep = match.group(1).split('::')[0]
                            # Only track local vs external if needed, but for now let's just track high-level
                            deps.append(dep)
                
                units.append({
                    "id": file,
                    "code": content,
                    "dependencies": list(set(deps)),
                    "required_headers": [],
                    "path": rel_path
                })
    
    output_path = "/Users/jon/.gemini/antigravity/brain/fd4385f2-72cc-404c-9116-da831bf46c28/vouch_units.json"
    with open(output_path, 'w') as f:
        json.dump(units, f, indent=2)
    
    print(f"Successfully wrote {len(units)} units to {output_path}")

if __name__ == "__main__":
    scan_vouch()
