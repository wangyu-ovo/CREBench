# Decompile all functions and export to JSON

import json
from ghidra.app.decompiler import DecompInterface

def find_main(function_map):
    if "entry" not in function_map:
        return None
    entry = function_map["entry"]
    libc = entry.find("__libc_start_main(")
    if libc == -1:
        return None
    funcend = entry.find(',', libc)
    if funcend == -1:
        return None
    return entry[libc + 18:funcend]

def export(filename):
    function_map = {}
    address_map = {}
    main_func = None
    
    ifc = DecompInterface()
    ifc.openProgram(currentProgram)
    
    for func in currentProgram.getListing().getFunctions(True):
        res = ifc.decompileFunction(func, 0, monitor)
        if not res.decompileCompleted():
            print("Error: " + res.getErrorMessage())
            continue
        
        code = res.getDecompiledFunction().getC()
        function_map[func.getName()] = code
        address_map[str(func.getEntryPoint())] = func.getName()
        print(func.getName())
    
    if "main" not in function_map:
        main_func = find_main(function_map)
    
    json_data = {
        "functions": function_map,
        "addresses": address_map
    }
    if main_func:
        json_data["main"] = main_func
    
    with open(filename, 'w') as f:
        json.dump(json_data, f, indent=2)

# Main execution
args = getScriptArgs()
export(args[0])