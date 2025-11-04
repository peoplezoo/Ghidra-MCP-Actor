# Ghidra Analysis Export Script (Jython 2.7)
# This script runs inside Ghidra's headless analyzer to extract program analysis data
# @category: Analysis

import json
import sys
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def export_analysis():
    """
    Main function to export comprehensive analysis data from Ghidra.
    Outputs a JSON file with functions, strings, imports, exports, and more.
    """

    # Get the current program being analyzed
    program = currentProgram
    if program is None:
        print("ERROR: No program loaded")
        return

    print("[*] Starting analysis export for: " + program.getName())

    # Initialize decompiler
    decompiler = DecompInterface()
    decompiler.openProgram(program)

    # Data structure to hold all analysis results
    analysis_data = {
        "metadata": {},
        "functions": [],
        "strings": [],
        "imports": [],
        "exports": [],
        "sections": [],
        "references": {}
    }

    # Extract metadata
    print("[*] Extracting metadata...")
    analysis_data["metadata"] = {
        "name": program.getName(),
        "executable_path": program.getExecutablePath(),
        "executable_format": program.getExecutableFormat(),
        "language": program.getLanguageID().getIdAsString(),
        "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
        "min_address": str(program.getMinAddress()),
        "max_address": str(program.getMaxAddress()),
        "image_base": str(program.getImageBase())
    }

    # Extract functions
    print("[*] Extracting functions...")
    function_manager = program.getFunctionManager()
    functions = function_manager.getFunctions(True)  # True = forward iteration

    for func in functions:
        func_name = func.getName()
        func_entry = func.getEntryPoint()
        func_data = {
            "name": func_name,
            "address": str(func_entry),
            "size": func.getBody().getNumAddresses(),
            "signature": str(func.getSignature()),
            "call_count": func.getCallingFunctions(ConsoleTaskMonitor()).size(),
            "calls": [],
            "decompiled": None,
            "is_thunk": func.isThunk(),
            "is_external": func.isExternal()
        }

        # Get called functions
        called_funcs = func.getCalledFunctions(ConsoleTaskMonitor())
        for called in called_funcs:
            func_data["calls"].append({
                "name": called.getName(),
                "address": str(called.getEntryPoint())
            })

        # Decompile function
        try:
            results = decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())
            if results and results.decompileCompleted():
                decomp_code = results.getDecompiledFunction().getC()
                func_data["decompiled"] = decomp_code
        except Exception as e:
            func_data["decompiled"] = "// Decompilation failed: " + str(e)

        analysis_data["functions"].append(func_data)

    print("[*] Extracted " + str(len(analysis_data["functions"])) + " functions")

    # Extract strings
    print("[*] Extracting strings...")
    memory = program.getMemory()
    listing = program.getListing()

    # Iterate through all defined data looking for strings
    data_iterator = listing.getDefinedData(True)
    for data in data_iterator:
        if data.hasStringValue():
            string_value = data.getValue()
            if string_value:
                analysis_data["strings"].append({
                    "address": str(data.getAddress()),
                    "value": str(string_value),
                    "length": len(str(string_value)),
                    "refs": data.getReferenceIteratorTo().hasNext()
                })

    print("[*] Extracted " + str(len(analysis_data["strings"])) + " strings")

    # Extract imports
    print("[*] Extracting imports...")
    symbol_table = program.getSymbolTable()
    external_manager = program.getExternalManager()

    for ext_name in external_manager.getExternalLibraryNames():
        for ext_loc in external_manager.getExternalLocations(ext_name):
            analysis_data["imports"].append({
                "library": ext_name,
                "function": ext_loc.getLabel(),
                "address": str(ext_loc.getAddress()) if ext_loc.getAddress() else "N/A"
            })

    print("[*] Extracted " + str(len(analysis_data["imports"])) + " imports")

    # Extract exports (symbols marked for export)
    print("[*] Extracting exports...")
    for symbol in symbol_table.getAllSymbols(True):
        if symbol.isExternalEntryPoint():
            analysis_data["exports"].append({
                "name": symbol.getName(),
                "address": str(symbol.getAddress())
            })

    print("[*] Extracted " + str(len(analysis_data["exports"])) + " exports")

    # Extract memory sections
    print("[*] Extracting memory sections...")
    for block in memory.getBlocks():
        analysis_data["sections"].append({
            "name": block.getName(),
            "start": str(block.getStart()),
            "end": str(block.getEnd()),
            "size": block.getSize(),
            "read": block.isRead(),
            "write": block.isWrite(),
            "execute": block.isExecute()
        })

    print("[*] Extracted " + str(len(analysis_data["sections"])) + " sections")

    # Write JSON output
    output_path = "/tmp/analysis_output/ghidra_analysis.json"
    print("[*] Writing output to: " + output_path)

    try:
        with open(output_path, 'w') as f:
            json.dump(analysis_data, f, indent=2)
        print("[+] Analysis export completed successfully!")
    except Exception as e:
        print("ERROR writing output: " + str(e))
        sys.exit(1)

    # Cleanup
    decompiler.dispose()

# Run the export
if __name__ == "__main__":
    export_analysis()
