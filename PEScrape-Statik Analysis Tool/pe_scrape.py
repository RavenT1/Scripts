import pefile
import hashlib
import math
import argparse
import datetime

import peutils
from colorama import Fore, Style, init

init()
# ASCII art
ascii_art = f"""{Fore.GREEN}
         ______          ______                             
        (_____ \        / _____)                            
         _____) )_____ ( (____    ____   ____  _____  ____  
        |  ____/| ___ | \____ \  / ___) / ___)(____ ||  _ \  
        | |     | ____| _____) )( (___ | |    / ___ || |_| |
        |_|     |_____)(______/  \____)|_|    \_____||  __/ 
                                                     |_|    

      ---------------------------------------------------------
      | Twitter: https://twitter.com/zayotem                  |
      | Github: https://github.com/ZAYOTEM                    |
      | Authors: Tolga Yılmaz                                 |
      ---------------------------------------------------------
      
{Style.RESET_ALL}"""

print(ascii_art)

def get_file_hash(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
        md5_hash = hashlib.md5(data).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()
    return md5_hash, sha256_hash

def calculate_entropy(data):
    if not data:
        return 0

    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

def analyze_os_dependencies(pe):
    dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
    os_dependencies = []

    # Check the availability of Windows API functions
    if dll_characteristics & 0x0001:
        os_dependencies.append("Relocation Stripped")
    if dll_characteristics & 0x0002:
        os_dependencies.append("Executable Image")
    if dll_characteristics & 0x0004:
        os_dependencies.append("Line Numbers Stripped")
    if dll_characteristics & 0x0008:
        os_dependencies.append("Local Symbols Stripped")
    if dll_characteristics & 0x0010:
        os_dependencies.append("Aggressive Working Set Trim")
    if dll_characteristics & 0x0020:
        os_dependencies.append("Large Address Aware")
    if dll_characteristics & 0x0080:
        os_dependencies.append("Bytes of machine word are reversed")
    if dll_characteristics & 0x0100:
        os_dependencies.append("Debugging information is removed from the image file")
    if dll_characteristics & 0x0200:
        os_dependencies.append("Run from swap file")
    if dll_characteristics & 0x0400:
        os_dependencies.append("Is a DLL")
    if dll_characteristics & 0x0800:
        os_dependencies.append("Up System Only")
    if dll_characteristics & 0x1000:
        os_dependencies.append("Bytes of machine word are reversed")
    if dll_characteristics & 0x2000:
        os_dependencies.append("32-bit word machine")
    if dll_characteristics & 0x4000:
        os_dependencies.append("Debugging information is removed from the image file")
    if dll_characteristics & 0x8000:
        os_dependencies.append("Run from swap file")

    return os_dependencies

def get_compiler_info(pe):
    # Check if the file is a .NET assembly
    if hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR'):
        return ".NET Assembly"

    # Check TimeDateStamp field in FILE_HEADER to determine compiler information
    compile_time = pe.FILE_HEADER.TimeDateStamp
    compile_date = datetime.datetime.utcfromtimestamp(compile_time)

    # Some heuristic checks based on known compiler date ranges
    if compile_date.year < 1990:
        return "Unknown (Possibly very old)"
    elif compile_date.year < 2000:
        return "Microsoft Visual C++ 6.0 or older"
    elif compile_date.year < 2005:
        return "Microsoft Visual C++ 7.0 / 7.1 (.NET)"
    elif compile_date.year < 2010:
        return "Microsoft Visual C++ 8.0 / 9.0"
    elif compile_date.year < 2013:
        return "Microsoft Visual C++ 10.0 / 11.0"
    elif compile_date.year < 2017:
        return "Microsoft Visual C++ 12.0 / 14.0"
    elif compile_date.year < 2020:
        return "Microsoft Visual C++ 15.0 / 16.0"
    else:
        return "Recent Visual C++ or other compiler"

def print_section_header(title):
    print("\n" + "-"*40)
    print(f"{' '*10}{title}")
    print("-"*40)

def analyze_imported_libraries(pe):
    print_section_header("Imported Libraries")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(f"    [+] {entry.dll.decode()} library")
        for func in entry.imports:
            if func.name:
                print(f"       [>] {func.name.decode()}")
            else:
                print(f"       [>] Ordinal {func.ordinal}")

def analyze_exported_functions(pe):
    print_section_header("Exported Functions")
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exported_func in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print(f"    [+] {exported_func.name.decode()}")

def check_anti_analysis(pe):
    anti_analysis_flags = []

    # Packed File Detection
    # if pe.FILE_HEADER.Characteristics & 0x0100:
    #   anti_analysis_flags.append("File is probably packed")

    # Debugger Detection
    if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040:
        anti_analysis_flags.append("Debugger Detection Flag Set")

    # Virtual Machine Detection
    if pe.FILE_HEADER.Machine == 0x014C and pe.OPTIONAL_HEADER.Magic == 0x10B:
        anti_analysis_flags.append("Emulation detected: x86 executable running on x64 emulator")

    # Sandbox Evasion Techniques
    # Check for presence of known sandbox artifacts, such as processes or registry keys
    sandbox_artifacts = ["\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                         "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                         "SbieDll.dll",
                         "Sandboxiedcomlaunch.exe"]
    for artifact in sandbox_artifacts:
        if artifact in pe.dump_dict():
            anti_analysis_flags.append("Sandbox artifact found: " + artifact)

    # Anti-Debugging Techniques
    anti_debugger_apis = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtGlobalFlag"]
    for api in anti_debugger_apis:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if any(api.lower() in imp.name.decode().lower() for imp in entry.imports if imp.name):
                    anti_analysis_flags.append(f"Anti-debugging API detected: {api}")

    # Anti-Antivirus Techniques
        if b"avp32.exe" in pe.get_memory_mapped_image():
            anti_analysis_flags.append("Known antivirus process detected: avp32.exe")

    return anti_analysis_flags


def analyze_malware(file_path, imported_lib=False, exported_func=False, anti_analysis=False):
    try:
        pe = pefile.PE(file_path)

        print_section_header("File Analysis Started")

        total_size = 0

        for section in pe.sections:
            total_size += section.SizeOfRawData

        # Convert total size to KB
        total_size_kb = total_size / 1024

        print(f" File Size: {total_size_kb:.2f} KB")
        print(f" Optional Header Size: {pe.FILE_HEADER.SizeOfOptionalHeader - pe.OPTIONAL_HEADER.SizeOfHeaders}")
        print(f" Visible Signature: {hex(pe.OPTIONAL_HEADER.CheckSum)}")
        print(f" Image Base Address: {hex(pe.OPTIONAL_HEADER.ImageBase)}")
        print(f" Number of Sections: {pe.FILE_HEADER.NumberOfSections}")

        # Compiler information
        print(f" Compiler: {get_compiler_info(pe)}")

        # Compilation time
        compile_time = pe.FILE_HEADER.TimeDateStamp
        print(f" Compile Time: {datetime.datetime.utcfromtimestamp(compile_time)}")

        print_section_header("Section Information")
        for section in pe.sections:
            section_entropy = calculate_entropy(section.get_data())
            print(f"\nSection Name: {section.Name.decode().strip('x00')}")
            print(f"   Section Size: {hex(section.SizeOfRawData)}")
            print(f"   Section RVA: {hex(section.VirtualAddress)}")
            print(f"   Section MD5 Hash: {section.get_hash_md5()}")
            print(f"   Section SHA256 Hash: {section.get_hash_sha256()}")
            print(f"   Entropy Value: {section_entropy:.2f}")

        print_section_header("Operating System Dependencies")
        os_dependencies = analyze_os_dependencies(pe)
        for dependency in os_dependencies:
            print(f"   {dependency}")

        print_section_header("File Hash Values")
        md5_hash, sha256_hash = get_file_hash(file_path)
        print(f"   MD5 Hash: {md5_hash}")
        print(f"   SHA256 Hash: {sha256_hash}")

        if imported_lib:
            analyze_imported_libraries(pe)

        if exported_func:
            analyze_exported_functions(pe)

        print_section_header("Total Entropy Value")

        with open(file_path, 'rb') as f:
            data = f.read()
            total_entropy = calculate_entropy(data)
            print(f"   File Total Entropy Value: {total_entropy}")

            entropy_threshold = 7.0
            if total_entropy > entropy_threshold:
                print("   The file is probably packaged or encrypted!")
            else:
                print("   The file is probably not packaged!")

            if args.anti_analysis:
                print_section_header("Anti-Analysis Flags")
                anti_analysis_flags = check_anti_analysis(pe)
                for flag in anti_analysis_flags:
                    print(f"   {flag}")


    except Exception as e:
        print("[!] Error:", str(e))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"{Fore.YELLOW}PE File Analysis Tool ")
    parser.add_argument("file_path", help="path to the file to analyze(with\"\")")
    parser.add_argument("--imported_lib", action="store_true", help="display imported libraries")
    parser.add_argument("--exported_func", action="store_true", help="display exported functions")
    parser.add_argument("--anti_analysis", action="store_true", help="check for anti-analysis techniques")

    args = parser.parse_args()

    analyze_malware(args.file_path, args.imported_lib, args.exported_func, args.anti_analysis)


