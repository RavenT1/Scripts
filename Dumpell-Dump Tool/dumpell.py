import sys
import psutil
import win32process
import win32con
import win32api
import lief
from colorama import Fore, Style

first_run = True

def list_processes():
    processes = {}
    for proc in psutil.process_iter(['pid', 'name']):
        processes[proc.info['pid']] = proc.info['name']
    return processes

def dump_memory(pid, address, size, output_file):
    try:
        process_handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, pid)
        buffer = win32process.ReadProcessMemory(process_handle, address, size)
        with open(output_file, 'wb') as f:
            f.write(buffer)
        print(f"Memory dump saved to {output_file}")
    except Exception as e:
        print(f"An error occurred: {e}")

def print_usage():
    print(Fore.YELLOW + "Usage: python dumpell.py [options]")
    print("Options:")
    print("  --help  : Show this help message")
    print("  --pid   : List running process IDs and their names")
    print("  --dump  : Perform memory dump operation")
    print("  --opcode_search : Search for specified opcodes in an executable")
    print(Style.RESET_ALL)

def print_process_info():
    processes = list_processes()
    print("Running processes:")
    for pid, name in processes.items():
        print(f"PID: {pid}, Name: {name}")

def perform_memory_dump():
    print_process_info()
    selected_pid = int(input("Enter the PID of the process you want to dump: "))
    address = int(input("Enter the starting address in hexadecimal (without '0x'): "), 16)
    size = int(input("Enter the size of memory to dump (in bytes): "))
    output_file = input("Enter the path for the output dump file: ")

    if selected_pid not in list_processes():
        print(Fore.RED + "Invalid PID.")
        print(Style.RESET_ALL)
        return

    dump_memory(selected_pid, address, size, output_file)

def search_opcodes_in_exe(exe_path, opcodes):
    try:
        binary = lief.parse(exe_path)
    except lief.parser_error as e:
        print("Parser error:", e)
        return

    found_opcodes = []
    for section in binary.sections:
        section_content = section.content
        for i in range(len(section_content)):
            if section_content[i:i + len(opcodes)] == opcodes:
                found_opcodes.append((section.name, hex(section.virtual_address + i)))

    return found_opcodes

def opcode_search():
    exe_path = input("Enter the path to the executable file: ")
    opcodes_str = input("Enter the opcode sequence (without spaces, e.g., '90A1B2'): ")
    opcodes = bytes.fromhex(opcodes_str)

    found_opcodes = search_opcodes_in_exe(exe_path, opcodes)
    if found_opcodes:
        print("Found at:")
        for section, address in found_opcodes:
            print(f"Section: {section}, Address: {address}")
    else:
        print("Opcode sequence not found in the executable.")

if __name__ == "__main__":
    if first_run:
        print(Fore.GREEN + "      *********************************************")
        print(r"""
          _____                             _ _ 
         |  __ \                           | | |
         | |  | |_   _ _ __ ___  _ __   ___| | |
         | |  | | | | | '_ ` _ \| '_ \ / _ \ | |
         | |__| | |_| | | | | | | |_) |  __/ | |
         |_____/ \__,_|_| |_| |_| .__/ \___|_|_|
                                | |             
                                |_|             
            """)
        print("      *********************************************")
        print(Style.RESET_ALL)
        first_run = False

    if len(sys.argv) == 1 or "--help" in sys.argv:
        print_usage()
        sys.exit(0)

    if "--pid" in sys.argv:
        print_process_info()
        sys.exit(0)

    if "--dump" in sys.argv:
        perform_memory_dump()
        sys.exit(0)

    if "--opcode_search" in sys.argv:
        opcode_search()
        sys.exit(0)

    print(Fore.RED + "Invalid option. Use --help for usage instructions.")
    print(Style.RESET_ALL)
