import lief

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


if __name__ == "__main__":
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
