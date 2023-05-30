def parse_instruction(line):
    """Parse an instruction line and extract the opcode, registers, and memory address
    Returns:
        tuple: A tuple containing the opcode (str), registers (list), and memory address (str)"""
    line = line.strip()
    fields = line.split()
    opcode = fields[0]
    registers = fields[1:-1]
    mem_addr = fields[-1]
    return opcode, registers, mem_addr

def parse_variable(line):
    """Parse a variable definition line and extract the variable name
    Returns:
        str: The variable name"""
    line = line.strip()
    var_name = line.split()[1]
    return var_name

def validate_instruction_fields(opcode, registers, mem_addr, labels, variables):
    """Validate the fields of an instruction.
    Returns:
        bool: True if the instruction fields are valid, False otherwise."""
    supported_opcodes = ['mov', 'add', 'sub', 'mul', 'div', 'ld', 'st', 'jmp', 'jz', 'jn', 'hlt']
    supported_registers = ['R0', 'R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'FLAGS']
    valid = True

    if opcode not in supported_opcodes:
        print(f"Syntax Error: Unsupported instruction '{opcode}'")
        valid = False

    for reg in registers:
        if reg not in supported_registers:
            print(f"Syntax Error: Invalid register '{reg}'")
            valid = False

    if opcode in ['jmp', 'jz', 'jn'] and mem_addr not in labels:
        print(f"Syntax Error: Undefined label '{mem_addr}'")
        valid = False

    if opcode in ['ld', 'st'] and mem_addr not in variables:
        print(f"Syntax Error: Undefined variable '{mem_addr}'")
        valid = False

    if 'FLAGS' in registers and opcode != 'jz' and opcode != 'jn':
        print(f"Syntax Error: Illegal use of 'FLAGS' register in '{opcode}' instruction")
        valid = False

    return valid

def generate_binary(opcode, registers, mem_addr, labels, variables):
    """Generate the binary representation of an instruction.
    Returns:
        str: The binary representation of the instruction.
    """
    opcodes = {
        'mov': '0001',
        'add': '0010',
        'sub': '0011',
        'mul': '0100',
        'div': '0101',
        'ld': '0110',
        'st': '0111',
        'jmp': '1000',
        'jz': '1001',
        'jn': '1010',
        'hlt': '1101'
    }

    register_codes = {
        'R0': '000',
        'R1': '001',
        'R2': '010',
        'R3': '011',
        'R4': '100',
        'R5': '101',
        'R6': '110',
        'FLAGS': '111'
    }
    # Append opcode to binary instruction
    if opcode == 'hlt':
        return opcodes[opcode] + '0' * 11

    binary_instruction = opcodes[opcode]

    # Append register codes to binary instruction
    for reg in registers:
        binary_instruction += register_codes[reg]

    # Append memory address or immediate value to binary instruction
    if opcode in ['jmp', 'jz', 'jn']:
        if mem_addr in labels:
            binary_instruction += bin(labels[mem_addr])[2:].zfill(8)
        else:
            print(f"Syntax Error: Undefined label '{mem_addr}'")
            return None
    elif opcode in ['ld', 'st']:
        if mem_addr in variables:
            binary_instruction += bin(variables[mem_addr])[2:].zfill(8)
        else:
            print(f"Syntax Error: Undefined variable '{mem_addr}'")
            return None
    else:
        try:
            immediate = int(mem_addr[1:])
            if 0 <= immediate <= 1023:
                binary_instruction += bin(immediate)[2:].zfill(10)
            else:
                print(f"Syntax Error: Invalid Immediate value '{mem_addr}'")
                return None
        except ValueError:
            print(f"Syntax Error: Invalid Immediate value '{mem_addr}'")
            return None

    return binary_instruction

def assemble_program(program):
    """Assemble the given assembly program.
    Returns:
        list: The list of binary instructions if the program is error-free, None otherwise"""
    lines = program.split('\n')
    labels = {}
    variables = {}
    instructions = []
    line_num = 1

    # First pass: Parse labels and variables
    for line in lines:
        if line.strip() == '':
            continue

        if line.endswith(':'):
            label = line.strip()[:-1]
            if label in labels or label in variables:
                print(f"Syntax Error: Duplicate label or variable '{label}'")
                return None
            labels[label] = line_num
        elif line.startswith('var'):
            var_name = parse_variable(line)
            if var_name in labels or var_name in variables:
                print(f"Syntax Error: Duplicate label or variable '{var_name}'")
                return None
            variables[var_name] = len(variables)
        else:
            instructions.append(line)
        line_num += 1

    binary_instructions = []

    # Second pass: Parse and validate instructions, generate binary code
    for line in instructions:
        opcode, registers, mem_addr = parse_instruction(line)
        if not validate_instruction_fields(opcode, registers, mem_addr, labels, variables):
            return None
        binary = generate_binary(opcode, registers, mem_addr, labels, variables)
        if binary is None:
            return None
        binary_instructions.append(binary)

    return binary_instructions

def write_binary_file(binary_instructions, filename):
     #Write the binary instructions to a file.
    with open(filename, 'w') as file:
        for binary in binary_instructions:
            file.write(binary + '\n')

def main():
    # Read the assembly program from the assembl text file
    with open('assembl.txt', 'r') as file:
        program = file.read()

    # Assemble the program
    binary_instructions = assemble_program(program)
    if binary_instructions is not None:
        # Write the binary instructions to the output text file
        write_binary_file(binary_instructions, 'output.txt')

#calling main
if __name__ == '__main__':
    main()
