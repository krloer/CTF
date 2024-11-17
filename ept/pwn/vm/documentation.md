# Virtual Machine (VM) Documentation

Welcome to the documentation for the custom Virtual Machine (VM). This guide provides comprehensive information about the VM's architecture, instruction set, and opcodes. It is intended for developers and enthusiasts interested in understanding or extending the VM's capabilities.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Architecture Overview](#architecture-overview)
   - [Registers](#registers)
   - [Memory](#memory)
   - [Flags Register](#flags-register)
3. [Instruction Set Design](#instruction-set-design)
   - [Instruction Format](#instruction-format)
   - [Addressing Modes](#addressing-modes)
   - [Data Types](#data-types)
4. [Opcodes and Instructions](#opcodes-and-instructions)
   - [Data Movement Instructions](#data-movement-instructions)
   - [Arithmetic Instructions](#arithmetic-instructions)
   - [Bitwise Instructions](#bitwise-instructions)
   - [Control Flow Instructions](#control-flow-instructions)
   - [I/O Instructions](#io-instructions)
   - [Comparison Instructions](#comparison-instructions)
   - [System Instructions](#system-instructions)
5. [Detailed Opcode Reference](#detailed-opcode-reference)
6. [Examples](#examples)
   - [Hello World Program](#hello-world-program)
   - [Byte Swap Program](#byte-swap-program)
   - [Overflow Detection Program](#overflow-detection-program)
7. [Assembler Usage](#assembler-usage)
8. [Conclusion](#conclusion)
9. [Appendix](#appendix)
   - [Register Summary](#register-summary)
   - [Flags Register Bits](#flags-register-bits)
   - [Instruction Encoding Example](#instruction-encoding-example)

---

## Introduction

This Virtual Machine (VM) simulates a simple CPU with a custom instruction set architecture (ISA), registers, memory, and a set of operations. It is designed to execute machine code generated from assembly programs written using the provided instruction set.

The VM supports basic arithmetic operations, data movement, control flow, bitwise operations, and special features such as an overflow flag and extended memory addressing.

---

## Architecture Overview

### Registers

The VM has **8 general-purpose 16-bit registers**:

- **R0** to **R7**

Additionally, there are special-purpose registers:

- **SEG**: 16-bit segment register used for extended memory addressing.
- **SP**: 32-bit stack pointer (not fully utilized in the current instruction set).
- **PC**: 32-bit program counter, pointing to the next instruction to execute.
- **FLAGS**: 8-bit flags register containing status flags.

### Memory

- **Size**: The VM has **128 KB** of byte-addressable memory, ranging from `0x00000` to `0x1FFFF`.
- **Addressing**: Memory is accessed using 16-bit addresses, extended with the segment register for addresses beyond `0xFFFF`.
- **Endianness**: Little-endian format is used when storing and loading 16-bit words.

### Flags Register

The **FLAGS** register is an 8-bit register used to store status flags resulting from operations:

- **Zero Flag (ZF, bit 1)**: Set when a comparison or arithmetic operation results in zero.
- **Overflow Flag (OF, bit 2)**: Set when an arithmetic operation results in an overflow beyond 16 bits.

---

## Instruction Set Design

### Instruction Format

Each instruction in the VM is **4 bytes** long and follows a fixed format:

- **Opcode (1 byte)**: Specifies the operation to perform.
- **Operand1 (1 byte)**: First operand or destination register.
- **Operand2 (1 byte)**: Second operand, register, or high byte of immediate/address.
- **Operand3 (1 byte)**: Third operand, immediate value, or low byte of immediate/address.

**Example:**

+---------+----------+----------+----------+ 
| Opcode | Operand1 | Operand2 | Operand3 | 
+---------+----------+----------+----------+


### Addressing Modes

The VM supports several addressing modes:

- **Immediate**: Operand is a constant value embedded in the instruction.
- **Register Direct**: Operand is a value in a register.
- **Memory Direct**: Operand is a memory address specified in the instruction.
- **Register Indirect**: Operand is a memory address held in a register.

### Data Types

- **Byte**: 8 bits.
- **Word**: 16 bits.

---

## Opcodes and Instructions

### Data Movement Instructions

| Mnemonic | Opcode | Description                                        |
|----------|--------|----------------------------------------------------|
| `NOP`    | 0x00   | No operation                                       |
| `MOV`    | 0x01   | Move data between registers                        |
| `MOVI`   | 0x02   | Move immediate value to register                   |
| `LOAD`   | 0x03   | Load byte from memory to register                  |
| `STORE`  | 0x04   | Store byte from register to memory                 |
| `LOADI`  | 0x05   | Load byte from memory address in a register        |
| `XCHG`   | 0x06   | Exchange values between two registers              |
| `LOADW`  | 0x07   | Load word (16 bits) from memory to register        |
| `STOREW` | 0x08   | Store word (16 bits) from register to memory       |
| `MOVS`   | 0x23   | Move immediate value to segment register (`SEG`)   |

### Arithmetic Instructions

| Mnemonic | Opcode | Description                                         |
|----------|--------|-----------------------------------------------------|
| `ADD`    | 0x10   | Add register to register                            |
| `ADDI`   | 0x11   | Add immediate value to register                     |
| `SHL`    | 0x12   | Shift register left by immediate value              |
| `SHR`    | 0x13   | Shift register right by immediate value             |

### Bitwise Instructions

*Note: Bitwise instructions may not be implemented by default but can be added.*

| Mnemonic | Opcode | Description                                         |
|----------|--------|-----------------------------------------------------|
| `AND`    | 0x14   | Bitwise AND between registers                       |
| `OR`     | 0x15   | Bitwise OR between registers                        |
| `XOR`    | 0x16   | Bitwise XOR between registers                       |
| `NOT`    | 0x17   | Bitwise NOT of a register                           |

### Control Flow Instructions

| Mnemonic | Opcode | Description                                         |
|----------|--------|-----------------------------------------------------|
| `JMP`    | 0x20   | Unconditional jump to address                       |
| `JE`     | 0x21   | Jump if zero flag is set                            |
| `JO`     | 0x22   | Jump if overflow flag is set                        |

### I/O Instructions

| Mnemonic | Opcode | Description                                         |
|----------|--------|-----------------------------------------------------|
| `OUT`    | 0x40   | Output lower 8 bits of a register                   |

### Comparison Instructions

| Mnemonic | Opcode | Description                                         |
|----------|--------|-----------------------------------------------------|
| `CMP`    | 0x50   | Compare register with immediate value               |

### System Instructions

| Mnemonic | Opcode | Description                                         |
|----------|--------|-----------------------------------------------------|
| `HLT`    | 0xFF   | Halt execution                                      |

---

## Detailed Opcode Reference

Below is a detailed description of each opcode, including its operands and effects.

### `NOP` (0x00)

- **Description**: No operation. The VM does nothing and proceeds to the next instruction.
- **Format**: `NOP`

### `MOV` (0x01)

- **Description**: Move data from one register to another.
- **Format**: `MOV dest, src`
- **Operands**:
  - `dest` (Operand1): Destination register (0-7 for R0-R7).
  - `src` (Operand2): Source register (0-7 for R0-R7).
- **Example**: `MOV R1, R0` (Copy the value from R0 to R1).

### `MOVI` (0x02)

- **Description**: Move an immediate 16-bit value into a register.
- **Format**: `MOVI reg, imm`
- **Operands**:
  - `reg` (Operand1): Destination register.
  - `imm` (Operand2 & Operand3): 16-bit immediate value.
- **Example**: `MOVI R0, 0x1234` (Load 0x1234 into R0).

### `LOAD` (0x03)

- **Description**: Load a byte from memory into a register.
- **Format**: `LOAD reg, addr`
- **Operands**:
  - `reg` (Operand1): Destination register.
  - `addr` (Operand2 & Operand3): 16-bit memory address.
- **Addressing**: Effective address is `(SEG << 16) | addr`.
- **Example**: `LOAD R0, 0x1000` (Load byte from address into R0).

### `STORE` (0x04)

- **Description**: Store the lower 8 bits of a register into memory.
- **Format**: `STORE addr, reg`
- **Operands**:
  - `addr` (Operand2 & Operand3): 16-bit memory address.
  - `reg` (Operand1): Source register.
- **Addressing**: Effective address is `(SEG << 16) | addr`.
- **Example**: `STORE 0x1000, R0` (Store lower 8 bits of R0 into address).

### `LOADI` (0x05)

- **Description**: Load a byte from a memory address specified in a register.
- **Format**: `LOADI dest, addr_reg`
- **Operands**:
  - `dest` (Operand1): Destination register.
  - `addr_reg` (Operand2): Register containing the memory address.
- **Example**: `LOADI R0, R1` (Load byte from address in R1 into R0).

### `XCHG` (0x06)

- **Description**: Exchange the values of two registers.
- **Format**: `XCHG reg1, reg2`
- **Operands**:
  - `reg1` (Operand1): First register.
  - `reg2` (Operand2): Second register.
- **Example**: `XCHG R0, R1` (Swap values in R0 and R1).

### `LOADW` (0x07)

- **Description**: Load a word (16 bits) from memory into a register.
- **Format**: `LOADW reg, addr`
- **Operands**:
  - `reg` (Operand1): Destination register.
  - `addr` (Operand2 & Operand3): 16-bit memory address.
- **Addressing**: Effective address is `(SEG << 16) | addr`.
- **Example**: `LOADW R0, 0x1000` (Load word from address into R0).

### `STOREW` (0x08)

- **Description**: Store a word (16 bits) from a register into memory.
- **Format**: `STOREW addr, reg`
- **Operands**:
  - `addr` (Operand2 & Operand3): 16-bit memory address.
  - `reg` (Operand1): Source register.
- **Addressing**: Effective address is `(SEG << 16) | addr`.
- **Example**: `STOREW 0x1000, R0` (Store word from R0 into address).

### `ADD` (0x10)

- **Description**: Add the value of one register to another.
- **Format**: `ADD dest, src`
- **Operands**:
  - `dest` (Operand1): Destination register (and first operand).
  - `src` (Operand2): Source register (second operand).
- **Flags Affected**:
  - **Overflow Flag**: Set if the result exceeds 16 bits.
- **Example**: `ADD R0, R1` (R0 = R0 + R1).

### `ADDI` (0x11)

- **Description**: Add an immediate value to a register.
- **Format**: `ADDI reg, imm`
- **Operands**:
  - `reg` (Operand1): Destination register.
  - `imm` (Operand2 & Operand3): 16-bit immediate value.
- **Flags Affected**:
  - **Overflow Flag**: Set if the result exceeds 16 bits.
- **Example**: `ADDI R0, 0x10` (R0 = R0 + 0x10).

### `SHL` (0x12)

- **Description**: Shift a register's value left by a specified number of bits.
- **Format**: `SHL reg, imm`
- **Operands**:
  - `reg` (Operand1): Register to shift.
  - `imm` (Operand3): Number of bits to shift (0-15).
- **Flags Affected**:
  - **Overflow Flag**: Set if bits are shifted out.
- **Example**: `SHL R0, 1` (R0 = R0 << 1).

### `SHR` (0x13)

- **Description**: Shift a register's value right by a specified number of bits.
- **Format**: `SHR reg, imm`
- **Operands**:
  - `reg` (Operand1): Register to shift.
  - `imm` (Operand3): Number of bits to shift (0-15).
- **Example**: `SHR R0, 1` (R0 = R0 >> 1).

### `JMP` (0x20)

- **Description**: Unconditional jump to a specified address.
- **Format**: `JMP addr`
- **Operands**:
  - `addr` (Operand2 & Operand3): 16-bit address.
- **Addressing**: Effective address is `(SEG << 16) | addr`.
- **Example**: `JMP start` (Jump to label `start`).

### `JE` (0x21)

- **Description**: Jump to a specified address if the zero flag is set.
- **Format**: `JE addr`
- **Operands**:
  - `addr` (Operand2 & Operand3): 16-bit address.
- **Example**: `JE loop` (Jump to `loop` if ZF is set).

### `JO` (0x22)

- **Description**: Jump to a specified address if the overflow flag is set.
- **Format**: `JO addr`
- **Operands**:
  - `addr` (Operand2 & Operand3): 16-bit address.
- **Example**: `JO overflow_handler` (Jump if OF is set).

### `MOVS` (0x23)

- **Description**: Move an immediate value into the segment register (`SEG`).
- **Format**: `MOVS imm`
- **Operands**:
  - `imm` (Operand2 & Operand3): 16-bit immediate value.
- **Example**: `MOVS 1` (Set `SEG` to 1).

### `OUT` (0x40)

- **Description**: Output the lower 8 bits of a register.
- **Format**: `OUT reg`
- **Operands**:
  - `reg` (Operand1): Source register.
- **Example**: `OUT R0` (Output lower 8 bits of R0).

### `CMP` (0x50)

- **Description**: Compare a register's value with an immediate value.
- **Format**: `CMP reg, imm`
- **Operands**:
  - `reg` (Operand1): Register to compare.
  - `imm` (Operand2 & Operand3): 16-bit immediate value.
- **Flags Affected**:
  - **Zero Flag**: Set if `reg` equals `imm`.
- **Example**: `CMP R0, 0x00` (Compare R0 with 0x00).

### `HLT` (0xFF)

- **Description**: Halt execution.
- **Format**: `HLT`
- **Example**: `HLT` (Stop the VM).

---

## Examples

