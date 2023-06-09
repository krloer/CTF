#!/usr/bin/env python3.9
import dis
import readline  # pylint: disable=unused-import
import types
import random
import string

with open("flag.txt", encoding="utf-8") as f:
	flag = f.read().strip()

def all_code_objects(code):
	yield code
	for const in code.co_consts:
		if isinstance(const, types.CodeType):
			yield from all_code_objects(const)

def main():
	
	allowed_instructions = [
		#unary
		"UNARY_POSITIVE",
		"UNARY_NEGATIVE",
		"UNARY_NOT",
		"UNARY_INVERT",
		"GET_ITER",
		# binary
		"STORE_SUBSCR",
		"COMPARE_OP",
		"IS_OP",
		"CONTAINS_OP",
		# comprehensions
		"SET_ADD",
		"LIST_APPEND",
		"MAP_ADD",
		# misc
		"RETURN_VALUE",
		"CALL_FUNCTION",
		"MAKE_FUNCTION",
		"BUILD_SLICE",
		"EXTENDED_ARG",
		"FOR_ITER",
		# variables
		"STORE_NAME",
		"STORE_GLOBAL",
		"STORE_FAST",
		"LOAD_CONST",
		"LOAD_NAME",
		"LOAD_GLOBAL",
		"LOAD_FAST",
		# collections
		"BUILD_TUPLE",
		"BUILD_LIST",
		"BUILD_SET",
		"BUILD_MAP",
		"BUILD_STRING",
		"LIST_EXTEND",
		"SET_UPDATE",
		"DICT_UPDATE",
		#jumps
		"JUMP_FORWARD",
		"POP_JUMP_IF_TRUE",
		"POP_JUMP_IF_FALSE",
		"JUMP_IF_TRUE_OR_POP",
		"JUMP_IF_FALSE_OR_POP",
		"JUMP_ABSOLUTE"
	]
	
	# unnecessary globals slow us down
	allowed_globals = vars(__builtins__).copy()
	for var in (
		"getattr", "setattr", "eval", "exec", "__import__", "open", "__builtins__", "breakpoint",
		"help"
	):
		allowed_globals[var] = None
	
	while True:
		if random.random() < 0.1:
			print("Stuck? Here's a hint:")
			letter = random.choice(string.ascii_lowercase)
			print(f"There are {flag.count(letter)} {letter}'s in the flag!")
		try:
			inp = input("> ")
		except (EOFError, KeyboardInterrupt):
			exit()
		
		if not inp:
			continue
		
		code = compile(inp, "", "exec")
		
		for subcode in all_code_objects(code):
			for instruction in dis.Bytecode(subcode):
				# unnecessary instructions slow us down
				if instruction.opname not in allowed_instructions and not (
					instruction.opname.startswith("BINARY_") or
					instruction.opname.startswith("INPLACE_")
				):
					print("INPLACE OR BINARY OP!")
					break
			else:
				break
			
			for name in subcode.co_names + subcode.co_varnames:
				# long variable names slow us down
				if len(name) > 5:
					print("TOO LONG SYMBOL!")
					break
			else:
				break
		else:
			print("Illegal!")
			continue
		
		try:
			exec(code, allowed_globals.copy())
		except Exception:
			print("Error!")

if __name__ == "__main__":
	main()