// Create a function at an address (vector targets are disassembled through the vector pointers but
// Ghidra does not make them functions). Script arg: <address>
//@category Testing

import ghidra.app.script.GhidraScript;

public class CreateFunction extends GhidraScript {
	@Override
	protected void run() throws Exception {
		createFunction(toAddr(getScriptArgs()[0]), null);
	}
}
