// Decode a list of records with the current program's language, without loading them into
// memory: each record starts at a byte offset of a data file and is decoded as if at address
// ram:<chunk base>+<offset in chunk>. Prints "<index> <length> <text>" ("0 BAD" if rejected).
// Script args: <recs.txt> <data.bin> <outfile>; recs.txt lines: "<index> <file offset> <address>"
//@category Testing

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;

public class DumpRecs extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		byte[] data = Files.readAllBytes(Paths.get(args[1]));
		PrintStream out = new PrintStream(args[2]);
		Language lang = currentProgram.getLanguage();
		ProcessorContextImpl ctx = new ProcessorContextImpl(lang);
		try (BufferedReader r = new BufferedReader(new FileReader(args[0]))) {
			String line;
			while ((line = r.readLine()) != null) {
				String[] f = line.trim().split("\\s+");
				int off = Integer.parseInt(f[1]);
				Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(
					Long.parseLong(f[2], 16));
				byte[] buf = new byte[8];
				System.arraycopy(data, off, buf, 0, Math.min(8, data.length - off));
				String text;
				int n;
				try {
					MemBuffer mb = new ByteMemBufferImpl(a, buf, false);
					InstructionPrototype proto = lang.parse(mb, ctx, false);
					PseudoInstruction pi = new PseudoInstruction(currentProgram, a, proto, mb, ctx);
					text = pi.toString();
					n = pi.getLength();
				}
				catch (Exception e) {
					text = "BAD";
					n = 0;
				}
				out.printf("%s %d %s%n", f[0], n, text);
			}
		}
		out.close();
	}
}
