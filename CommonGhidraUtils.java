import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.OptionalInt;
import java.util.OptionalLong;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.app.util.bin.format.pe.SectionHeader;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.Msg;

public class CommonGhidraUtils {
	private FlatProgramAPI f;
	
	public CommonGhidraUtils(FlatProgramAPI f) {
		this.f = f;
	}
	
	public List<Address> getCallAddresses(String functionName) {
		List<Address> addresses = new ArrayList<>();
		Function resolver = f.getGlobalFunctions(functionName).get(0);
		for (Reference ref : f.getReferencesTo(resolver.getEntryPoint())) {
			if (ref.getReferenceType() != RefType.UNCONDITIONAL_CALL)
				continue;
			addresses.add(ref.getFromAddress());
		}
		return addresses;
	}
	
	class UnknownVariableCopy extends Exception {
		public UnknownVariableCopy(PcodeOp unknownCode, Address addr) {
			super(String.format("unknown opcode %s for variable copy at %08X", unknownCode.getMnemonic(),
					addr.getOffset()));
		}
	}
	
	public OptionalLong traceVarnodeValue(Varnode argument) throws UnknownVariableCopy {
		while (!argument.isConstant()) {
			PcodeOp ins = argument.getDef();
			if (ins == null)
				break;
			switch (ins.getOpcode()) {
			case PcodeOp.CAST:
			case PcodeOp.COPY:
				argument = ins.getInput(0);
				break;
			case PcodeOp.PTRSUB:
			case PcodeOp.PTRADD:
				argument = ins.getInput(1);
				break;
			case PcodeOp.INT_MULT:
			case PcodeOp.MULTIEQUAL:
				// known cases where an array is indexed
				return OptionalLong.empty();
			default:
				// don't know how to handle this yet.
				throw new UnknownVariableCopy(ins, argument.getAddress());
			}
		}
		return OptionalLong.of(argument.getOffset());
	}

	public OptionalLong[] getConstantCallArgument(Address addr, int[] argumentIndices)
			throws IllegalStateException, UnknownVariableCopy {
		int argumentPos = 0;
		OptionalLong argumentValues[] = new OptionalLong[argumentIndices.length];
		Function caller = f.getFunctionBefore(addr);
		if (caller == null)
			throw new IllegalStateException();

		DecompInterface decompInterface = new DecompInterface();
		decompInterface.openProgram(f.getCurrentProgram());
		DecompileResults decompileResults = decompInterface.decompileFunction(caller, 120, f.getMonitor());
		if (!decompileResults.decompileCompleted())
			throw new IllegalStateException();

		HighFunction highFunction = decompileResults.getHighFunction();
		Iterator<PcodeOpAST> pCodes = highFunction.getPcodeOps(addr);
		while (pCodes.hasNext()) {
			PcodeOpAST instruction = pCodes.next();
			if (instruction.getOpcode() == PcodeOp.CALL) {
				for (int index : argumentIndices) {
					argumentValues[argumentPos] = traceVarnodeValue(instruction.getInput(index));
					argumentPos++;
				}
			}
		}
		return argumentValues;
	}
	
	public OptionalLong getConstantCallArgument(Address addr)
			throws IllegalStateException, UnknownVariableCopy {
		int[] i = {1};
		return getConstantCallArgument(addr, i)[0];
	}
	
	public OptionalInt getSection(String name) throws IOException {
    	ByteProvider byteProvider = new MemoryByteProvider(f.getCurrentProgram().getMemory(),
                f.getCurrentProgram().getImageBase());
        PortableExecutable portableExecutable = null;
        try {
            portableExecutable =
                    PortableExecutable.createPortableExecutable(RethrowContinuesFactory.INSTANCE,
                            byteProvider, PortableExecutable.SectionLayout.MEMORY);
        } catch (IOException e) {
            Msg.error(this, e.toString());
            byteProvider.close();
            return OptionalInt.empty();
        }
        
        for (SectionHeader h : portableExecutable.getNTHeader().getFileHeader().getSectionHeaders())
        	if(h.getName().equals(name)) {
        		return OptionalInt.of(h.getVirtualAddress());
        	}
        return OptionalInt.empty();
    }
	

}
