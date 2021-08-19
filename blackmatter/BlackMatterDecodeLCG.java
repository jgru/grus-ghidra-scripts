//Decodes BlackMatter's string buffers, which were crypted by using a linear congruential generator
//@author jgru
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import java.io.IOException;
import java.util.OptionalInt;
import java.util.OptionalLong;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;

public class BlackMatterDecodeLCG extends GhidraScript {
	private String DIR_NAME = ".rsrc"; 
	CommonGhidraUtils utils; 
	
    public void run() throws Exception {
    	this.utils = new CommonGhidraUtils(this);
		String decoderFunc = null;
		try {
			decoderFunc = askString("Enter Name", "Enter the name of the decoding function below:",
					getFunctionBefore(currentAddress.next()).getName());
		} catch (CancelledException X) {
			return;
		}
//		long addr = askInt("Enter address", "Enter address of the function call to decode its buffer arg"); 
//		
		OptionalLong seed = retrieveSeed();
		
		if(seed.isEmpty()) {
			println("Could not find seed");
		return;
		}

		for (Address callAddr : utils.getCallAddresses(decoderFunc)) {
			monitor.setMessage(String.format("parsing call at %08X", callAddr.getOffset()));
			decode(callAddr, seed.getAsLong());
		}
    }
    private void decode(Address addr, long seed) throws MemoryAccessException {
		OptionalLong ol;
		try {
			ol = utils.getConstantCallArgument(addr);
		} catch (IllegalStateException | CommonGhidraUtils.UnknownVariableCopy e) {
			((Throwable) e).printStackTrace();
			return;
		}
		
		if (ol.isEmpty()) {
			println(String.format("Argument to call at %08X is not a block of memory.", addr.getOffset()));
			return;
		}
				
		long buf = ol.getAsLong();
		Address bufAddr = currentAddress.getNewAddress(buf);
		decodeArgBuf(bufAddr, seed);
    }
    private OptionalLong retrieveSeed() throws IOException, MemoryAccessException {
		// Retrieve rsrc-section, where the seed value is stored
		OptionalInt sectRVA = utils.getSection(DIR_NAME);
		if(sectRVA.isEmpty()) {
			println("Error finding section with name " + DIR_NAME);
			return OptionalLong.empty(); 
		}

		// Retrieve seed address 
		Address seedAddr = currentAddress.getNewAddress(currentProgram.getImageBase().getOffset() + sectRVA.getAsInt());
		println(String.format("Section of interest at %08X .", seedAddr.getOffset()));
		
		// Retrieve seed value for LCG
		long seed  = currentProgram.getMemory().getInt(seedAddr) & 0xFFFFFFFFL; 
		println(String.format("Seed %08X ", seed));
		
		return OptionalLong.of(seed);
    }
    private void decodeArgBuf(Address bufAddr, long seed) throws MemoryAccessException{
		Address lenAddr = bufAddr.subtract(4);
		int len = currentProgram.getMemory().getInt(lenAddr);
		println(String.format("Buffer Length %08X ", len));
		
		// Iterate and perform decoding
    	Address a = bufAddr;
    	long lastSeed = seed & 0xFFFFFFFFL; 
    	
    	// Perform XORing with pseudo-random numbers produced by LCG
    	for(int i = 0; i < len; i += 4) {
    		long newSeed = (lastSeed * 0x8088405 + 1) & 0xFFFFFFFFL;
    		long v =  newSeed * seed;
    		int x = (int) ((v >> 0x20) & 0xFFFFFFFFL);
    	
    		try {
    			int r = currentProgram.getMemory().getInt(a) ^ x;
    			currentProgram.getMemory().setInt(a, r);    		
    		}catch (MemoryAccessException e) {
    			println(String.format("Could not read memory at %08X ", a.getOffset()));
    			break;
    		}
    		
    		lastSeed = newSeed;
    		println(String.format("Last seed %08X ", lastSeed));
    		a = a.add(4); 
    	}
    }
}
