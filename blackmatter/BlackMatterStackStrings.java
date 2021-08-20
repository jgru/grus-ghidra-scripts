//Decodes stack strings by utilizing Unicorn's emulation capabilities
//@author jgru
//@category
//@keybinding 
//@menupath 
//@toolbar 

import java.nio.charset.StandardCharsets;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import unicorn.Unicorn;
import unicorn.UnicornException;

public class BlackMatterStackStrings extends GhidraScript {

	// Memory address of the code segment
	private static final int CODE_ADDRESS = 0x1000000;
	private static int CODE_LEN = 0x1000;

	// Address of the stack
	private static final int STACK_ADDRESS = 0x90000;
	private static int STACK_LEN = 4096;

	public void run() throws Exception {
		println("Running stack string decoder");

		// Declare variables to populate, either via selection or dialog pop-ups
		Address startAddr = null;
		byte[] code;
		int len = 0;
		
		// Uses code range selection from Ghidra's UI
		if (currentSelection != null) {
			startAddr = currentSelection.getMinAddress();
			len = (int) (currentSelection.getMaxAddress().getOffset() - startAddr.getOffset()) + 4; // Compensate jump
																									
			println(String.format("Start address: %02X", startAddr.getOffset()));
			println(String.format("End address: %02X", currentSelection.getMaxAddress().getOffset()));

		} else { // Displays dialogs to ask for memory addresses
			int start = askInt("Enter start address", "Enter address to start emulation");
			int end = askInt("Enter end address", "Enter end address");
			len = end - start; // Compensate jump opcodes
			startAddr = currentAddress.getNewAddress(start);
		}

		code = new byte[len];
		currentProgram.getMemory().getBytes(startAddr, code);

		byte[] stackMem = emuAndReadStack(code);
		String s = retrieveString(stackMem);
		println("Decoded result: " + s);
		currentProgram.getListing().setComment(startAddr, CodeUnit.PRE_COMMENT, s);
	}

	String retrieveString(byte[] b) {
		int start = -1;
		int end = -1;

		for (int i = 0; i < b.length - 1; i += 2) {
			if (b[i] == 0 && b[i + 1] == 0) {
				if (start != -1) {
					end = i - 1;
					break;
				}
			} else {
				if (start == -1) {
					start = i;
				}
			}
		}

		if (start != -1 && end > 0)
			return new String(b, start - 1, end - start + 1, StandardCharsets.UTF_16);

		return null;
	}

	byte[] emuAndReadStack(byte[] codeToEmu) {
		println("Emulating i386 code");

		// Initializes the emulator in X86-32bit mode
		Unicorn uc;
		try {
			uc = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_32);

		} catch (UnicornException uex) {
			println("Failed on uc_open() with error returned: " + uex);
			return null;
		}

		// Maps memory for code segment and stack segment
		uc.mem_map(STACK_ADDRESS, STACK_LEN, Unicorn.UC_PROT_ALL);
		uc.mem_map(CODE_ADDRESS, CODE_LEN, Unicorn.UC_PROT_EXEC);

		try {
			// Clears memory
			uc.mem_write(STACK_ADDRESS, new byte[STACK_LEN]);
			uc.mem_write(CODE_ADDRESS, new byte[CODE_LEN]);
			// Writes machine code to be emulated to code segment
			uc.mem_write(CODE_ADDRESS, codeToEmu);

		} catch (UnicornException uex) {
			println("Failed to write emulation code to memory, quit!\n");
			return null;
		}
		// Initializes stack registers
		uc.reg_write(Unicorn.UC_X86_REG_EBP, STACK_ADDRESS + 256);
		uc.reg_write(Unicorn.UC_X86_REG_ESP, STACK_ADDRESS + 512);

		// Emulate the machine code within 10 seconds
		try {
			uc.emu_start(CODE_ADDRESS, CODE_ADDRESS + CODE_LEN, 0, 0);
		} catch (UnicornException uex) {
			println("Failed on uc_emu_start() with error : %s\n" + uex.getMessage());
		}

		byte[] tmp = null;

		// Read stack memory
		try {
			tmp = uc.mem_read(STACK_ADDRESS, STACK_LEN);
		} catch (UnicornException ex) {
			println("Failed to read stack memory at [0x%x]\n" + STACK_ADDRESS);
		}

		uc.close();

		return tmp;
	}

}
