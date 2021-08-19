// Rebuild the imports of BlackMatter
//@author jgru (building up on a script of larsborn)
//@category _NEW_
//@keybinding
//@menupath
//@toolbar

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.OptionalLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;


public class BlackMatterApiHashing extends GhidraScript {
	CommonGhidraUtils utils; 
	
	@Override
	public void run() throws Exception {
		this.utils = new CommonGhidraUtils(this);
		
		String resolverFunc;

		try {
			resolverFunc = askString("Enter Name", "Enter the name of the API resolution function below:",
					getFunctionBefore(currentAddress.next()).getName());
		} catch (CancelledException X) {
			return;
		}

		File apiHashFile = askFile("Hash List", "Open");
		HashMap<Long, String> hashToFunc = parseHashFile(apiHashFile);

		long xorvalue = askInt("Enter the XOR key", "Enter the XOR key"); 
		
		for (Address callAddr : utils.getCallAddresses(resolverFunc)) {
			monitor.setMessage(String.format("parsing call at %08X", callAddr.getOffset()));
			resolveSingleCall(callAddr, hashToFunc, xorvalue);
		}
	}

	private void resolveSingleCall(Address callAddr, HashMap<Long, String> map, long xorValue) throws Exception {
		int arguments[] = { 1, 2 };
		OptionalLong options[] = utils.getConstantCallArgument(callAddr, arguments);

		if (options[0].isEmpty() || options[1].isEmpty()) {
			println(String.format("Argument to call at %08X is not a block of memory.", callAddr.getOffset()));
			return;
		}

		long result = options[0].getAsLong();
		long hash = options[1].getAsLong();

		if (result == 0 || hash == 0) {
			return;
		}
		println(String.format("Array of API hashes at %08X\nArray of function pointers at %08X", hash, result));

		Address resultAddr = currentAddress.getNewAddress(result);
		Address hashAddr = currentAddress.getNewAddress(hash);

		// Perform the resolution and label the addresses
		resolveApiHash(map, hashAddr, resultAddr, xorValue);
	}
	
	private void resolveApiHash(HashMap<Long, String> hm, Address hashAddr, Address resultAddr, long xorValue) {
		// Skip module hash
		Address currAddr = hashAddr.add(4);
		resultAddr = resultAddr.add(4);

		// Loop until 0xCCCCCCCC is found
		while (currAddr != null && !monitor.isCancelled()) {
			long value = 0;

			try {
				value = getInt(currAddr) & 0xFFFFFFFFL;
			} catch (MemoryAccessException e1) {
				e1.printStackTrace();
				return;
			}
			// End of list is reached
			if (value == 0xCCCCCCCCL)
				return;

			long ah = (value ^ xorValue) & 0xFFFFFFFFL;

			try {
				String funcName = hm.get(ah);

				if (funcName != null) {
					this.println(String.format("%08X %s", resultAddr.getOffset(), funcName));
					createLabel(resultAddr, funcName, true);
					createDWord(resultAddr);
				} else {
					this.println(String.format("%08X unknown hash %d", currAddr.getOffset(), funcName));
					println(String.format("%08X - %08X", ah, value));
				}				
			} catch (Exception e) {
				e.printStackTrace();
			}
			
			currAddr = currAddr.add(4);
			resultAddr = resultAddr.add(4);
		}
	}

	private HashMap<Long, String> parseHashFile(File apiHashFile) {

		List<String> lines;

		try {
			lines = Files.readAllLines(apiHashFile.toPath(), Charset.defaultCharset());
		} catch (IOException e) {
			this.println(String.format("File not found: %s", apiHashFile.getAbsolutePath()));
			return null;
		}

		HashMap<Long, String> hm = new HashMap<>();

		for (String line : lines) {
			Pattern patternDll = Pattern.compile("\"dll\"\\s*:\\s*\"(\\w*?.dll)\"");
			Pattern patternName = Pattern.compile("\"name\"\\s*:\\s*\"(\\w*?)\"");
			Pattern patternHash = Pattern.compile("\"hash\"\\s*:\\s*(\\d+)");

			Matcher matchDll = patternDll.matcher(line);
			Matcher matchName = patternName.matcher(line);
			Matcher matchHash = patternHash.matcher(line);

			if (!matchDll.find() || !matchName.find() || !matchHash.find())
				continue;

			long hashAsLong = Long.parseLong(matchHash.group(1));
			try {
				hm.put(hashAsLong, matchName.group(1));
			} catch (IllegalArgumentException e) {
			}

		}
		return hm;
	}

	
}
