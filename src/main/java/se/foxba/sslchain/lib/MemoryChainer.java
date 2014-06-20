package se.foxba.sslchain.lib;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;

public class MemoryChainer extends IChainer {
	public MemoryChainer(File caLibraryFile) {
		super(caLibraryFile);
	}

	public String convert(String in, boolean intermediateOnly) {
		return new String(convert(in.getBytes(), intermediateOnly));
	}

	public byte[] convert(byte[] in, boolean intermediateOnly) {
		ByteArrayInputStream inStream = new ByteArrayInputStream(in);
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		convert(inStream, outStream, intermediateOnly);
		return outStream.toByteArray();
	}
}
