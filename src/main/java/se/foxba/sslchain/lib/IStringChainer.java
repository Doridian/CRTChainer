package se.foxba.sslchain.lib;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;

public class IStringChainer extends IChainer {
	public IStringChainer(File caLibraryFile, boolean intermediatesOnly) {
		super(caLibraryFile, intermediatesOnly);
	}

	public String convert(String in) {
		return new String(convert(in.getBytes()));
	}

	public byte[] convert(byte[] in) {
		ByteArrayInputStream inStream = new ByteArrayInputStream(in);
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		convert(inStream, outStream);
		return outStream.toByteArray();
	}
}
