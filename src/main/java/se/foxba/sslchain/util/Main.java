package se.foxba.sslchain.util;

import se.foxba.sslchain.lib.IFileChainer;

import java.io.File;

public class Main {
	private static boolean isTruthy(String val) {
		if(val == null)
			return false;
		val = val.toLowerCase();
		return val.equals("1") || val.equals("true") || val.equals("y") || val.equals("yes") || val.equals("on");
	}

	public static void main(String[] args) {
		if(args.length != 3)  {
			System.err.println("Usage: crtchainer [CADir/CAFile] [in] [out]");
			return;
		}

		final boolean intermediatesOnly = isTruthy(System.getProperty("intermediatesOnly"));
		final File caLibraryFile = new File(args[0]);

		final File in = new File(args[1]);
		final File out = new File(args[2]);

		if(in.isDirectory()) {
			out.mkdirs();

			new IFileChainer(caLibraryFile, intermediatesOnly) {
				@Override
				public File transformFile(File in) {
					return new File(out, in.getName());
				}
			}.convert(in);
		} else {
			new IFileChainer(caLibraryFile, intermediatesOnly) {
				@Override
				public File transformFile(File in) {
					return out;
				}
			}.convert(in);
		}
	}
}
