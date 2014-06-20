package se.foxba.sslchain.lib;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public abstract class IFileChainer extends IChainer {
	public abstract File transformFile(File in);

	protected IFileChainer(File caLibraryFile) {
		super(caLibraryFile);
	}

	public void convert(File in, boolean intermediateOnly) {
		if(in.isDirectory())
			for(File file : in.listFiles())
				_convert(file, transformFile(file), intermediateOnly);
		else
			_convert(in, transformFile(in), intermediateOnly);
	}

	private void _convert(File in, File out, boolean intermediateOnly) {
		try {
			convert(new FileInputStream(in), new FileOutputStream(out), intermediateOnly);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
