package se.foxba.sslchain.lib;

import org.bouncycastle.openssl.PEMWriter;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.security.cert.X509Certificate;

public abstract class IFileChainer extends IChainer {
	public abstract File transformFile(File in);

	protected IFileChainer(File caLibraryFile, boolean intermediatesOnly) {
		super(caLibraryFile, intermediatesOnly);
	}

	public void convert(File in) {
		if(in.isDirectory())
			for(File file : in.listFiles())
				_convert(file, transformFile(file));
		else
			_convert(in, transformFile(in));
	}

	private void _convert(File in, File out) {
		try {
			convert(new FileInputStream(in), new FileOutputStream(out));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
