package se.foxba.sslchain.lib;

import se.foxba.sslchain.lib.CALibrary;
import se.foxba.sslchain.lib.CRTLoader;
import se.foxba.sslchain.lib.X509CertificateChainBuilder;
import org.bouncycastle.openssl.PEMWriter;

import java.io.File;
import java.io.FileWriter;
import java.security.Security;
import java.security.cert.X509Certificate;

public abstract class IChainer {
	private final boolean intermediatesOnly;
	private final CALibrary caLibrary;

	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	protected IChainer(File caLibraryFile, boolean intermediatesOnly) {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		this.caLibrary = new CALibrary(caLibraryFile);
		this.intermediatesOnly = intermediatesOnly;
	}

	public abstract File transformFile(File in);

	public void convert(File in) {
		if(in.isDirectory())
			for(File file : in.listFiles())
				_convert(file, transformFile(file));
		 else
			_convert(in, transformFile(in));
	}

	private void _convert(File in, File out) {
		try {
			CRTLoader crtLoader = new CRTLoader(in);
			X509Certificate[] chain = X509CertificateChainBuilder.buildPath(crtLoader, caLibrary);
			PEMWriter crtWriter = new PEMWriter(new FileWriter(out));
			for(int i = (intermediatesOnly ? 1 : 0); i < chain.length; i++)
				crtWriter.writeObject(chain[i]);
			crtWriter.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
