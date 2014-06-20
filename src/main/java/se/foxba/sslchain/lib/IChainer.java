package se.foxba.sslchain.lib;

import org.bouncycastle.openssl.PEMWriter;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.Security;
import java.security.cert.X509Certificate;

public abstract class IChainer {
	protected final CALibrary caLibrary;

	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	protected IChainer(File caLibraryFile) {;
		this.caLibrary = new CALibrary(caLibraryFile);
	}

	public void convert(InputStream in, OutputStream out, boolean intermediatesOnly) {
		try {
			CRTLoader crtLoader = new CRTLoader(in);
			X509Certificate[] chain = X509CertificateChainBuilder.buildPath(crtLoader, caLibrary);
			PEMWriter crtWriter = new PEMWriter(new OutputStreamWriter(out));
			for(int i = (intermediatesOnly ? 1 : 0); i < chain.length; i++)
				crtWriter.writeObject(chain[i]);
			crtWriter.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
