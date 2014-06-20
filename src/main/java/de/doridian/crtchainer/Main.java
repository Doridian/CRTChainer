package de.doridian.crtchainer;

import de.doridian.crtchainer.lib.CALibrary;
import de.doridian.crtchainer.lib.CRTLoader;
import de.doridian.crtchainer.lib.X509CertificateChainBuilder;
import org.bouncycastle.openssl.PEMWriter;

import java.io.File;
import java.io.FileWriter;
import java.security.Security;
import java.security.cert.X509Certificate;

public class Main {
	private static CALibrary caLibrary;

	public static void main(String[] args) {
		if(args.length != 3)  {
			System.err.println("Usage: crtchainer [CADir/CAFile] [in] [out]");
			return;
		}

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		caLibrary = new CALibrary(new File(args[0]));

		File in = new File(args[1]);
		File out = new File(args[2]);
		if(in.isDirectory()) {
			out.mkdirs();
			for(File file : in.listFiles()) {
				convert(file, new File(out, file.getName()));
			}
		} else {
			convert(in, out);
		}
	}

	private static void convert(File in, File out) {
		try {
			CRTLoader crtLoader = new CRTLoader(in);
			X509Certificate[] chain = X509CertificateChainBuilder.buildPath(crtLoader, caLibrary);
			PEMWriter crtWriter = new PEMWriter(new FileWriter(out));
			for(int i = 0; i < chain.length; i++)
				crtWriter.writeObject(chain[i]);
			crtWriter.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
