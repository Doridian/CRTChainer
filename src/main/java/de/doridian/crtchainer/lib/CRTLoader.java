package de.doridian.crtchainer.lib;

import org.bouncycastle.openssl.PEMReader;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.cert.X509Certificate;

public class CRTLoader {
	final X509Certificate cert;

	public CRTLoader(File file) throws IOException {
		X509Certificate _cert = null;
		PEMReader pemReader = new PEMReader(new FileReader(file));
		Object object;
		while((object = pemReader.readObject()) != null) {
			if(object instanceof X509Certificate) {
				_cert = (X509Certificate)object;
				break;
			}
		}
		pemReader.close();
		cert = _cert;
	}
}
