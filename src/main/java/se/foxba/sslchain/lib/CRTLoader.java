package se.foxba.sslchain.lib;

import org.bouncycastle.openssl.PEMReader;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.cert.X509Certificate;

public class CRTLoader {
	final X509Certificate cert;

	public CRTLoader(InputStream in) throws IOException {
		X509Certificate _cert = null;
		PEMReader pemReader = new PEMReader(new InputStreamReader(in));
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
