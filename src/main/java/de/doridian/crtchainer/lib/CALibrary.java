package de.doridian.crtchainer.lib;

import org.bouncycastle.openssl.PEMReader;

import java.io.File;
import java.io.FileReader;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

public class CALibrary {
	public CALibrary(File dir) {
		loadCADyn(dir);
	}

	final ArrayList<X509Certificate> caCerts = new ArrayList<X509Certificate>();

	public Collection<X509Certificate> getCertificates() {
		return new ArrayList<X509Certificate>(caCerts);
	}

	private void loadCADyn(File file) {
		if (!file.canRead())
			return;
		if (file.isDirectory())
			loadCADir(file);
		else
			loadCACrt(file);
	}

	private void loadCADir(File dir) {
		try {
			for (File file : dir.listFiles()) {
				loadCADyn(file);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void loadCACrt(File file) {
		try {
			PEMReader pemReader = new PEMReader(new FileReader(file));
			Object object;
			while((object = pemReader.readObject()) != null) {
				if(object instanceof X509Certificate) {
					caCerts.add((X509Certificate)object);
				}
			}
			pemReader.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
