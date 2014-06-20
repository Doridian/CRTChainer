/*
 * $HeadURL: http://juliusdavies.ca/svn/not-yet-commons-ssl/tags/commons-ssl-0.3.13/src/java/org/apache/commons/ssl/X509CertificateChainBuilder.java $
 * $Revision: 134 $
 * $Date: 2008-02-26 21:30:48 -0800 (Tue, 26 Feb 2008) $
 *
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package se.foxba.sslchain.lib;

import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;

/**
 * Utility for building X509 certificate chains.
 *
 * @author Credit Union Central of British Columbia
 * @author <a href="http://www.cucbc.com/">www.cucbc.com</a>
 * @author <a href="mailto:juliusdavies@cucbc.com">juliusdavies@cucbc.com</a>
 * @since 16-Nov-2005
 */
public class X509CertificateChainBuilder {
	/**
	 * Builds the ordered certificate chain upwards from the startingPoint.
	 * Uses the supplied X509Certificate[] array to search for the parent,
	 * grandparent, and higher ancestor certificates.  Stops at self-signed
	 * certificates, or when no ancestor can be found.
	 * <p/>
	 * Thanks to Joe Whitney for helping me put together a Big-O( m * n )
	 * implementation where m = the length of the final certificate chain.
	 * For a while I was using a Big-O( n ^ 2 ) implementation!
	 *
	 * @param startingPoint the X509Certificate for which we want to find
	 *                      ancestors
	 * @param certificates  A pool of certificates in which we expect to find
	 *                      the startingPoint's ancestors.
	 * @return Array of X509Certificates, starting with the "startingPoint" and
	 *         ending with highest level ancestor we could find in the supplied
	 *         collection.
	 * @throws java.security.NoSuchAlgorithmException
	 *          on unsupported signature
	 *          algorithms.
	 * @throws java.security.InvalidKeyException
	 *          on incorrect key.
	 * @throws java.security.NoSuchProviderException
	 *          if there's no default provider.
	 * @throws java.security.cert.CertificateException
	 *          on encoding errors.
	 */
	public static X509Certificate[] buildPath(CRTLoader startingPoint,
											  CALibrary certificates)
			throws NoSuchAlgorithmException, InvalidKeyException,
			NoSuchProviderException, CertificateException {
		// Use a LinkedList, because we do lots of random it.remove() operations.
		return buildPath(startingPoint.cert,
				new LinkedList<X509Certificate>(certificates.caCerts));
	}

	/**
	 * Builds the ordered certificate chain upwards from the startingPoint.
	 * Uses the supplied X509Certificate[] array to search for the parent,
	 * grandparent, and higher ancestor certificates.  Stops at self-signed
	 * certificates, or when no ancestor can be found.
	 * <p/>
	 * Thanks to Joe Whitney for helping me put together a Big-O( m * n )
	 * implementation where m = the length of the final certificate chain.
	 * For a while I was using a Big-O( n ^ 2 ) implementation!
	 *
	 * @param startingPoint the X509Certificate for which we want to find
	 *                      ancestors
	 * @param certificates  A pool of certificates in which we expect to find
	 *                      the startingPoint's ancestors.
	 * @return Array of X509Certificates, starting with the "startingPoint" and
	 *         ending with highest level ancestor we could find in the supplied
	 *         collection.
	 * @throws java.security.NoSuchAlgorithmException
	 *          on unsupported signature
	 *          algorithms.
	 * @throws java.security.InvalidKeyException
	 *          on incorrect key.
	 * @throws java.security.NoSuchProviderException
	 *          if there's no default provider.
	 * @throws java.security.cert.CertificateException
	 *          on encoding errors.
	 */
	public static X509Certificate[] buildPath(X509Certificate startingPoint,
											  X509Certificate[] certificates)
			throws NoSuchAlgorithmException, InvalidKeyException,
			NoSuchProviderException, CertificateException {
		// Use a LinkedList, because we do lots of random it.remove() operations.
		return buildPath(startingPoint,
				new LinkedList<X509Certificate>(Arrays.asList(certificates)));
	}

	/**
	 * Builds the ordered certificate chain upwards from the startingPoint.
	 * Uses the supplied collection to search for the parent, grandparent,
	 * and higher ancestor certificates.  Stops at self-signed certificates,
	 * or when no ancestor can be found.
	 * <p/>
	 * Thanks to Joe Whitney for helping me put together a Big-O( m * n )
	 * implementation where m = the length of the final certificate chain.
	 * For a while I was using a Big-O( n ^ 2 ) implementation!
	 *
	 * @param startingPoint the X509Certificate for which we want to find
	 *                      ancestors
	 * @param certificates  A pool of certificates in which we expect to find
	 *                      the startingPoint's ancestors.
	 * @return Array of X509Certificates, starting with the "startingPoint" and
	 *         ending with highest level ancestor we could find in the supplied
	 *         collection.
	 * @throws java.security.NoSuchAlgorithmException
	 *          on unsupported signature
	 *          algorithms.
	 * @throws java.security.InvalidKeyException
	 *          on incorrect key.
	 * @throws java.security.NoSuchProviderException
	 *          if there's no default provider.
	 * @throws java.security.cert.CertificateException
	 *          on encoding errors.
	 */
	public static X509Certificate[] buildPath(X509Certificate startingPoint,
											  Collection<X509Certificate> certificates)
			throws NoSuchAlgorithmException, InvalidKeyException,
			NoSuchProviderException, CertificateException {
		LinkedList<X509Certificate> path = new LinkedList<X509Certificate>();
		path.add(startingPoint);
		boolean nodeAdded = true;
		// Keep looping until an iteration happens where we don't add any nodes
		// to our path.
		while (nodeAdded) {
			// We'll start out by assuming nothing gets added.  If something
			// gets added, then nodeAdded will be changed to "true".
			nodeAdded = false;
			X509Certificate top = path.getLast();
			if (isSelfSigned(top)) {
				// We're self-signed, so we're done!
				break;
			}

			// Not self-signed.  Let's see if we're signed by anyone in the
			// collection.
			Iterator<X509Certificate> it = certificates.iterator();
			while (it.hasNext()) {
				X509Certificate x509 = it.next();
				if (verify(top, x509.getPublicKey())) {
					// We're signed by this guy!  Add him to the chain we're
					// building up.
					path.add(x509);
					nodeAdded = true;
					it.remove(); // Not interested in this guy anymore!
					break;
				}
				// Not signed by this guy, let's try the next guy.
			}
		}
		X509Certificate[] results = new X509Certificate[path.size()];
		path.toArray(results);
		return results;
	}

	public static boolean isSelfSigned(X509Certificate cert)
			throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
		return verify(cert, cert.getPublicKey());
	}

	public static boolean verify(X509Certificate cert, PublicKey key)
			throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
		try {
			cert.verify(key);
			return true;
		} catch (InvalidKeyException ike) {
			return false;
		} catch (SignatureException se) {
			return false;
		}
	}
}