package org.tamal.es;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Properties;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * @author Tamal Kanti Nath
 */
public class SSLEngineFactory {

	/**
	 * Creates a SSL Context.
	 * @return {@link SSLContext}
	 * @throws IOException if keystore or the config file cannot be read
	 * @throws GeneralSecurityException if SSL Context cannot be created
	 */
	public static SSLContext createSSLContext() throws IOException, GeneralSecurityException {
		final String home = System.getProperty("es.path.home");
		String config = home + "/config/" + SecurityPlugin.NAME + "/security.properties";
    	Properties prop = new Properties();
    	try (InputStream in = new FileInputStream(config)) {
        	prop.load(in);
    	}
    	String keystoreType = prop.getProperty("keystore.type", "PKCS12");
		String keystoreFile = prop.getProperty("keystore.file", home + "/config/" + SecurityPlugin.NAME + "/keystore.p12");
    	String keystorePassword = prop.getProperty("keystore.password", "changeit");
    	KeyStore ks = KeyStore.getInstance(keystoreType);
    	try (InputStream in = new FileInputStream(keystoreFile)) {
    		ks.load(in, keystorePassword.toCharArray());
    	}
    	String keyPassword = prop.getProperty("key.password", "changeit");
    	String keyAlgorithm = prop.getProperty("keyManagerFactory.algorithm", KeyManagerFactory.getDefaultAlgorithm());
    	KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(keyAlgorithm);
    	keyManagerFactory.init(ks, keyPassword.toCharArray());

    	String trustAlgorithm = prop.getProperty("trustManagerFactory.algorithm", TrustManagerFactory.getDefaultAlgorithm());
    	TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(trustAlgorithm);
    	String truststoreFile = prop.getProperty("truststore.file");
    	if (truststoreFile == null) {
    		trustManagerFactory.init(ks);
    	} else {
        	String truststoreType = prop.getProperty("truststore.type", "PKCS12");
        	String truststorePassword = prop.getProperty("truststore.password", "changeit");
        	KeyStore ts = KeyStore.getInstance(truststoreType);
        	try (InputStream in = new FileInputStream(truststoreFile)) {
        		ts.load(in, truststorePassword.toCharArray());
        	}
    		trustManagerFactory.init(ts);
    	}
    	String protocol = prop.getProperty("ssl.protocol", "TLS");
        SSLContext sslContext = SSLContext.getInstance(protocol);
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());
		return sslContext;
	}

}
