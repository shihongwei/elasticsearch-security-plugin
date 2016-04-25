package org.tamal.es;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * @author Tamal Kanti Nath
 */
public class CreateCertificate {

	/**
	 * Creates dynamic Certificate.
	 * @param args the command line arguments
	 * @throws URISyntaxException will never happen
	 * @throws IOException if I/O certificate cannot be created
	 * @throws InterruptedException if the process is interrupted
	 */
	public static void main(String[] args) throws URISyntaxException, InterruptedException, IOException {
		String keystore = Paths.get(CreateCertificate.class.getProtectionDomain().getCodeSource().getLocation().toURI())
				.resolve("../../../config/" + SecurityPlugin.NAME + "/keystore.p12").normalize().toString();
		String keytool = new File(System.getProperty("java.home") + "/bin/keytool").getPath();
		String host = InetAddress.getLocalHost().getCanonicalHostName();
		String subject = String.format("CN=%s", host);
		String san = getSubjectAltName();
		String[] generateKeyPair = { keytool, "-genkeypair", "-alias", host, "-dname", subject, "-keystore", keystore, "-storetype", "PKCS12", "-storepass", "changeit", "-keypass", "changeit", "-keyalg", "RSA", "-keysize", "2048", "-sigalg", "SHA512withRSA", "-validity", "365", "-ext", san };
		System.out.println(String.join(" ", generateKeyPair));
        new ProcessBuilder(generateKeyPair).inheritIO().start().waitFor();
	}

    private static String getSubjectAltName() throws UnknownHostException, SocketException {
        List<InetAddress> inetAddresses = new ArrayList<>();
        String san = null;
        inetAddresses.add(InetAddress.getLocalHost());
        inetAddresses.add(InetAddress.getLoopbackAddress());
        Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
        while (networkInterfaces.hasMoreElements()) {
            NetworkInterface networkInterface = networkInterfaces.nextElement();
            Enumeration<InetAddress> inetAddr = networkInterface.getInetAddresses();
            while (inetAddr.hasMoreElements()) {
                inetAddresses.add(inetAddr.nextElement());
            }
        }
        Set<String> hosts = new TreeSet<>();
        for (InetAddress inetAddress : inetAddresses) {
            String ip = inetAddress.getHostAddress();
            if (!ip.equals(inetAddress.getCanonicalHostName())) {
                hosts.add("dns:" + inetAddress.getCanonicalHostName());
            }
            if (!ip.equals(inetAddress.getHostName())) {
                hosts.add("dns:" + inetAddress.getHostName());
            }
            hosts.add("ip:" + ip);
        }
        StringBuilder sb = new StringBuilder("san=");
        for (String s : hosts) {
            sb.append(s).append(',');
        }
        san = sb.substring(0, sb.length() - 1);
        return san;
    }

}
