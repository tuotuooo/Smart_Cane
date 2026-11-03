import com.android.apksig.ApkSigner;
import com.android.apksig.ApkSigner.SignerConfig;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;

public class Sign {
    public static void main(String[] args) throws Exception {
        String in = args[0];
        String out = args[1];
        String ksPath = args[2];
        String alias = args[3];
        String pass = args[4];

        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(ksPath)) {
            ks.load(fis, pass.toCharArray());
        }
        PrivateKey key = (PrivateKey) ks.getKey(alias, pass.toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        if (key == null || cert == null) {
            throw new IllegalStateException("key or cert not found for alias " + alias);
        }
        SignerConfig sc = new SignerConfig.Builder(alias, key, Collections.singletonList(cert)).build();
        new ApkSigner.Builder(Collections.singletonList(sc))
                .setInputApk(new File(in))
                .setOutputApk(new File(out))
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .build()
                .sign();
        System.out.println("SIGNED OK -> " + out);
    }
}
