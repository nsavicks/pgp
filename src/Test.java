import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Iterator;

public class Test
{

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, PGPException, IOException
    {

        KeyManagement.GenerateKeyRing("nebojsa", "nebojsa@nebojsa.com", "sifra", 1024, true, 1024);

        File f = new File("C:\\Users\\Nebojsa\\Desktop\\test.asc");

        if (f.exists())
            f.delete();

        f.createNewFile();

        FileOutputStream out = new FileOutputStream(f);

        Iterator<PGPSecretKeyRing> it  = KeyManagement.secretKeyRings.getKeyRings();

        KeyManagement.ExportSecretKeyRing(it.next(), out, true);

        out.close();

    }

}
