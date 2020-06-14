package etf.openpgp.sn160078dtf160077d.tests;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import etf.openpgp.sn160078dtf160077d.pgp.KeyManagement;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class KeyManagementTest
{

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, PGPException, IOException
    {

        KeyManagement.GenerateKeyRing("nebojsa", "nebojsa@nebojsa.com", "sifra", 1024, true, 1024);

        File f = new File("C:\\Users\\Nebojsa\\Desktop\\secret.asc");

        File f2 = new File("C:\\Users\\Nebojsa\\Desktop\\public.asc");



        PGPKeyRing ringSecret = KeyManagement.ImportKeyRing(new FileInputStream(f));

        PGPKeyRing ringPublic = KeyManagement.ImportKeyRing(new FileInputStream(f2));

        System.out.println(ringSecret.getPublicKey().getKeyID());

        System.out.println(ringPublic.getPublicKey().getKeyID());

    }

}
