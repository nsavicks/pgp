package etf.openpgp.sn160078dtf160077d.tests;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import etf.openpgp.sn160078dtf160077d.pgp.KeyManagement;
import etf.openpgp.sn160078dtf160077d.pgp.MessageManagement;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;

public class MessageManagementTest
{

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, PGPException, IOException, SignatureException
    {

        File f = new File("C:\\Users\\Nebojsa\\Desktop\\secret.asc");

        File f2 = new File("C:\\Users\\Nebojsa\\Desktop\\public.asc");

        File f3 = new File("C:\\Users\\Nebojsa\\Desktop\\poruka.txt");

//        if (f3.exists()){
//            f3.delete();
//        }
//
//        f3.createNewFile();

        FileInputStream fin = new FileInputStream(f);
        FileInputStream fin2 = new FileInputStream(f2);

        KeyManagement.ImportKeyRing(fin);

        KeyManagement.ImportKeyRing(fin2);

        fin.close();
        fin2.close();

        List<PGPPublicKeyRing> publicKeys = new ArrayList<>();

        publicKeys.add(KeyManagement.publicKeyRings.getKeyRings().next());

        FileOutputStream fout = new FileOutputStream(f3);

        MessageManagement.SendMessage("Proba poruke", false, false, false, true,
                KeyManagement.secretKeyRings.getKeyRings().next(),
                publicKeys,
                SymmetricKeyAlgorithmTags.AES_128,
                "sifra",
                fout
                );

        fout.close();

        //MessageManagement.RecieveMessage(f3, "sifra");

    }

}
