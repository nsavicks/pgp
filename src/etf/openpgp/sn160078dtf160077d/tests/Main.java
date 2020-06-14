package etf.openpgp.sn160078dtf160077d.tests;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;

public class Main
{

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, PGPException
    {

        File f = new File("C:\\Users\\Nebojsa\\Desktop\\pgp\\src\\privatekey.asc");
        File f2 = new File("C:\\Users\\Nebojsa\\Desktop\\pgp\\src\\pgpexample.txt");


        FileInputStream fileInputStream = new FileInputStream(f);

        BcPGPObjectFactory factory = new BcPGPObjectFactory(PGPUtil.getDecoderStream(fileInputStream));

        PGPSecretKeyRing o = (PGPSecretKeyRing) factory.nextObject();

        Iterator<PGPSecretKey> it = o.getSecretKeys();
        it.next();

        PGPSecretKey secretKey = it.next();

        PGPPrivateKey pgpPrivateKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build("sifra".toCharArray()));

        PGPPublicKey pgpPublicKey = secretKey.getPublicKey();

        // PODACI

        factory = new BcPGPObjectFactory(PGPUtil.getDecoderStream(new ArmoredInputStream(new FileInputStream(f2))));

        PGPEncryptedDataList o2 = (PGPEncryptedDataList) factory.nextObject();

        PGPPublicKeyEncryptedData data = (PGPPublicKeyEncryptedData) o2.get(0);

        InputStream dataStream = data.getDataStream(new BcPublicKeyDataDecryptorFactory(pgpPrivateKey));

        // DALJE

        factory = new BcPGPObjectFactory(PGPUtil.getDecoderStream(dataStream));

        PGPCompressedData o3 = (PGPCompressedData) factory.nextObject();

        factory = new BcPGPObjectFactory(PGPUtil.getDecoderStream(o3.getDataStream()));

        // DALJE

        PGPOnePassSignatureList list = (PGPOnePassSignatureList) factory.nextObject();

        PGPOnePassSignature onePassSignature = list.get(0);

        onePassSignature.init(new BcPGPContentVerifierBuilderProvider(), o.getPublicKey());

        PGPLiteralData literalData = (PGPLiteralData) factory.nextObject();

        InputStream rawData = literalData.getInputStream();

        byte buf[] = new byte[rawData.available()];

        rawData.read(buf);

        onePassSignature.update(buf);

        PGPSignatureList signatureList = (PGPSignatureList) factory.nextObject();

        if (onePassSignature.verify(signatureList.get(0))){
            System.out.println("VERIFIED");
        }


//        byte[] buff = new byte[19];
//
//        o5.getInputStream().read(buff);
//
//        System.out.println(new String(buff, StandardCharsets.UTF_8));

    }
}
