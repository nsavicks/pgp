package tests;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;

import org.bouncycastle.openpgp.*;

import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public class BCPGPDecryptor {

    private String privateKeyFilePath;
    private String password;

    private boolean isSigned;

    public boolean isSigned() {
        return isSigned;
    }

    public void setSigned(boolean isSigned) {
        this.isSigned = isSigned;
    }

    public String getSigningPublicKeyFilePath() {
        return signingPublicKeyFilePath;
    }

    public void setSigningPublicKeyFilePath(String signingPublicKeyFilePath) {
        this.signingPublicKeyFilePath = signingPublicKeyFilePath;
    }

    private String signingPublicKeyFilePath;

    public String getPrivateKeyFilePath() {
        return privateKeyFilePath;
    }

    public void setPrivateKeyFilePath(String privateKeyFilePath) {
        this.privateKeyFilePath = privateKeyFilePath;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void decryptFile(String inputFileNamePath, String outputFileNamePath)
            throws Exception {
        decryptFile(new File(inputFileNamePath), new File(outputFileNamePath));
    }

    public void decryptFile(File inputFile, File outputFile) throws Exception {
        decryptFile(new FileInputStream(inputFile), new FileOutputStream(
                outputFile));
    }

    public void decryptFile(InputStream in, OutputStream out) throws Exception {
        BufferedOutputStream bOut = new BufferedOutputStream(out);
        InputStream unc = decryptFile(in);
        int ch;
        while ((ch = unc.read()) >= 0) {
            bOut.write(ch);
        }
        bOut.close();
    }

    public InputStream decryptFile(InputStream in) throws Exception {
        InputStream is = null;
        byte[] bytes = null;
        //InputStream keyIn = new FileInputStream(new File(privateKeyFilePath));
        char[] passwd = password.toCharArray();
        in = PGPUtil.getDecoderStream(in);

        // CREAT KEY

        File f = new File("C:\\Users\\Nebojsa\\Desktop\\pgp\\src\\privatekey.asc");

        FileInputStream fileInputStream = new FileInputStream(f);

        BcPGPObjectFactory factory = new BcPGPObjectFactory(PGPUtil.getDecoderStream(fileInputStream));

        PGPSecretKeyRing oo = (PGPSecretKeyRing) factory.nextObject();

        Iterator<PGPSecretKey> it2 = oo.getSecretKeys();
        it2.next();

        PGPPrivateKey pgpPrivateKey = it2.next().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build("sifra".toCharArray()));


        PGPObjectFactory pgpF = new BcPGPObjectFactory(PGPUtil.getDecoderStream(in));
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();
        //
        // the first object might be a PGP marker packet.
        //
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        //
        // find the secret key
        //
        Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = (PGPPublicKeyEncryptedData) it.next();

        sKey = pgpPrivateKey;

        if (sKey == null) {
            throw new IllegalArgumentException("secret key for message not found.");
        }

        InputStream clear = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(pgpPrivateKey));
        PGPObjectFactory plainFact = new BcPGPObjectFactory(PGPUtil.getDecoderStream(clear));
        Object message = plainFact.nextObject();
        PGPObjectFactory pgpFact = null;
        if (message instanceof PGPCompressedData) {
            PGPCompressedData cData = (PGPCompressedData) message;
            pgpFact = new BcPGPObjectFactory(cData.getDataStream());
            message = pgpFact.nextObject();
        }

        PGPOnePassSignature ops = null;
        if (message instanceof PGPOnePassSignatureList) {
            if (isSigned) {
                PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) message;
                ops = p1.get(0);
                long keyId = ops.getKeyID();
                PGPPublicKey signerPublicKey = oo.getPublicKey();
                ops.init(new BcPGPContentVerifierBuilderProvider(), signerPublicKey);
            }
            message = pgpFact.nextObject();
        }

        if (message instanceof PGPLiteralData) {
            PGPLiteralData ld = (PGPLiteralData) message;
            if (pbe.isIntegrityProtected()) {
                if (!pbe.verify()) {
                    throw new PGPException("message failed integrity check");
                }
            }
            is = ld.getInputStream();
            bytes = new byte[is.available()];
            is.read(bytes);

            if (isSigned) {
                ops.update(bytes);
                PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();
                if (!ops.verify(p3.get(0))) {
                    throw new PGPException("Signature verification failed!");
                }
            }
        } else {
            throw new PGPException("message is not a simple encrypted file - type unknown.");
        }
        return new ByteArrayInputStream(bytes);
    }


    public static void main(String[] args) throws Exception
    {

        BCPGPDecryptor bcpgpDecryptor = new BCPGPDecryptor();

        bcpgpDecryptor.isSigned = true;
        bcpgpDecryptor.password = "sifra";

        bcpgpDecryptor.decryptFile("C:\\Users\\Nebojsa\\Desktop\\pgp\\src\\pgpexample.txt", "C:\\Users\\Nebojsa\\Desktop\\pgp\\src\\out.txt");
    }
}