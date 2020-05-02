package pgp;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ElGamalGenParameterSpec;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRing;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.jcajce.JcaPGPSecretKeyRing;
import org.bouncycastle.openpgp.jcajce.JcaPGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;

public class KeyManagement
{

    public static PGPPublicKeyRingCollection publicKeyRings;

    public static PGPSecretKeyRingCollection secretKeyRings;

    static {
        FileInputStream fileInputStream = null;
        try
        {

            Security.addProvider(new BouncyCastleProvider());

            publicKeyRings = new JcaPGPPublicKeyRingCollection(new ArrayList<>());

            secretKeyRings = new JcaPGPSecretKeyRingCollection(new ArrayList<>());

            File f = new File("C:\\Users\\tf160077d\\Desktop\\zp\\pgp\\src\\pgp\\init.asc");
            fileInputStream = new FileInputStream(f);

            initializeFromFile(fileInputStream);

        } catch (IOException | PGPException e)
        {
            e.printStackTrace();
        }
        finally {
            if (fileInputStream != null) {
                try {
                    fileInputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

    }

    private static void initializeFromFile(FileInputStream inputStream) throws IOException {
        // importing keys from init.asc file
        ImportKeyRings(inputStream);
    }

    public static void SaveAfterExit() throws IOException {

        try (FileOutputStream fileOutputStream = new FileOutputStream(new File("C:\\Users\\tf160077d\\Desktop\\zp\\pgp\\src\\pgp\\init.asc"))) {
            SaveToFile(fileOutputStream);
        } catch (PGPException e) {
            e.printStackTrace();
        }
    }

    public static void SaveToFile(FileOutputStream out) throws PGPException, IOException {
        ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(out);

        // exporting public keys
        Iterator<PGPPublicKeyRing> publicKeyRingIterator = publicKeyRings.getKeyRings();

        while (publicKeyRingIterator.hasNext()){
            PGPPublicKeyRing publicKeyRing = publicKeyRingIterator.next();
            publicKeyRing.encode(armoredOutputStream);
        }

        // exporting private keys
        Iterator<PGPSecretKeyRing> secretKeyRingIterator = secretKeyRings.getKeyRings();
        while (secretKeyRingIterator.hasNext()){
            PGPSecretKeyRing secretKeyRing = secretKeyRingIterator.next();
            secretKeyRing.encode(armoredOutputStream);
        }

        armoredOutputStream.close();
    }

    public static void GenerateKeyRing(String name, String email, String password, int dsaKeySize, boolean elgamal, int elgamalKeySize) throws NoSuchProviderException, NoSuchAlgorithmException, PGPException
    {

        // Generate DSA

        KeyPair dsaKeyPair = generateKeyPair("DSA", dsaKeySize);

        PGPKeyPair dsaPGPKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKeyPair, new Date());

        PGPDigestCalculator digestCalculator = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        PGPKeyRingGenerator generator = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                dsaPGPKeyPair,
                name + " <" + email + ">",
                digestCalculator,
                null,
                null,
                new JcaPGPContentSignerBuilder(dsaPGPKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_128, digestCalculator).setProvider("BC").build(password.toCharArray())
        );

        if (elgamal){

            KeyPair elgamalKeyPair = generateKeyPair("ELGAMAL", elgamalKeySize);
            PGPKeyPair elgamalPGPKeyPar = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgamalKeyPair, new Date());

            generator.addSubKey(elgamalPGPKeyPar);

        }


        publicKeyRings = JcaPGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRings, generator.generatePublicKeyRing());
        secretKeyRings = JcaPGPSecretKeyRingCollection.addSecretKeyRing(secretKeyRings, generator.generateSecretKeyRing());

    }

    public static void initialize(){

    }

    public static void ExportPublicKeyRing(PGPPublicKeyRing keyRing, FileOutputStream out, boolean radix64) throws IOException
    {

        if (radix64){
            ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(out);
            keyRing.encode(armoredOutputStream);
            armoredOutputStream.close();
        }
        else{
            keyRing.encode(out);
        }

    }

    public static void ExportSecretKeyRing(PGPSecretKeyRing keyRing, FileOutputStream out, boolean radix64) throws IOException
    {

        if (radix64){
            ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(out);
            keyRing.encode(armoredOutputStream);
            armoredOutputStream.close();
        }
        else{
            keyRing.encode(out);
        }

    }

    public static void ImportKeyRings(FileInputStream in) throws IOException {

        BcPGPObjectFactory factory = new BcPGPObjectFactory(PGPUtil.getDecoderStream(in));

        while (true) {
            Object o = factory.nextObject();

            if (o == null)
                break;

            if (o instanceof PGPPublicKeyRing) {

                publicKeyRings = JcaPGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRings, (PGPPublicKeyRing) o);

            } else if (o instanceof PGPSecretKeyRing) {

                secretKeyRings = JcaPGPSecretKeyRingCollection.addSecretKeyRing(secretKeyRings, (PGPSecretKeyRing) o);
                // TODO Import public key ring???
            }
        }

    }

    public static PGPKeyRing ImportKeyRing(FileInputStream in) throws IOException
    {

        BcPGPObjectFactory factory = new BcPGPObjectFactory(PGPUtil.getDecoderStream(in));

        Object o = factory.nextObject();

        if (o instanceof PGPPublicKeyRing){

            publicKeyRings = JcaPGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRings, (PGPPublicKeyRing) o);

        }
        else if (o instanceof PGPSecretKeyRing){

            secretKeyRings = JcaPGPSecretKeyRingCollection.addSecretKeyRing(secretKeyRings, (PGPSecretKeyRing) o);
            // TODO Import public key ring???

        }

        return (PGPKeyRing) o;

    }

    public static void RemovePublicKeyRing(long keyID) throws PGPException
    {

        if (publicKeyRings.contains(keyID))
        {

            PGPPublicKeyRing pgpPublicKeyRing = publicKeyRings.getPublicKeyRing(keyID);

            publicKeyRings = JcaPGPPublicKeyRingCollection.removePublicKeyRing(publicKeyRings, pgpPublicKeyRing);

        }

    }

    public static void RemoveSecretKeyRing(long keyID, String password) throws PGPException
    {

        if (secretKeyRings.contains(keyID)){

            PGPSecretKeyRing secretKeyRing = secretKeyRings.getSecretKeyRing(keyID);

            // THIS WILL THROW EXCEPTION IF PASSWORD IS NOT CORRECT
            secretKeyRing.getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build(password.toCharArray()));

            secretKeyRings = JcaPGPSecretKeyRingCollection.removeSecretKeyRing(secretKeyRings, secretKeyRing);

        }

    }

    public static PGPSecretKeyRing GetSecretKeyRing(long keyID) throws PGPException
    {

        return secretKeyRings.getSecretKeyRing(keyID);

    }

    public static PGPPublicKeyRing GetPublicKeyRing(long keyID) throws PGPException
    {

        return publicKeyRings.getPublicKeyRing(keyID);

    }

    public static String GetKeyOwnerInfo(long keyID) throws PGPException {

        if (publicKeyRings.getPublicKeyRing(keyID) != null)
            return publicKeyRings.getPublicKeyRing(keyID).getPublicKey().getUserIDs().next();
        else
            return null;
    }

    private static KeyPair generateKeyPair(String algorithm, int keySize) throws NoSuchProviderException, NoSuchAlgorithmException
    {

        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, "BC");

        generator.initialize(keySize);

        return generator.generateKeyPair();
    }


}
