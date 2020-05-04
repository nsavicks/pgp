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
import org.bouncycastle.util.encoders.Hex;

import java.io.*;
import java.net.URL;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.Objects;

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

            File publicDir = new File("src/pgp/keys/public/");
            File privateDir = new File("src/pgp/keys/private/");


            if (publicDir.isDirectory() && publicDir.listFiles() != null) {
                for (File f : Objects.requireNonNull(publicDir.listFiles())) {
                    FileInputStream inputStream = new FileInputStream(f);
                    ImportKeyRings(inputStream);
                    inputStream.close();
                }
            }

            if (privateDir.isDirectory() && privateDir.listFiles() != null) {
                for (File f : Objects.requireNonNull(privateDir.listFiles())) {
                    FileInputStream inputStream = new FileInputStream(f);
                    ImportKeyRings(inputStream);
                    inputStream.close();
                }
            }


        } catch (IOException | PGPException e)
        {
            e.printStackTrace();
        }

    }

    public static void SaveAfterExit() throws IOException {

        // public
        for (PGPPublicKeyRing publicKeyRing : publicKeyRings) {
            SaveKeyRingToFile(publicKeyRing);
        }

        for (PGPSecretKeyRing secretKeyRing : secretKeyRings) {
            SaveKeyRingToFile(secretKeyRing);
        }
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

        PGPPublicKeyRing publicKeyRing = generator.generatePublicKeyRing();
        PGPSecretKeyRing secretKeyRing = generator.generateSecretKeyRing();

        publicKeyRings = JcaPGPPublicKeyRingCollection.addPublicKeyRing(publicKeyRings, publicKeyRing);
        secretKeyRings = JcaPGPSecretKeyRingCollection.addSecretKeyRing(secretKeyRings, secretKeyRing);

        SaveKeyRingToFile(publicKeyRing);
        SaveKeyRingToFile(secretKeyRing);

    }

    private static void SaveKeyRingToFile(PGPKeyRing keyRing){
        String fingerPrint = "";
        byte [] bytes = keyRing.getPublicKey().getFingerprint();

        String path = "";
        if (keyRing instanceof PGPSecretKeyRing){
            path = "src/pgp/keys/private/";
        }
        else {
            path = "src/pgp/keys/public/";
        }

        fingerPrint = Hex.toHexString(bytes).toUpperCase();
        File f = new File(path + fingerPrint + ".asc");

        if (f.exists()) return;

        try (FileOutputStream fileOutputStream = new FileOutputStream(f)){

            if (keyRing instanceof PGPSecretKeyRing){
                ExportSecretKeyRing((PGPSecretKeyRing) keyRing, fileOutputStream, true);
            }
            else {
                ExportPublicKeyRing((PGPPublicKeyRing) keyRing, fileOutputStream, true);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void initialize(){
        // for static initialize
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

            String fingerPrint = "";
            byte [] bytes = pgpPublicKeyRing.getPublicKey().getFingerprint();

            fingerPrint = Hex.toHexString(bytes).toUpperCase();
            File f = new File("src/pgp/keys/public/" + fingerPrint + ".asc");

            if (f.exists()){
                f.delete();
            }

        }

    }

    public static void RemoveSecretKeyRing(long keyID, String password) throws PGPException
    {

        if (secretKeyRings.contains(keyID)){

            PGPSecretKeyRing secretKeyRing = secretKeyRings.getSecretKeyRing(keyID);

            // THIS WILL THROW EXCEPTION IF PASSWORD IS NOT CORRECT
            secretKeyRing.getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build(password.toCharArray()));

            secretKeyRings = JcaPGPSecretKeyRingCollection.removeSecretKeyRing(secretKeyRings, secretKeyRing);

            String fingerPrint = "";
            byte [] bytes = secretKeyRing.getPublicKey().getFingerprint();

            fingerPrint = Hex.toHexString(bytes).toUpperCase();
            File f = new File("src/pgp/keys/private/" + fingerPrint + ".asc");

            if (f.exists()){
                f.delete();
            }

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
