package etf.openpgp.sn160078dtf160077d.pgp;

import etf.openpgp.sn160078dtf160077d.gui.helpers.SelectKeyDialog;
import etf.openpgp.sn160078dtf160077d.gui.models.KeyModel;
import etf.openpgp.sn160078dtf160077d.gui.models.MessageModel;
import javafx.util.Pair;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.jcajce.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.*;


public class MessageManagement
{


    public static void OnlySignMessage(
            String plaintext,
            PGPSecretKeyRing secretKey,
            int algorithm,
            String password,
            FileOutputStream fileOut
    ) throws PGPException, IOException, SignatureException {

        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA256));
        PGPSignature signature;
        PGPPrivateKey privateKey = null;

        try {
            privateKey = secretKey.getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build(password.toCharArray()));
        } catch (PGPException e) {
            throw new PGPException("Password incorrect!");
        }

        try {
            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

            PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();
            subpacketGenerator.setSignerUserID(false, secretKey.getPublicKey().getUserIDs().next());
            signatureGenerator.setHashedSubpackets(subpacketGenerator.generate());

            signature = signatureGenerator.generate();

            signature.encode(fileOut);
        }
        catch (IOException e) {
            throw e;
        }

        File tmpFile = File.createTempFile("etf/openpgp/sn160078dtf160077d/pgp", null);
        FileWriter writer = new FileWriter(tmpFile);
        writer.write(plaintext.toCharArray());
        writer.close();

        writeFileToLiteralData(fileOut, PGPLiteralDataGenerator.UTF8, tmpFile, new byte[16 * 1024], signatureGenerator);

        signatureGenerator.generate().encode(fileOut);

    }

    public static void SendMessage(
            String plaintext,
            boolean encrypt,
            boolean sign,
            boolean compress,
            boolean radix64,
            PGPSecretKeyRing secretKey,
            List<PGPPublicKeyRing> publicKeys,
            int algorithm,
            String password,
            FileOutputStream fileOut
    ) throws IOException, PGPException, NoSuchAlgorithmException, SignatureException
    {


        // RADIX-64 conversion

        OutputStream finalOut;

        if (radix64){

            finalOut = new ArmoredOutputStream(fileOut);

        }
        else{
            finalOut = fileOut;
        }

        // ENCRYPTION

        OutputStream encOut = null;

        if (encrypt){

            if (publicKeys.size() == 0){
                throw new PGPException("You must specify at least one public key for encryption.");
            }

            JcePGPDataEncryptorBuilder dataEncryptorBuilder = new JcePGPDataEncryptorBuilder(algorithm);
            dataEncryptorBuilder.setWithIntegrityPacket(true);
            dataEncryptorBuilder.setSecureRandom(new SecureRandom());
            dataEncryptorBuilder.setProvider("BC");

            KeyGenerator generator = null;

            if (algorithm == SymmetricKeyAlgorithmTags.AES_128){

               generator = KeyGenerator.getInstance("AES");
               generator.init(128);

            }
            else if (algorithm == SymmetricKeyAlgorithmTags.TRIPLE_DES){

                generator = KeyGenerator.getInstance("DESede");
                generator.init(168);

            }

            SecretKey sessionKey = generator.generateKey();

            dataEncryptorBuilder.build(sessionKey.getEncoded());

            PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptorBuilder);

            for (PGPPublicKeyRing publicKey: publicKeys){

                Iterator<PGPPublicKey> it = publicKey.getPublicKeys();

                PGPPublicKey masterKey = it.next();

                if (!it.hasNext())
                    throw new PGPException("Selected key doesn't have ElGamal subkey which is needed for encryption.");

                PGPPublicKey subKey = it.next();

                encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(subKey));
            }

            encOut = encryptedDataGenerator.open(finalOut, new byte[16 * 1024]);

        }
        else{

            encOut = finalOut;

        }

        // Compression stream

        OutputStream cmpOut = null;

        if (compress){

            PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);

            cmpOut = compressedDataGenerator.open(encOut);

        }
        else{

            cmpOut = encOut;

        }

        // IF needed signature

        PGPOnePassSignature signature = null;

        PGPSignatureGenerator signatureGenerator = null;

        if (sign){

            signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.DSA, HashAlgorithmTags.SHA256));

            PGPPrivateKey privateKey = null;

            try{
                 privateKey = secretKey.getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build(password.toCharArray()));
            }
            catch (PGPException e){
                throw new PGPException("Password incorrect!");
            }

            try {
                signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

                PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();

                subpacketGenerator.setSignerUserID(false, secretKey.getPublicKey().getUserIDs().next());

                signatureGenerator.setHashedSubpackets(subpacketGenerator.generate());

                signature = signatureGenerator.generateOnePassVersion(false);

                signature.encode(cmpOut);
            }
            catch (Exception e){
                throw e;
            }
        }

        File tmpFile = File.createTempFile("etf/openpgp/sn160078dtf160077d/pgp", null);
        FileWriter writer = new FileWriter(tmpFile);
        writer.write(plaintext.toCharArray());
        writer.close();

        writeFileToLiteralData(cmpOut, PGPLiteralDataGenerator.UTF8, tmpFile, new byte[16 * 1024], signatureGenerator);

        if (signatureGenerator != null)
            signatureGenerator.generate().encode(cmpOut);

        cmpOut.close();

        encOut.close();

        finalOut.close();

    }

    public static void writeFileToLiteralData(OutputStream out, char fileType,
                                       File file, byte[] buffer, PGPSignatureGenerator
                                               signatureGenerator)
            throws IOException, SignatureException, PGPException
    {
        PGPLiteralDataGenerator literalDataGenerator = null;
        BufferedInputStream in = null;
        try
        {
            literalDataGenerator = new
                    PGPLiteralDataGenerator();
            OutputStream literalOut =
                    literalDataGenerator.open(out, fileType,
                            file.getName(), new
                                    Date(file.lastModified()), buffer);
            in = new BufferedInputStream(new
                    FileInputStream(file),
                    buffer.length);
            byte[] buf = new byte[buffer.length];
            int len;

            while ((len = in.read(buf)) > 0)
            {
                literalOut.write(buf, 0, len);
                if (signatureGenerator != null)
                    signatureGenerator.update(buf, 0, len);
            }

            literalOut.close();
            // Generate the signature save it to the file
            // signatureGenerator.generate().encode(literalOut);
        } finally
        {
            if (literalDataGenerator != null)
            {
                literalDataGenerator.close();
            }
            if (in != null)
            {
                in.close();
            }
        }
    }


    public static MessageModel ReceiveMessage(
            File file
    ) throws IOException, PGPException
    {

        boolean verified = true;
        PGPOnePassSignatureList onePassSignatureList = null;

        // INFO DATA

        List<String> validVerifiers = new ArrayList<>();
        List<Long> notFoundKeys = new ArrayList<>();
        String finalMessage = null;
        boolean signed = false;

        byte[] buffer = null;

        try (FileInputStream fileInputStream = new FileInputStream(file)) {

            BcPGPObjectFactory factory = new BcPGPObjectFactory(PGPUtil.getDecoderStream(fileInputStream));

            Object packet = null;

            while (true) {

                packet = factory.nextObject();

                if (packet == null) break;

                if (packet instanceof PGPEncryptedDataList) {

                    PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) packet;

                    List<PGPSecretKeyRing> secretKeyRings = new ArrayList<>();
                    HashMap<Long, PGPPublicKeyEncryptedData> encryptedDataHashMap = new HashMap<>();

                    for (int i = 0; i < encryptedDataList.size(); i++) {

                        PGPPublicKeyEncryptedData encryptedData = (PGPPublicKeyEncryptedData) encryptedDataList.get(i);
                        PGPSecretKeyRing secretKeyRing = KeyManagement.GetSecretKeyRing(encryptedData.getKeyID());

                        if (secretKeyRing != null) {
                            secretKeyRings.add(secretKeyRing);
                            encryptedDataHashMap.put(secretKeyRing.getPublicKey().getKeyID(), encryptedData);
                        }
                    }

                    if (secretKeyRings.size() == 0) throw new PGPException("Private key for decryption not found!");
                    

                    // TODO provera da li je podrzan algoritam


                    SelectKeyDialog dialog = new SelectKeyDialog(secretKeyRings);

                    Optional<Pair<KeyModel, String>> optionalPassword = dialog.showAndWait();

                    if (!optionalPassword.isPresent())
                        throw new PGPException("You need to select key");

                    String password = optionalPassword.get().getValue();
                    KeyModel keyModel = optionalPassword.get().getKey();

                    PGPSecretKeyRing selectedSecretKeyRing = (PGPSecretKeyRing) keyModel.getKeyRing();
                    PGPPublicKeyEncryptedData selectedEncryptedData = encryptedDataHashMap.get(selectedSecretKeyRing.getPublicKey().getKeyID());

                    Iterator<PGPSecretKey> iterator = selectedSecretKeyRing.getSecretKeys();

                    PGPSecretKey masterSecretKey = iterator.next();

                    if (!iterator.hasNext()) throw new PGPException("No subkey for decryption!");

                    PGPSecretKey secretSubKey = iterator.next();

                    try {

                        PGPPrivateKey privateKey = secretSubKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build(password.toCharArray()));

                        InputStream plainStream = selectedEncryptedData.getDataStream(new BcPublicKeyDataDecryptorFactory(privateKey));

                        factory = new BcPGPObjectFactory(PGPUtil.getDecoderStream(plainStream));

                    } catch (PGPException e) {
                        throw new PGPException("Password for decrypting incorrect!");
                    }

                }

                if (packet instanceof PGPCompressedData) {

                    PGPCompressedData compressedData = (PGPCompressedData) packet;

                    if (compressedData.getAlgorithm() != CompressionAlgorithmTags.ZIP)
                        throw new PGPException("Compression algorithm not supported! (Only ZIP algorithm is supported)");

                    factory = new BcPGPObjectFactory(PGPUtil.getDecoderStream(compressedData.getDataStream()));

                }

                if (packet instanceof PGPOnePassSignatureList) {

                    signed = true;

                    onePassSignatureList = (PGPOnePassSignatureList) packet;

                    for (int i = 0; i < onePassSignatureList.size(); i++) {

                        PGPOnePassSignature onePassSignature = onePassSignatureList.get(i);

                        long keyId = onePassSignature.getKeyID();

                        PGPPublicKeyRing signerPublicKeyRing = KeyManagement.GetPublicKeyRing(keyId);

                        if (signerPublicKeyRing == null) {

                            notFoundKeys.add(keyId);

                        } else {

                            PGPPublicKey signerPublicKey = signerPublicKeyRing.getPublicKey();

                            if (signerPublicKey.getAlgorithm() != SignaturePacket.DSA)
                                throw new PGPException("Signing algorithm not supported (Only DSA algorithm is supported");

                            onePassSignature.init(new BcPGPContentVerifierBuilderProvider(), signerPublicKey);

                        }

                    }

                }

                if (packet instanceof PGPLiteralData) {

                    PGPLiteralData literalData = (PGPLiteralData) packet;

                    InputStream rawData = literalData.getInputStream();

                    buffer = new byte[rawData.available()];

                    rawData.read(buffer);

                    finalMessage = new String(buffer);

                    if (onePassSignatureList != null) {

                        for (int i = 0; i < onePassSignatureList.size(); i++) {

                            PGPOnePassSignature onePassSignature = onePassSignatureList.get(i);

                            if (!notFoundKeys.contains(onePassSignature.getKeyID()))
                                onePassSignature.update(buffer);

                        }

                    }

                }
                if (packet instanceof PGPSignatureList) {

                    PGPSignatureList signatureList = (PGPSignatureList) packet;

                    for (int i = 0; i < signatureList.size(); i++) {

                        PGPSignature signature = signatureList.get(i);

                        if (onePassSignatureList != null){
                            PGPOnePassSignature onePassSignature = onePassSignatureList.get(onePassSignatureList.size() - i - 1);

                            if (notFoundKeys.contains(signature.getKeyID()) || !onePassSignature.verify(signature)) {
                                verified = false;
                            } else {
                                // adding to valid verifiers list
                                validVerifiers.add(KeyManagement.GetKeyOwnerInfo(signature.getKeyID()));
                            }
                        }
                        else {

                            PGPPublicKeyRing publicKeyRing = KeyManagement.GetPublicKeyRing(signature.getKeyID());

                            if (publicKeyRing == null){
                                throw new PGPException("Public key for verification not found.");
                            }

                            signature.init(new BcPGPContentVerifierBuilderProvider(), publicKeyRing.getPublicKey());

                            signature.update(buffer);

                            if (!signature.verify()){
                                verified = false;
                            }
                            else{
                                validVerifiers.add(KeyManagement.GetKeyOwnerInfo(publicKeyRing.getPublicKey().getKeyID()));
                            }

                        }

                    }

                }
            }

        }

//            // WRITING INFO
//            if (finalMessage != ""){
//
//                System.out.println("Decrypted message: " + finalMessage);
//                System.out.println("Users verified: " + validVerifiers.toString());
//                System.out.println("Not found keys: " + notFoundKeys.toString());
//                if (verified)
//                    System.out.println("Message verified!");
//                else
//                    System.out.println("Message not verified");
//
//            }
//            else {
//                System.out.println("Message failed to decrypt");
//            }

        return new MessageModel(finalMessage, signed, verified, validVerifiers, notFoundKeys);
    }

    public static MessageModel ReceiveDetachedMessage(
            File signFile,
            File messageFile
    ) throws IOException, PGPException
    {
        boolean verified = true;
        PGPOnePassSignatureList onePassSignatureList = null;

        // INFO DATA

        List<String> validVerifiers = new ArrayList<>();
        List<Long> notFoundKeys = new ArrayList<>();
        String finalMessage = null;
        boolean signed = false;

        byte[] buffer = null;

        try (FileInputStream fileInputStream = new FileInputStream(messageFile)) {
            buffer = Files.readAllBytes(messageFile.toPath());
        }

        try (FileInputStream fileInputStream = new FileInputStream(signFile)) {

            BcPGPObjectFactory factory = new BcPGPObjectFactory(PGPUtil.getDecoderStream(fileInputStream));
            Object packet = null;
            while (true) {

                packet = factory.nextObject();

                if (packet == null) break;

                if (packet instanceof PGPSignatureList) {

                    PGPSignatureList signatureList = (PGPSignatureList) packet;

                    for (int i = 0; i < signatureList.size(); i++) {

                        PGPSignature signature = signatureList.get(i);

                        PGPPublicKeyRing publicKeyRing = KeyManagement.GetPublicKeyRing(signature.getKeyID());

                        if (publicKeyRing == null){
                            throw new PGPException("Public key for verification not found.");
                        }

                        signature.init(new BcPGPContentVerifierBuilderProvider(), publicKeyRing.getPublicKey());

                        signature.update(buffer);

                        if (!signature.verify()){
                            verified = false;
                        }
                        else{
                            validVerifiers.add(KeyManagement.GetKeyOwnerInfo(publicKeyRing.getPublicKey().getKeyID()));
                        }
                    }
                }
                else {
                    throw new PGPException("Sign file doesn't contain only PGPSignatureList packets.");
                }
            }

        }

        return new MessageModel(new String(buffer), signed, verified, validVerifiers, notFoundKeys);
    }

}
