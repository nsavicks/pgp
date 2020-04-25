package pgp;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.jcajce.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.sound.midi.Soundbank;
import javax.xml.crypto.dsig.keyinfo.PGPData;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.*;

public class MessageManagement
{

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

            JcePGPDataEncryptorBuilder dataEncryptorBuilder = new JcePGPDataEncryptorBuilder(algorithm);
            dataEncryptorBuilder.setWithIntegrityPacket(true);
            dataEncryptorBuilder.setSecureRandom(new SecureRandom());
            dataEncryptorBuilder.setProvider("BC");

            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(128);

            SecretKey sessionKey = generator.generateKey();

            dataEncryptorBuilder.build(sessionKey.getEncoded());

            PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptorBuilder);

            for (PGPPublicKeyRing publicKey: publicKeys){

                Iterator<PGPPublicKey> it = publicKey.getPublicKeys();

                PGPPublicKey masterKey = it.next();
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

            PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZLIB);

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

            PGPPrivateKey privateKey = secretKey.getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build(password.toCharArray()));

            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

            PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();

            subpacketGenerator.setSignerUserID(false, secretKey.getPublicKey().getUserIDs().next());

            signatureGenerator.setHashedSubpackets(subpacketGenerator.generate());

            signature = signatureGenerator.generateOnePassVersion(false);

            signature.encode(cmpOut);

        }

        File tmpFile = File.createTempFile("pgp", null);
        FileWriter writer = new FileWriter(tmpFile);
        writer.write(plaintext.toCharArray());
        writer.close();

        writeFileToLiteralData(cmpOut, PGPLiteralDataGenerator.UTF8, tmpFile, new byte[16 * 1024], signatureGenerator);

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


    public static boolean RecieveMessage(
            File file,
            String password
    ) throws IOException, PGPException
    {

        boolean verified = true;
        PGPOnePassSignatureList onePassSignatureList = null;

        // INFO DATA
        List<String> validVerifiers = new ArrayList<>();
        List<String> invalidVerifiers = new ArrayList<>();
        List<Long> notFoundKeys = new ArrayList<>();
        String finalMessage = null;

        FileInputStream fileInputStream = null;

        try{

            fileInputStream = new FileInputStream(file);

            BcPGPObjectFactory factory = new BcPGPObjectFactory(PGPUtil.getDecoderStream(fileInputStream));

            Object packet = null;

            PGPSecretKeyRing secretKeyRing = null;

            while (true){

                packet = factory.nextObject();

                if (packet == null) break;

                if (packet instanceof PGPEncryptedDataList){

                    // TRAZI PRIVATEKEY I PASSWORD

                    PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) packet;

                    PGPPublicKeyEncryptedData encryptedData = null;

                    for (int i = 0; i < encryptedDataList.size(); i++){

                        encryptedData = (PGPPublicKeyEncryptedData) encryptedDataList.get(i);

                        secretKeyRing = KeyManagement.GetSecretKeyRing(encryptedData.getKeyID());

                        if (secretKeyRing != null) break;

                    }

                    if (secretKeyRing == null) throw new PGPException("Private key for decryption not found!");

                    Iterator<PGPSecretKey> iterator = secretKeyRing.getSecretKeys();

                    PGPSecretKey masterSecretKey = iterator.next();

                    if (!iterator.hasNext()) throw new PGPException("No subkey for decryption!");

                    PGPSecretKey secretSubKey = iterator.next();

                    // TODO provera da li je podrzan algoritam

                    // TODO password se unosi iz dialoga
                    PGPPrivateKey privateKey = secretSubKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build(password.toCharArray()));

                    InputStream plainStream = encryptedData.getDataStream(new BcPublicKeyDataDecryptorFactory(privateKey));

                    factory = new BcPGPObjectFactory(PGPUtil.getDecoderStream(plainStream));

                }

                if (packet instanceof PGPCompressedData){

                    PGPCompressedData compressedData = (PGPCompressedData) packet;

                    //if (compressedData.getAlgorithm() != CompressionAlgorithmTags.ZIP)
                        //throw new PGPException("Compression algorithm not supported! (Only ZIP algorithm is supported)");

                    factory = new BcPGPObjectFactory(PGPUtil.getDecoderStream(compressedData.getDataStream()));

                }

                if (packet instanceof PGPOnePassSignatureList){

                    onePassSignatureList = (PGPOnePassSignatureList) packet;

                    for (int i = 0; i < onePassSignatureList.size(); i++){

                        PGPOnePassSignature onePassSignature = onePassSignatureList.get(i);

                        long keyId = onePassSignature.getKeyID();

                        PGPPublicKeyRing signerPublicKeyRing = KeyManagement.GetPublicKeyRing(keyId);

                        if (signerPublicKeyRing == null){

                            notFoundKeys.add(keyId);

                        }
                        else {

                            PGPPublicKey signerPublicKey = signerPublicKeyRing.getPublicKey();

                            if (signerPublicKey.getAlgorithm() != SignaturePacket.DSA)
                                throw new PGPException("Signing algorithm not supported (Only DSA algorithm is supported");

                            onePassSignature.init(new BcPGPContentVerifierBuilderProvider(), signerPublicKey);

                        }

                    }

                }

                if (packet instanceof PGPLiteralData){

                    PGPLiteralData literalData = (PGPLiteralData) packet;

                    InputStream rawData = literalData.getInputStream();

                    byte[] buffer = new byte[rawData.available()];

                    rawData.read(buffer);

                    finalMessage = new String(buffer);

                    for (int i = 0; i < onePassSignatureList.size(); i++) {

                        PGPOnePassSignature onePassSignature = onePassSignatureList.get(i);

                        onePassSignature.update(buffer);

                    }

                }

                if (packet instanceof  PGPSignatureList) {

                    PGPSignatureList signatureList = (PGPSignatureList) packet;

                    for (int i = 0; i < signatureList.size(); i++) {

                        PGPSignature signature = signatureList.get(i);

                        PGPOnePassSignature onePassSignature = onePassSignatureList.get(onePassSignatureList.size() - i - 1);

                        if (!onePassSignature.verify(signature)) {

                            verified = false;

                            // adding to invalid verifiers list
                            invalidVerifiers.add(KeyManagement.GetKeyOwnerInfo(signature.getKeyID()));

                        }
                        else {

                            // adding to valid verifiers list
                            validVerifiers.add(KeyManagement.GetKeyOwnerInfo(signature.getKeyID()));

                        }

                    }

                }
            }

        }
        finally
        {

            // WRITING INFO
            if (finalMessage != ""){

                System.out.println("Decrypted message: " + finalMessage);
                System.out.println("Users verified: " + validVerifiers.toString());
                System.out.println("Users failed to verify: " + invalidVerifiers.toString());
                if (verified)
                    System.out.println("Message verified!");
                else
                    System.out.println("Message not verified");

            }
            else {
                System.out.println("Message failed to decrypt");
            }

            fileInputStream.close();

        }
        return verified;
    }

}
