package pgp;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.crypto.dsig.keyinfo.PGPData;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

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

}
