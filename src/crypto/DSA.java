package crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class DSA {

    public static KeyPair buildKeyPair1024(boolean is1K) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");

        if (is1K){
            keyPairGenerator.initialize(1024);
        }
        else {
            keyPairGenerator.initialize(2048);
        }

        return keyPairGenerator.genKeyPair();
    }

}
