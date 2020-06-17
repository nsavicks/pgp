package etf.openpgp.sn160078dtf160077d.gui.models;

import org.bouncycastle.openpgp.PGPKeyRing;

/**
 * Class that represents model of public and private keys
 */
public class KeyModel
{

    private String name;

    private String email;

    private String keyID;

    private PGPKeyRing keyRing;


    public KeyModel(PGPKeyRing keyRing)
    {
        String userID[] = keyRing.getPublicKey().getUserIDs().next().split(" ");

        name = userID[0];

        email = userID[1];

        keyID = Long.toHexString(keyRing.getPublicKey().getKeyID()).toUpperCase();

        this.keyRing = keyRing;
    }

    /**
     * Gets name of key owner
     * @return Key owner name
     */
    public String getName()
    {
        return name;
    }

    /**
     * Sets key owner name
     * @param name
     */
    public void setName(String name)
    {
        this.name = name;
    }


    /**
     * Gets key owner e-mail
     * @return Key owner e-mail
     */
    public String getEmail()
    {
        return email;
    }

    /**
     * Sets key owner e-mail
     * @param email
     */
    public void setEmail(String email)
    {
        this.email = email;
    }

    /**
     * Gets key ID
     * @return Key ID
     */
    public String getKeyID()
    {
        return keyID;
    }

    /**
     * Sets key ID
     * @param keyID
     */
    public void setKeyID(String keyID)
    {
        this.keyID = keyID;
    }

    /**
     * Gets PGPKeyRing of this key model
     * @return PGPKeyRing
     */
    public PGPKeyRing getKeyRing()
    {
        return keyRing;
    }

    /**
     * Sets PGPKeyRing of this key model
     * @param keyRing
     */
    public void setKeyRing(PGPKeyRing keyRing)
    {
        this.keyRing = keyRing;
    }


    @Override
    public String toString()
    {
        return name + " " + email + " " + keyID;
    }
}
