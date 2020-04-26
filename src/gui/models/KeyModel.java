package gui.models;

import org.bouncycastle.openpgp.PGPKeyRing;

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

    public String getName()
    {
        return name;
    }

    public void setName(String name)
    {
        this.name = name;
    }

    public String getEmail()
    {
        return email;
    }

    public void setEmail(String email)
    {
        this.email = email;
    }

    public String getKeyID()
    {
        return keyID;
    }

    public void setKeyID(String keyID)
    {
        this.keyID = keyID;
    }

    public PGPKeyRing getKeyRing()
    {
        return keyRing;
    }

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
