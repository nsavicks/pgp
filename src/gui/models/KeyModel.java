package gui.models;

import org.bouncycastle.openpgp.PGPKeyRing;

public class KeyModel
{

    private String name;

    private String email;

    private String keyID;

    private PGPKeyRing keyRing;


    public KeyModel(String name, String email, String keyID, PGPKeyRing keyRing)
    {
        this.name = name;
        this.email = email;
        this.keyID = keyID;
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
}
