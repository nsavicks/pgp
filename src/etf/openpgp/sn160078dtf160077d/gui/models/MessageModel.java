package etf.openpgp.sn160078dtf160077d.gui.models;

import java.util.List;


/**
 * Class that represents PGP message model
 */
public class MessageModel
{
    private String plainText;

    private boolean signed;

    private boolean verified;

    private List<String> signerInfo;

    private List<Long> notFoundKeys;

    /**
     * Constructor
     * @param plainText message text
     * @param signed is message signed
     * @param verified is message verified
     * @param signerInfo signer information
     * @param notFoundKeys keys for signature verification that were not found
     */
    public MessageModel(String plainText, boolean signed, boolean verified, List<String> signerInfo, List<Long> notFoundKeys)
    {
        this.plainText = plainText;
        this.signed = signed;
        this.verified = verified;
        this.signerInfo = signerInfo;
        this.notFoundKeys = notFoundKeys;
    }

    public String getPlainText()
    {
        return plainText;
    }

    public void setPlainText(String plainText)
    {
        this.plainText = plainText;
    }

    public boolean isSigned()
    {
        return signed;
    }

    public void setSigned(boolean signed)
    {
        this.signed = signed;
    }

    public boolean isVerified()
    {
        return verified;
    }

    public void setVerified(boolean verified)
    {
        this.verified = verified;
    }

    public List<String> getSignerInfo()
    {
        return signerInfo;
    }

    public void setSignerInfo(List<String> signerInfo)
    {
        this.signerInfo = signerInfo;
    }

    public List<Long> getNotFoundKeys()
    {
        return notFoundKeys;
    }

    public void setNotFoundKeys(List<Long> notFoundKeys)
    {
        this.notFoundKeys = notFoundKeys;
    }
}
