package etf.openpgp.sn160078dtf160077d.gui.models;

public class NewKeyPairModel {

    private String name, email;
    private int sizeDSA;
    private int sizeElGamal;
    private boolean isElGamal;

    private String password;

    public NewKeyPairModel(String name, String email, int sizeDSA, int sizeElGamal, boolean isElGamal, String password) {
        this.name = name;
        this.email = email;
        this.sizeDSA = sizeDSA;
        this.sizeElGamal = sizeElGamal;
        this.isElGamal = isElGamal;
        this.password = password;
    }


    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public int getSizeDSA() {
        return sizeDSA;
    }

    public void setSizeDSA(int sizeDSA) {
        this.sizeDSA = sizeDSA;
    }

    public int getSizeElGamal() {
        return sizeElGamal;
    }

    public void setSizeElGamal(int sizeElGamal) {
        this.sizeElGamal = sizeElGamal;
    }

    public boolean isElGamal() {
        return isElGamal;
    }

    public void setElGamal(boolean elGamal) {
        isElGamal = elGamal;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

}
