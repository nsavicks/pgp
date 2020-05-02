package gui.helpers;

import gui.models.NewKeyPairModel;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import org.bouncycastle.openpgp.PGPException;


public class NewKeyPairDialog extends Dialog<NewKeyPairModel> {

    private PasswordField passwordField;
    private TextField nameField, emailField;

    private RadioButton sizeDSA1024Radio;
    private RadioButton sizeDSA2048Radio;

    private CheckBox elgamalCB;
    private RadioButton sizeElGamal1024Radio;
    private RadioButton sizeElGamal2048Radio;
    private RadioButton sizeElGamal4096Radio;

    public NewKeyPairDialog() {
        final ToggleGroup toggleGroupDSA = new ToggleGroup();
        final ToggleGroup toggleGroupElGamal = new ToggleGroup();

        setTitle("Generate new key pair");

        ButtonType okButton = new ButtonType("OK", ButtonBar.ButtonData.OK_DONE);
        getDialogPane().getButtonTypes().addAll(okButton, ButtonType.CANCEL);

        nameField = new TextField();
        nameField.setPromptText("Name");

        emailField = new TextField();
        emailField.setPromptText("Email");

        passwordField = new PasswordField();
        passwordField.setPromptText("Password");

        sizeDSA1024Radio = new RadioButton("1024");
        sizeDSA1024Radio.setToggleGroup(toggleGroupDSA);

        sizeDSA2048Radio = new RadioButton("2048");
        sizeDSA2048Radio.setToggleGroup(toggleGroupDSA);

        Label dsaSizeLabel = new Label("DSA size: ");
        dsaSizeLabel.setLabelFor(sizeDSA1024Radio);

        elgamalCB = new CheckBox("ElGamal (for encryption)");

        sizeElGamal1024Radio = new RadioButton("1024");
        sizeElGamal1024Radio.setToggleGroup(toggleGroupElGamal);

        sizeElGamal2048Radio = new RadioButton("2048");
        sizeElGamal2048Radio.setToggleGroup(toggleGroupElGamal);

        sizeElGamal4096Radio = new RadioButton("4096");
        sizeElGamal4096Radio.setToggleGroup(toggleGroupElGamal);

        Label elGamalSizeLabel = new Label("ElGamal size: ");
        elGamalSizeLabel.setLabelFor(sizeElGamal1024Radio);

        sizeElGamal1024Radio.managedProperty().bind(sizeElGamal1024Radio.visibleProperty());
        sizeElGamal2048Radio.managedProperty().bind(sizeElGamal2048Radio.visibleProperty());
        sizeElGamal4096Radio.managedProperty().bind(sizeElGamal4096Radio.visibleProperty());
        elGamalSizeLabel.managedProperty().bind(elGamalSizeLabel.visibleProperty());

        sizeElGamal1024Radio.visibleProperty().bind(elgamalCB.selectedProperty());
        sizeElGamal2048Radio.visibleProperty().bind(elgamalCB.selectedProperty());
        sizeElGamal4096Radio.visibleProperty().bind(elgamalCB.selectedProperty());
        elGamalSizeLabel.visibleProperty().bind(elgamalCB.selectedProperty());

        elgamalCB.setSelected(true);
        sizeElGamal1024Radio.setSelected(true);
        sizeDSA1024Radio.setSelected(true);

        VBox vBox = new VBox();
        vBox.getChildren().addAll(
                nameField,
                emailField,
                passwordField,
                dsaSizeLabel,
                sizeDSA1024Radio,
                sizeDSA2048Radio,
                elgamalCB,
                elGamalSizeLabel,
                sizeElGamal1024Radio,
                sizeElGamal2048Radio,
                sizeElGamal4096Radio
        );
        vBox.setAlignment(Pos.TOP_LEFT);

        vBox.setSpacing(5);
        VBox.setMargin(elgamalCB, new Insets(35, 0, 0, 0));
        VBox.setMargin(dsaSizeLabel, new Insets(20, 0, 0, 0));

        VBox.setVgrow(passwordField, Priority.ALWAYS);

        getDialogPane().setContent(vBox);

        Platform.runLater(() -> nameField.requestFocus());

        setResultConverter(dialogButton -> {
            if (dialogButton == okButton) {
                int dsaSize = 0, elGamalSize = 0;

                if (sizeDSA1024Radio.isSelected()){
                    dsaSize = 1024;
                }
                else if (sizeDSA2048Radio.isSelected()){
                    dsaSize = 2048;
                }

                if (elgamalCB.isSelected()){
                    if (sizeElGamal1024Radio.isSelected()){
                        elGamalSize = 1024;
                    }
                    else if (sizeElGamal2048Radio.isSelected()){
                        elGamalSize = 2048;
                    }
                    else if (sizeElGamal4096Radio.isSelected()){
                        elGamalSize = 4096;
                    }
                }
                return new NewKeyPairModel(
                        nameField.getText(),
                        emailField.getText(),
                        dsaSize,
                        elGamalSize,
                        elgamalCB.isSelected(),
                        passwordField.getText()
                );
            }
            return null;
        });
    }
}
