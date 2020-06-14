package etf.openpgp.sn160078dtf160077d.gui.helpers;

import etf.openpgp.sn160078dtf160077d.gui.models.KeyModel;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.util.Pair;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import java.util.List;

public class SelectKeyDialog extends Dialog<Pair<KeyModel, String>> {

    private ComboBox<KeyModel> comboBox;
    private PasswordField passwordField;

    public SelectKeyDialog(List<PGPSecretKeyRing> list){
        comboBox = new ComboBox<>();
        passwordField = new PasswordField();

        setTitle("Select key");

        ButtonType okButton = new ButtonType("OK", ButtonBar.ButtonData.OK_DONE);
        getDialogPane().getButtonTypes().addAll(okButton, ButtonType.CANCEL);

        comboBox.getItems().clear();

        for (PGPSecretKeyRing secretKeyRing : list) {
            comboBox.getItems().add(new KeyModel(secretKeyRing));
        }

        comboBox.getSelectionModel().selectFirst();

        VBox vBox = new VBox();

        vBox.getChildren().add(comboBox);
        vBox.getChildren().add(passwordField);

        vBox.setMargin(comboBox, new Insets(10));
        vBox.setMargin(passwordField, new Insets(10));

        getDialogPane().setContent(vBox);

        Platform.runLater(() -> passwordField.requestFocus());

        setResultConverter(dialogButton -> {
            if (dialogButton == okButton) {
                return new Pair<>(comboBox.getSelectionModel().getSelectedItem(), passwordField.getText());
            }
            return null;
        });
    }

}
