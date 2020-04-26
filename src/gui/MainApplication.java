package gui;

import com.sun.javafx.collections.ObservableListWrapper;
import gui.models.KeyModel;
import gui.models.MessageModel;
import javafx.application.Application;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ListChangeListener;
import javafx.collections.ObservableList;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.input.MouseButton;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import pgp.KeyManagement;
import pgp.MessageManagement;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class MainApplication extends Application
{

    private Scene mainScene;

    private ObservableList<KeyModel> publicKeys;

    private ObservableList<KeyModel> privateKeys;

    private TableView tableView;

    private ComboBox privateKeysCb;

    private ListView<KeyModel> publicKeysLv;

    @Override
    public void start(Stage primaryStage) throws Exception
    {

        TabPane tabPane = new TabPane();

        tabPane.getTabs().add(CreateKeyTab(primaryStage));

        tabPane.getTabs().add(CreateMessagesTab(primaryStage));

        publicKeys = FXCollections.observableArrayList();

        privateKeys = FXCollections.observableArrayList();

        publicKeys.addListener(new ListChangeListener<KeyModel>()
        {
            @Override
            public void onChanged(Change<? extends KeyModel> c)
            {
                tableView.getItems().clear();
                tableView.getItems().addAll(privateKeys);
                tableView.getItems().addAll(publicKeys);

                publicKeysLv.getItems().clear();
                publicKeysLv.getItems().addAll(publicKeys);
            }
        });

        privateKeys.addListener(new ListChangeListener<KeyModel>()
        {
            @Override
            public void onChanged(Change<? extends KeyModel> c)
            {
                tableView.getItems().clear();
                tableView.getItems().addAll(privateKeys);
                tableView.getItems().addAll(publicKeys);

                privateKeysCb.getItems().clear();
                privateKeysCb.getItems().addAll(privateKeys);

            }
        });

        mainScene = new Scene(tabPane, 800, 400);

        primaryStage.setTitle("PGP");
        primaryStage.setScene(mainScene);
        primaryStage.setWidth(1200);
        primaryStage.setHeight(800);
        primaryStage.setResizable(false);

        primaryStage.show();
    }

    private Tab CreateKeyTab(Stage primaryStage){

        VBox vBox = new VBox();

        HBox hBox = new HBox();

        Button importButton = new Button("Import key");

        hBox.getChildren().add(importButton);

        vBox.getChildren().add(hBox);

        tableView = new TableView();

        TableColumn<String, KeyModel> nameColumn = new TableColumn<>("Name");
        nameColumn.setCellValueFactory(new PropertyValueFactory<>("name"));

        TableColumn<String, KeyModel> emailColumn = new TableColumn<>("E-mail");
        emailColumn.setCellValueFactory(new PropertyValueFactory<>("email"));

        TableColumn<String, KeyModel> keyIDColumn = new TableColumn<>("Key ID");
        keyIDColumn.setCellValueFactory(new PropertyValueFactory<>("keyID"));

        tableView.getColumns().add(nameColumn);
        tableView.getColumns().add(emailColumn);
        tableView.getColumns().add(keyIDColumn);

        tableView.setRowFactory(tv -> {

            TableRow<KeyModel> row = new TableRow<>();

            row.setOnMouseClicked(new EventHandler<MouseEvent>()
            {
                @Override
                public void handle(MouseEvent event)
                {
                    if (event.getButton() == MouseButton.SECONDARY){

                        ContextMenu contextMenu = new ContextMenu();
                        MenuItem exportKey = new MenuItem("Export key");
                        MenuItem expotSecretKey = new MenuItem("Export secret key");

                        contextMenu.getItems().add(exportKey);
                        contextMenu.getItems().add(expotSecretKey);

                        contextMenu.show(primaryStage, event.getScreenX(), event.getScreenY());

                    }
                }
            });

            return row;
        });

        vBox.getChildren().add(tableView);

        importButton.setOnMouseClicked(new EventHandler<MouseEvent>()
        {
            @Override
            public void handle(MouseEvent event)
            {

                FileChooser fileChooser = new FileChooser();
                fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("ASC file", "*.asc"));

                File file = fileChooser.showOpenDialog(primaryStage);

                if (file != null)
                {

                    FileInputStream fileInputStream = null;

                    try
                    {
                        fileInputStream = new FileInputStream(file);

                        PGPKeyRing key = KeyManagement.ImportKeyRing(fileInputStream);

                        if (key instanceof PGPPublicKeyRing){
                            publicKeys.add(new KeyModel(key));
                        }
                        else{
                            privateKeys.add(new KeyModel(key));
                        }

                    } catch (IOException e)
                    {

                        ShowError(e.getMessage());

                    } finally
                    {
                        if (fileInputStream != null)
                        {
                            try
                            {
                                fileInputStream.close();

                            } catch (IOException e)
                            {
                                ShowError(e.getMessage());
                            }
                        }
                    }
                }
            }
        });

        Tab keyTab = new Tab("Key Management", vBox);
        keyTab.setClosable(false);


        return keyTab;

    }

    private Tab CreateMessagesTab(Stage primaryStage){

        HBox hBox = new HBox();

        hBox.setPadding(new Insets(10));

        TextArea textArea = new TextArea();
        textArea.setPromptText("Enter message that you want to send...");
        textArea.setPrefRowCount(10);

        hBox.getChildren().add(textArea);

        VBox vBox = new VBox();

        VBox sendVbox = new VBox();

        // Encrypt
        CheckBox encryptCb = new CheckBox("Encrypt");
        ComboBox algorithmCb = new ComboBox();
        algorithmCb.getItems().addAll("AES128", "3DES");
        algorithmCb.setVisible(false);
        algorithmCb.getSelectionModel().selectFirst();
        publicKeysLv = new ListView<>();

        publicKeysLv.managedProperty().bind(publicKeysLv.visibleProperty());
        publicKeysLv.visibleProperty().bind(encryptCb.selectedProperty());

        algorithmCb.managedProperty().bind(algorithmCb.visibleProperty());
        algorithmCb.visibleProperty().bind(encryptCb.selectedProperty());

        // Signing
        CheckBox signCb = new CheckBox("Sign");
        privateKeysCb = new ComboBox();
        privateKeysCb.setVisible(false);
        privateKeysCb.getSelectionModel().selectFirst();
        TextField tfPassword = new TextField();
        tfPassword.setPromptText("Private key password...");

        privateKeysCb.managedProperty().bind(privateKeysCb.visibleProperty());
        privateKeysCb.visibleProperty().bind(signCb.selectedProperty());

        tfPassword.managedProperty().bind(tfPassword.visibleProperty());
        tfPassword.visibleProperty().bind(signCb.selectedProperty());

        // Compress
        CheckBox compressCb = new CheckBox("Compress");

        // Radix64
        CheckBox radixCb = new CheckBox("Radix-64 Encode");

        // Send Message
        Button sendButton = new Button("Send Message");

        Button recieveButton = new Button("Recieve Message");
        // Actions

        sendButton.setOnMouseClicked(new EventHandler<MouseEvent>()
        {
            @Override
            public void handle(MouseEvent event)
            {

                FileChooser fileChooser = new FileChooser();
                fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PGP file", "*.pgp"));

                File file = fileChooser.showSaveDialog(primaryStage);

                if (file != null)
                {

                    FileOutputStream fileOutputStream = null;

                    try
                    {

                        fileOutputStream = new FileOutputStream(file);

                        PGPSecretKeyRing secretKey = null;

                        if (signCb.isSelected()){

                            if (privateKeysCb.getValue() == null) throw new PGPException("No signing key selected.");

                            secretKey = (PGPSecretKeyRing) ((KeyModel) privateKeysCb.getValue()).getKeyRing();

                        }

                        List<PGPPublicKeyRing> publicKeys = new ArrayList<>();

                        int alg = -1;

                        if (encryptCb.isSelected()){

                            for (KeyModel publicKey : publicKeysLv.getSelectionModel().getSelectedItems()){

                                publicKeys.add((PGPPublicKeyRing) publicKey.getKeyRing());

                            }

                            String algorithm = (String) algorithmCb.getValue();

                            alg = (algorithm.equals("AES128")) ? SymmetricKeyAlgorithmTags.AES_128 : SymmetricKeyAlgorithmTags.TRIPLE_DES;

                        }

                        MessageManagement.SendMessage(
                                textArea.getText(),
                                encryptCb.isSelected(),
                                signCb.isSelected(),
                                compressCb.isSelected(),
                                radixCb.isSelected(),
                                secretKey,
                                publicKeys,
                                alg,
                                tfPassword.getText(),
                                fileOutputStream
                        );


                    } catch (IOException | NoSuchAlgorithmException e)
                    {

                        ShowError(e.getMessage());

                    } catch (SignatureException | PGPException e)
                    {
                        ShowError(e.getMessage());
                    } finally
                    {
                        if (fileOutputStream != null)
                        {
                            try
                            {
                                fileOutputStream.close();

                            } catch (IOException e)
                            {
                                ShowError(e.getMessage());
                            }
                        }
                    }
                }

            }
        });

        recieveButton.setOnMouseClicked(new EventHandler<MouseEvent>()
        {
            @Override
            public void handle(MouseEvent event)
            {
                FileChooser fileChooser = new FileChooser();
                fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PGP file", "*.pgp"));

                File file = fileChooser.showOpenDialog(primaryStage);

                try{

                    MessageModel message = null;

                    if (file != null)
                        message = MessageManagement.RecieveMessage(file);

                    if (message != null){

                        textArea.setText(message.getPlainText());

                        if (message.isVerified()){

                            Alert alert = new Alert(Alert.AlertType.CONFIRMATION, "Verified signature by " + message.getSignerInfo(), ButtonType.OK);
                            alert.showAndWait();

                        }
                        else{

                            Alert alert = new Alert(Alert.AlertType.WARNING, "Could not verify signature (You don't have public key of signer or signature is not valid.", ButtonType.OK);
                            alert.showAndWait();

                        }

                    }

                } catch (PGPException | IOException e)
                {
                    ShowError(e.getMessage());
                }
            }
        });

        // Adding to tab view

        sendVbox.getChildren().addAll(encryptCb, algorithmCb, publicKeysLv, signCb, privateKeysCb, tfPassword, compressCb, radixCb, sendButton, recieveButton);

        sendVbox.setSpacing(10);

        TitledPane sendPane = new TitledPane("Send Message", sendVbox);

        vBox.getChildren().add(sendPane);

        hBox.getChildren().add(vBox);

        Tab tab = new Tab("Send / Recieve Messages", hBox);
        tab.setClosable(false);

        return tab;

    }

    private void ShowError(String message){

        Alert alert = new Alert(Alert.AlertType.ERROR, message, ButtonType.CLOSE);

        alert.showAndWait();

    }

    public static void main(String[] args)
    {
        launch(args);
    }
}
