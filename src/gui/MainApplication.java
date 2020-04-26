package gui;

import gui.models.KeyModel;
import javafx.application.Application;
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
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import pgp.KeyManagement;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class MainApplication extends Application
{

    private Scene mainScene;

    @Override
    public void start(Stage primaryStage) throws Exception
    {

        //mainScene = CreateMainScene(primaryStage);

        TabPane tabPane = new TabPane();

        tabPane.getTabs().add(CreateKeyTab(primaryStage));

        tabPane.getTabs().add(CreateMessagesTab(primaryStage));

        mainScene = new Scene(tabPane, 800, 400);

        primaryStage.setTitle("PGP");
        primaryStage.setScene(mainScene);
        primaryStage.setWidth(800);
        primaryStage.setHeight(400);

        primaryStage.show();
    }

    private Tab CreateKeyTab(Stage primaryStage){

        VBox vBox = new VBox();

        HBox hBox = new HBox();

        Button importButton = new Button("Import key");

        hBox.getChildren().add(importButton);

        vBox.getChildren().add(hBox);

        TableView tableView = new TableView();

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

                        KeyManagement.ImportKeyRing(fileInputStream);

                        UpdateTableView(tableView);

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

        textArea.setPrefRowCount(10);

        hBox.getChildren().add(textArea);

        VBox vBox = new VBox();

        VBox sendVbox = new VBox();

        // Encrypt
        CheckBox encryptCb = new CheckBox("Encrypt");
        ComboBox algorithmCb = new ComboBox();
        algorithmCb.getItems().addAll("AES128", "3DES");


        // Signing
        List<KeyModel> privateKeys = getAllPrivateKeys();
        CheckBox signCb = new CheckBox("Sign");
        ComboBox privateKeyCb = new ComboBox();
        privateKeyCb.getItems().addAll(privateKeys);
        TextField tfPassword = new TextField();

        // Compress
        CheckBox compressCb = new CheckBox("Compress");

        // Radix64
        CheckBox radixCb = new CheckBox("Radix-64 Encode");

        // Send Message
        Button sendButton = new Button("Send Message");

        sendVbox.getChildren().addAll(encryptCb, algorithmCb, signCb, privateKeyCb, tfPassword, compressCb, radixCb, sendButton);

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

    private void UpdateTableView(TableView tableView){

        tableView.getItems().clear();

        List<KeyModel> publicKeys = getAllPublicKeys();
        List<KeyModel> privateKeys = getAllPrivateKeys();

        tableView.getItems().addAll(publicKeys);
        tableView.getItems().addAll(privateKeys);

    }

    private List<KeyModel> getAllPublicKeys(){

        List<KeyModel> list = new ArrayList<>();

        Iterator<PGPPublicKeyRing> iterator = KeyManagement.publicKeyRings.getKeyRings();

        while (iterator.hasNext()){

            PGPPublicKeyRing pgpPublicKeyRing = iterator.next();

            String userID[] = pgpPublicKeyRing.getPublicKey().getUserIDs().next().split(" ");

            String keyID = Long.toHexString(pgpPublicKeyRing.getPublicKey().getKeyID()).toUpperCase();

            KeyModel keyModel = new KeyModel(userID[0], userID[1], keyID, pgpPublicKeyRing);

            list.add(keyModel);

        }

        return list;

    }

    private List<KeyModel> getAllPrivateKeys(){

        List<KeyModel> list = new ArrayList<>();

        Iterator<PGPSecretKeyRing> iterator = KeyManagement.secretKeyRings.getKeyRings();

        while (iterator.hasNext()){

            PGPSecretKeyRing pgpSecretKeyRing = iterator.next();

            String userID[] = pgpSecretKeyRing.getPublicKey().getUserIDs().next().split(" ");

            String keyID = Long.toHexString(pgpSecretKeyRing.getPublicKey().getKeyID()).toUpperCase();

            KeyModel keyModel = new KeyModel(userID[0], userID[1], keyID, pgpSecretKeyRing);

            list.add(keyModel);

        }

        return list;

    }

    public static void main(String[] args)
    {
        launch(args);
    }
}
