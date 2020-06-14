package etf.openpgp.sn160078dtf160077d.gui;

import etf.openpgp.sn160078dtf160077d.gui.helpers.NewKeyPairDialog;
import etf.openpgp.sn160078dtf160077d.gui.helpers.PasswordDialog;
import etf.openpgp.sn160078dtf160077d.gui.models.KeyModel;
import etf.openpgp.sn160078dtf160077d.gui.models.MessageModel;
import etf.openpgp.sn160078dtf160077d.gui.models.NewKeyPairModel;
import javafx.application.Application;
import javafx.collections.FXCollections;
import javafx.collections.ListChangeListener;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.input.MouseButton;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.text.Font;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.util.encoders.Hex;
import etf.openpgp.sn160078dtf160077d.pgp.KeyManagement;
import etf.openpgp.sn160078dtf160077d.pgp.MessageManagement;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;

public class MainApplication extends Application
{
    private Scene mainScene;

    private ObservableList<KeyModel> publicKeys;

    private ObservableList<KeyModel> privateKeys;

    private TableView tableViewPrivateKeys, tableViewPublicKeys;

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
                KeysListChanged();
            }
        });

        privateKeys.addListener(new ListChangeListener<KeyModel>()
        {
            @Override
            public void onChanged(Change<? extends KeyModel> c)
            {
                KeysListChanged();
            }
        });

        // adding to observable list
        updatePublicAndPrivateObservableLists();

        mainScene = new Scene(tabPane, 800, 400);

        primaryStage.setTitle("PGP");
        primaryStage.setScene(mainScene);
        primaryStage.setWidth(800);
        primaryStage.setHeight(600);
        primaryStage.setResizable(false);

        primaryStage.show();
    }

    private void KeysListChanged(){

        tableViewPublicKeys.getItems().clear();
        tableViewPrivateKeys.getItems().clear();

        tableViewPrivateKeys.getItems().addAll(privateKeys);
        tableViewPublicKeys.getItems().addAll(publicKeys);

        publicKeysLv.getItems().clear();
        publicKeysLv.getItems().addAll(publicKeys);

        privateKeysCb.getItems().clear();
        privateKeysCb.getItems().addAll(privateKeys);
    }

    private Tab CreateKeyTab(Stage primaryStage){

        VBox vBox = new VBox();
        vBox.setAlignment(Pos.CENTER);
        vBox.setSpacing(3);

        HBox hBox = new HBox();

        Button importButton = new Button("Import key");
        Button generateNewKeyPairButton = new Button("Generate new key pair");

        hBox.getChildren().add(generateNewKeyPairButton);
        hBox.getChildren().add(importButton);

        hBox.setSpacing(10);

        vBox.getChildren().add(hBox);
        vBox.setMargin(hBox, new Insets(10, 0, 0, 0));

        tableViewPrivateKeys = new TableView();
        tableViewPublicKeys = new TableView();

        Label privateKeysLabel, publicKeysLabel;

        publicKeysLabel = new Label("PUBLIC KEYS");
        publicKeysLabel.setLabelFor(tableViewPublicKeys);
        publicKeysLabel.setFont(new Font(20));

        privateKeysLabel = new Label("PRIVATE KEYS");
        privateKeysLabel.setLabelFor(tableViewPrivateKeys);
        privateKeysLabel.setFont(new Font(20));

        vBox.getChildren().add(publicKeysLabel);
        CreateTableView(vBox, tableViewPublicKeys, true, primaryStage);

        vBox.getChildren().add(privateKeysLabel);
        CreateTableView(vBox, tableViewPrivateKeys, false, primaryStage);

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

        generateNewKeyPairButton.setOnMouseClicked(new EventHandler<MouseEvent>() {
            @Override
            public void handle(MouseEvent mouseEvent) {
                NewKeyPairDialog dialog = new NewKeyPairDialog();

                Optional<NewKeyPairModel> optNewKeyPairModel = dialog.showAndWait();

                if (optNewKeyPairModel.isPresent()){
                    NewKeyPairModel newKeyPairModel = optNewKeyPairModel.get();
                    try {
                        if (newKeyPairModel.getEmail().equals("") || newKeyPairModel.getName().equals("") || newKeyPairModel.getPassword().equals("")){
                            throw new PGPException("You need to fill name, email and password");
                        }
                        KeyManagement.GenerateKeyRing(
                                newKeyPairModel.getName(),
                                newKeyPairModel.getEmail(),
                                newKeyPairModel.getPassword(),
                                newKeyPairModel.getSizeDSA(),
                                newKeyPairModel.isElGamal(),
                                newKeyPairModel.getSizeElGamal()
                                );
                        updatePublicAndPrivateObservableLists();
                    } catch (Exception e) {
                        ShowError(e.getMessage());
                    }
                }

            }
        });

        Tab keyTab = new Tab("Key Management", vBox);
        keyTab.setClosable(false);

        return keyTab;

    }

    private void updatePublicAndPrivateObservableLists(){

        publicKeys.clear();
        privateKeys.clear();

        Iterator<PGPPublicKeyRing> publicKeyRingIterator = KeyManagement.publicKeyRings.getKeyRings();
        while (publicKeyRingIterator.hasNext()){
            PGPPublicKeyRing publicKeyRing = publicKeyRingIterator.next();
            publicKeys.add(new KeyModel(publicKeyRing));
        }

        // adding to observable list
        Iterator<PGPSecretKeyRing> secretKeyRingIterator = KeyManagement.secretKeyRings.getKeyRings();
        while (secretKeyRingIterator.hasNext()){
            PGPSecretKeyRing secretKeyRing = secretKeyRingIterator.next();
            privateKeys.add(new KeyModel(secretKeyRing));
        }
    }

    private void CreateTableView(VBox vBox, TableView tableView, boolean isPublic, Stage primaryStage){
        TableColumn<String, KeyModel> nameColumn = new TableColumn<>("Name");
        nameColumn.setCellValueFactory(new PropertyValueFactory<>("name"));
        nameColumn.prefWidthProperty().bind(tableView.widthProperty().divide(5));

        TableColumn<String, KeyModel> emailColumn = new TableColumn<>("E-mail");
        emailColumn.setCellValueFactory(new PropertyValueFactory<>("email"));
        emailColumn.prefWidthProperty().bind(tableView.widthProperty().divide(3));

        TableColumn<String, KeyModel> keyIDColumn = new TableColumn<>("Key ID");
        keyIDColumn.setCellValueFactory(new PropertyValueFactory<>("keyID"));
        keyIDColumn.prefWidthProperty().bind(tableView.widthProperty().divide(2.14));

        tableView.getColumns().add(nameColumn);
        tableView.getColumns().add(emailColumn);
        tableView.getColumns().add(keyIDColumn);

        TableView finalTableView = tableView;
        tableView.setRowFactory(tv -> {

            TableRow<KeyModel> row = new TableRow<>();

            row.setOnMouseClicked(new EventHandler<MouseEvent>()
            {
                @Override
                public void handle(MouseEvent event)
                {
                    if (event.getButton() == MouseButton.SECONDARY){

                        KeyModel selectedModel = (KeyModel) finalTableView.getSelectionModel().getSelectedItem();

                        PGPSecretKeyRing secretKeyRing = null;
                        PGPPublicKeyRing publicKeyRing = null;

                        if (isPublic){
                            publicKeyRing = (PGPPublicKeyRing) selectedModel.getKeyRing();
                        }
                        else {
                            secretKeyRing = (PGPSecretKeyRing) selectedModel.getKeyRing();
                        }

                        ContextMenu contextMenu = new ContextMenu();

                        MenuItem exportKey = new MenuItem("Export key");
                        MenuItem deleteKey = new MenuItem("Delete key");

                        contextMenu.getItems().add(exportKey);
                        contextMenu.getItems().add(deleteKey);

                        PGPPublicKeyRing finalPublicKeyRing = publicKeyRing;
                        PGPSecretKeyRing finalSecretKeyRing = secretKeyRing;
                        exportKey.setOnAction(new EventHandler<ActionEvent>() {
                            @Override
                            public void handle(ActionEvent actionEvent) {
                                String fingerPrint = "";
                                byte [] bytes;
                                if (isPublic){
                                    bytes = finalPublicKeyRing.getPublicKey().getFingerprint();
                                }
                                else {
                                    bytes = finalSecretKeyRing.getPublicKey().getFingerprint();
                                }

                                fingerPrint = Hex.toHexString(bytes).toUpperCase();

                                FileChooser fileChooser = new FileChooser();

                                fileChooser.setInitialFileName(fingerPrint + ".asc");
                                fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("ASC files", "*.asc"));

                                File file = fileChooser.showSaveDialog(primaryStage);

                                if (file != null){
                                    FileOutputStream fileOutputStream = null;
                                    try {
                                        fileOutputStream = new FileOutputStream(file);
                                    } catch (FileNotFoundException e) {
                                        e.printStackTrace();
                                    }
                                    if (isPublic){
                                        try {
                                            KeyManagement.ExportPublicKeyRing(finalPublicKeyRing, fileOutputStream, true);
                                        } catch (IOException e) {
                                            e.printStackTrace();
                                        }
                                    }
                                    else {
                                        try {
                                            KeyManagement.ExportSecretKeyRing(finalSecretKeyRing, fileOutputStream, true);
                                        } catch (IOException e) {
                                            e.printStackTrace();
                                        }
                                    }
                                    try {
                                        fileOutputStream.close();
                                    } catch (IOException e) {
                                        e.printStackTrace();
                                    }
                                }
                            }
                        });


                        deleteKey.setOnAction(new EventHandler<ActionEvent>() {
                            @Override
                            public void handle(ActionEvent actionEvent) {
                                if (isPublic){
                                    try {
                                        KeyManagement.RemovePublicKeyRing(selectedModel.getKeyRing().getPublicKey().getKeyID());
                                        removeFromPublicObservableList(selectedModel.getKeyRing().getPublicKey().getKeyID());
                                    } catch (PGPException e) {
                                        ShowError(e.getMessage() );
                                    }
                                }
                                else {

                                    PasswordDialog dialog = new PasswordDialog();

                                    Optional<String> password = dialog.showAndWait();

                                    if (password.isPresent()) {
                                        try {
                                            KeyManagement.RemoveSecretKeyRing(selectedModel.getKeyRing().getPublicKey().getKeyID(), password.get());
                                            removeFromSecretObservableList(selectedModel.getKeyRing().getPublicKey().getKeyID());
                                        } catch (PGPException e) {
                                            ShowError("Wrong password!");
                                        }
                                    }
                                }
                            }
                        });

                        contextMenu.show(primaryStage, event.getScreenX(), event.getScreenY());
                    }
                }
            });

            return row;
        });


        vBox.getChildren().add(tableView);
    }

    private void removeFromPublicObservableList(long keyID){
        for (KeyModel keyModel: publicKeys){
            if (keyModel.getKeyRing().getPublicKey().getKeyID() == keyID){
                publicKeys.remove(keyModel);
                return;
            }
        }
    }
    private void removeFromSecretObservableList(long keyID){
        for (KeyModel keyModel: privateKeys){
            if (keyModel.getKeyRing().getPublicKey().getKeyID() == keyID){
                privateKeys.remove(keyModel);
                return;
            }
        }
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
        publicKeysLv.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);

        publicKeysLv.managedProperty().bind(publicKeysLv.visibleProperty());
        publicKeysLv.visibleProperty().bind(encryptCb.selectedProperty());

        algorithmCb.managedProperty().bind(algorithmCb.visibleProperty());
        algorithmCb.visibleProperty().bind(encryptCb.selectedProperty());

        // Signing
        CheckBox signCb = new CheckBox("Sign");
        privateKeysCb = new ComboBox();
        privateKeysCb.setVisible(false);
        privateKeysCb.getSelectionModel().selectFirst();
        PasswordField tfPassword = new PasswordField();
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

        Button receiveButton = new Button("Receive Message");
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

//                        if (signCb.isSelected() && !encryptCb.isSelected()){
//                            MessageManagement.OnlySignMessage(
//                                    textArea.getText(),
//                                    secretKey,
//                                    alg,
//                                    tfPassword.getText(),
//                                    fileOutputStream
//                            );
//                        }
//                        else {
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
//                        }

                    } catch (IOException | NoSuchAlgorithmException e)
                    {

                        ShowError(e.getMessage());

                    } catch (SignatureException | PGPException e)
                    {
                        ShowError(e.getMessage());
                    } finally
                    {

                        tfPassword.setText("");
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

        receiveButton.setOnMouseClicked(new EventHandler<MouseEvent>()
        {
            @Override
            public void handle(MouseEvent event)
            {
                FileChooser fileChooser = new FileChooser();
                fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("SIG, PGP and GPG files", "*.sig", "*.pgp", "*.gpg"));

                File file = fileChooser.showOpenDialog(primaryStage);

                try{

                    MessageModel message = null;

                    if (file != null) {
                        if (file.getAbsolutePath().substring(file.getPath().lastIndexOf(".")).equals(".sig")){

                            File messageFile = new File(file.getAbsolutePath().subSequence(0, file.getPath().lastIndexOf('.')).toString());

                            if (!messageFile.exists()){
                                throw new PGPException("Cannot find message file: " + messageFile.getAbsolutePath());
                            }

                            message = MessageManagement.ReceiveDetachedMessage(file, messageFile);

                        }
                        else {

                            message = MessageManagement.ReceiveMessage(file);

                        }
                    }
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

        sendVbox.getChildren().addAll(encryptCb, algorithmCb, publicKeysLv, signCb, privateKeysCb, tfPassword, compressCb, radixCb, sendButton, receiveButton);

        sendVbox.setSpacing(10);

        TitledPane sendPane = new TitledPane("Send Message", sendVbox);

        vBox.getChildren().add(sendPane);

        hBox.getChildren().add(vBox);

        Tab tab = new Tab("Send / Receive Messages", hBox);
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

    @Override
    public void stop() throws Exception {
        KeyManagement.SaveAfterExit();
        super.stop();
    }
}
