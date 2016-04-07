package com.richardson.timetesting;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.security.auth.x500.X500Principal;


public class MainActivity extends AppCompatActivity implements KeyChainAliasCallback {
    Logger logger = Logger.getLogger(MainActivity.class.getName());
    private static final String TEST_STRING= "Timer_Test_String_for_Yellow_Pepper_AvalPay";
    private static final String KEY_CONTAINER = "testKeyContainer";
    private static final String KEY_ALIAS = "testKey";
    private static final String KEYCHAIN_NAME = "test_keyChain2";
    final String fileName = "testFile";

    //algorithm/mode/padding strings
    private static final String CIPHER_SUITE1 = "RSA/ECB/NoPadding";
    private static final String CIPHER_SUITE2 = "RSA/ECB/PKCS1Padding";
    private static final String CIPHER_SUITE3 = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
    private static final String CIPHER_SUITE4 = "RSA/ECB/OAEPWithSHA-224AndMGF1Padding";
    private static final String CIPHER_SUITE5 = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String CIPHER_SUITE6 = "RSA/ECB/OAEPWithSHA-384AndMGF1Padding";
    private static final String CIPHER_SUITE7 = "RSA/ECB/OAEPWithSHA-512AndMGF1Padding";
    private static final String CIPHER_SUITE8 = "RSA/ECB/OAEPPadding";

    String cipherText = null;

    final Context context = this;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //initSharedPreferences();
        initInternalStorage();

        timeGetStringFromInternalStorage();
        //timeGetStringFromSharedPreferences();

        //createKeyPair();
        //encryptString();
        //timeDecryptText();
        //checkKeyChainInstalled();
        //installKeyChain();
    }

    /**
     * --KeyChain methods-----
     */

    private void installKeyChain(){
        try{
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            Certificate certificate = keyStore.getCertificate(KEY_ALIAS);
            Intent installIntent = KeyChain.createInstallIntent();
            installIntent.putExtra(KeyChain.EXTRA_CERTIFICATE, certificate.getEncoded());
            installIntent.putExtra(KeyChain.EXTRA_NAME, KEYCHAIN_NAME);
            startActivityForResult(installIntent, 1);
        } catch(Exception ex){
            ex.printStackTrace();
        }
    }

    private PrivateKey getPrivateKey(){
        try{
            return KeyChain.getPrivateKey(context, KEYCHAIN_NAME);
        } catch (Exception ex){
            ex.printStackTrace();
        }
        return null;
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data){
        if(requestCode == 1){
            if(resultCode == Activity.RESULT_OK){
                logger.info("Activity result OK");
                chooseCert();
            } else{
                logger.info("Activity result problem");
                super.onActivityResult(requestCode, resultCode, data);
            }
        }
    }

    private void chooseCert(){
        KeyChain.choosePrivateKeyAlias(this, this,
                new String[]{"rsa"},
                null,
                "localhost",
                -1,
                KEY_ALIAS);
    }

    @Override
    public void alias(String alias){
        //alias hardcoded for testing
    }

    /**
     * ------ KeyStore methods ---- *
     */

    private void createKeyPair() {
        KeyStore keyStore;
        try{
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            Calendar start = Calendar.getInstance();
            Calendar end = Calendar.getInstance();
            end.add(Calendar.YEAR, 1);

            //Android level 23 Marshmallow
            KeyGenParameterSpec specs = new KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_DECRYPT)
                    .setCertificateSubject(
                            new X500Principal("CN=Cordy Richardson, O=TestAuthority"))
                    .setCertificateSerialNumber(BigInteger.ONE)
                    .setCertificateNotBefore(start.getTime())
                    .setCertificateNotAfter(end.getTime())
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .build();
            /*
            //for Android level 22 and below
            KeyPairGeneratorSpec specs = new KeyPairGeneratorSpec.Builder(this)
                    .setAlias(KEY_ALIAS)
                    .setSubject(new X500Principal("CN=Cordy Richardson, O=TestAuthority"))
                    .setSerialNumber(BigInteger.ONE)
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .build();
                    */
            KeyPairGenerator generator =
                    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            generator.initialize(specs);

            KeyPair keys = generator.generateKeyPair();

        } catch(Exception ex){
            ex.printStackTrace();
        }
    }

    private void encryptString(){
        KeyStore keyStore;
        try{
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            KeyStore.PrivateKeyEntry privateKeyEntry =
                    (KeyStore.PrivateKeyEntry)keyStore.getEntry(KEY_ALIAS, null);
            RSAPublicKey publicKey = (RSAPublicKey)privateKeyEntry.getCertificate().getPublicKey();

            //encrypt the text
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            ByteArrayOutputStream byteos = new ByteArrayOutputStream();
            CipherOutputStream cipheros = new CipherOutputStream(byteos, cipher);
            cipheros.write(TEST_STRING.getBytes("UTF-8"));
            cipheros.close();

            byte[] cipherBytes = byteos.toByteArray();
            cipherText = new String(Base64.encodeToString(cipherBytes, Base64.DEFAULT));

        } catch (Exception e){
            e.printStackTrace();
        }
    }

    private void decryptText(){
        try{
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            KeyStore.PrivateKeyEntry privateKeyEntry =
                    (KeyStore.PrivateKeyEntry)keyStore.getEntry(KEY_ALIAS, null);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());
            CipherInputStream cipheris = new CipherInputStream(
              new ByteArrayInputStream(Base64.decode(cipherText, Base64.DEFAULT)), cipher);

            ArrayList<Byte> values = new ArrayList<>();
            int nextByte;
            while((nextByte = cipheris.read()) != -1){
                values.add((byte)nextByte);
            }

            byte[] bytes = new byte[values.size()];
            for(int i = 0; i < bytes.length; i++){
                bytes[i] = values.get(i).byteValue();
            }

            String finalText = new String(bytes, 0, bytes.length, "UTF-8");
            logger.info("Decrypted string: " + finalText);
        } catch (Exception e){
            e.printStackTrace();
        }
    }

    private void timeDecryptText(){
        long startTime = System.nanoTime();
        decryptText();
        long stopTime = System.nanoTime();

        long diff = stopTime - startTime;

        logger.info("GetPrefsTime: " + diff);
    }

    private void compareRSAAlgorithmCombinations(){

    }

    /**
     * -- Shared preferences and internal storage methods--- *
     */

    public void initSharedPreferences(){
        SharedPreferences sharedPreferences = getSharedPreferences(KEY_CONTAINER, MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPreferences.edit();
        editor.putString(KEY_ALIAS, TEST_STRING);
        editor.commit();
    }

    public void initInternalStorage(){

        File file = new File(getFilesDir(), fileName);
        try{
            FileOutputStream fos = openFileOutput(fileName, MODE_PRIVATE);
            fos.write(TEST_STRING.getBytes());
            fos.close();
        }catch (IOException ex){
            ex.printStackTrace();
        }

    }

    public void getStringFromSharedPreferences(){
        SharedPreferences sharedPreferences = getSharedPreferences(KEY_CONTAINER, 0);
        String testString = sharedPreferences.getString(KEY_ALIAS, "test");
        logger.info("Preferences retrieved" + testString);
    }

    public void getStringFromInternalStorage(){
        String filePath = this.getFilesDir().getAbsolutePath()+'/'+fileName;
        try{
            FileInputStream inputStream = new FileInputStream(filePath);
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            String readString = reader.readLine();
            logger.info("Getfile retrieved: " + readString);
            inputStream.close();
        } catch(IOException ex){
            ex.printStackTrace();
        }

    }

    public void timeGetStringFromSharedPreferences(){
                long startTime = System.nanoTime();
                getStringFromSharedPreferences();
                long stopTime = System.nanoTime();

                long diff = stopTime - startTime;

                logger.info("GetPrefsTime: " + diff);
    }

    public void timeGetStringFromInternalStorage(){
                long startTime = System.nanoTime();
                getStringFromInternalStorage();
                long stopTime = System.nanoTime();

                long diff = stopTime - startTime;

                logger.info("GetInteralStorage: " + diff);
    }

}
