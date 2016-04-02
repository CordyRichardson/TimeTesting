package com.richardson.timetesting;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Bundle;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v7.app.AppCompatActivity;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class MainActivity extends AppCompatActivity {
    Logger logger = Logger.getLogger(MainActivity.class.getName());
    final String testString = "Timer_Test_String_for_Yellow_Pepper_AvalPay";
    final String sharedPrefName = "TestPrefs";
    final String prefsKey = "prefsKey";
    final String fileName = "testFile";
    final String keyAlias = "testKeyAlias4";
    final String cipherParams = "AES/ECB/NoPadding";

    File file;

    SecretKey secretKey = null;
    byte[] encryptedBytes = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        /**
        initSharedPreferences();
        try{
                initInternalStorage();
                timeGetStringFromInternalStorage();
        } catch (IOException ex){}

        timeGetStringFromSharedPreferences();
        */

        //checkKeyStore();

        //doKeyChain();

        encryptString();
        for (int i = 0; i < 10; ++i) {
            timeGetKeyandDecrypt();
        }
        //decryptString();
    }

    public void initSharedPreferences(){
        SharedPreferences sharedPreferences = getSharedPreferences(sharedPrefName, MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPreferences.edit();
        editor.putString(prefsKey, testString);
        editor.commit();
    }

    public void initInternalStorage() throws IOException{

        File file = new File(getFilesDir(), fileName);
        FileOutputStream fos = openFileOutput(fileName, MODE_PRIVATE);
        fos.write(testString.getBytes());
        fos.close();
    }

    public void encryptString(){

        //1. generate secret key
        final int keyLength = 256;
        SecureRandom random = new SecureRandom();
        try{
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(keyLength, random);
            secretKey = keyGen.generateKey();
        } catch(NoSuchAlgorithmException ex){
            ex.printStackTrace();
        }

        //2. encode string
        byte[] keyBytes = secretKey.getEncoded();
        SecretKeySpec skeySpec = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
        try{
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(
                    new byte[cipher.getBlockSize()]));
            encryptedBytes = cipher.doFinal(testString.getBytes());

        } catch(NoSuchAlgorithmException ex){
            ex.printStackTrace();
        } catch(NoSuchPaddingException ex){
            ex.printStackTrace();
        } catch (InvalidKeyException ex){
            ex.printStackTrace();
        } catch(InvalidAlgorithmParameterException ex){
            ex.printStackTrace();
        } catch (IllegalBlockSizeException ex){
            ex.printStackTrace();
        } catch(BadPaddingException ex){
            ex.printStackTrace();
        }

        //3. store the encrypted password
      //  SharedPreferences sharedPreferences = getSharedPreferences(sharedPrefName, MODE_PRIVATE);
       // SharedPreferences.Editor editor = sharedPreferences.edit();
        //editor.putString("testString", encryptedBytes.toString());
        //editor.commit();
        String returnedString = new String(encryptedBytes);
        logger.info("Encrypted testString: " + returnedString);
    }

    public void decryptString(){

        try{
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(
                    new byte[cipher.getBlockSize()]));
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            logger.info("Decrypted string: " + decryptedBytes.toString());
        } catch (NoSuchAlgorithmException ex){
            ex.printStackTrace();
        } catch (NoSuchPaddingException ex){
            ex.printStackTrace();
        } catch (InvalidKeyException ex){
            ex.printStackTrace();
        } catch (InvalidAlgorithmParameterException ex){
            ex.printStackTrace();
        } catch (IllegalBlockSizeException ex){
            ex.printStackTrace();
        } catch (BadPaddingException ex){
            ex.printStackTrace();
        }
    }

    public void getStringFromSharedPreferences(){
        SharedPreferences sharedPreferences = getSharedPreferences(sharedPrefName, 0);
        String testString = sharedPreferences.getString(prefsKey, "test");
        logger.info("Preferences retrieved" + testString);
    }

    public void getStringFromInternalStorage() throws IOException{
        String filePath = this.getFilesDir().getAbsolutePath()+'/'+fileName;
        FileInputStream inputStream = new FileInputStream(filePath);
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        String readString = reader.readLine();
        logger.info("Getfile retrieved: " + readString);
        inputStream.close();
    }

    public void timeGetStringFromSharedPreferences(){
                long startTime = System.nanoTime();
                getStringFromSharedPreferences();
                long stopTime = System.nanoTime();

                long diff = stopTime - startTime;

                logger.info("GetPrefsTime: " + diff);
    }

    public void timeGetStringFromInternalStorage() throws IOException{
                long startTime = System.nanoTime();
                getStringFromInternalStorage();
                long stopTime = System.nanoTime();

                long diff = stopTime - startTime;

                logger.info("GetInteralStorage: " + diff);
    }

    public void timeGetKeyandDecrypt(){
        long startTime = System.nanoTime();
        decryptString();
        long stopTime = System.nanoTime();

        long diff = stopTime - startTime;

        logger.info("Time to decipher: " + diff);
    }

    public void doKeyChain(){
        KeyChainTask task = new KeyChainTask();
        task.execute(this);
    }

    private class KeyChainTask extends AsyncTask<Context, Void, Void>{

        public Void doInBackground(Context... params) {
            Context context = params[0];

            try {
                KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                try{
                    keyStore.load(null, null);



                } catch (IOException ex){
                    logger.info("IOException keychain get");
                    ex.printStackTrace();
                } catch (NoSuchAlgorithmException ex){
                    logger.info("Keychain task no such algo");
                    ex.printStackTrace();
                } catch(CertificateException ex){
                    logger.info("KeyChain Task Cert exception");
                    ex.printStackTrace();
                }
                Intent intent = KeyChain.createInstallIntent();
                intent.putExtra(KeyChain.EXTRA_NAME, keyStore.toString());
                startActivity(intent);
                SecretKey key = (SecretKey) KeyChain.getPrivateKey(context, keyAlias);
                logger.info("Key from task: " + key.toString());

            } catch (KeyStoreException ex){
                logger.info("Keystore exception in async task");
                ex.printStackTrace();
            }catch (KeyChainException ex){
                logger.info("keychain exception");
                ex.printStackTrace();
            } catch (InterruptedException ex){
                logger.info("interrupted exception");
            }
            return null;
        }
    }

}
