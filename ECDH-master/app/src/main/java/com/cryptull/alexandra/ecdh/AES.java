package com.cryptull.alexandra.ecdh;

import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public enum AES {
    ;
    private static final String ENCRYPTION_KEY = "somepassword";
    private static final String ENCRYPTION_IV = "4e5Wa71fYoT7MFEX";

    public static String cifrar1(String msg , KeyAgreement key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            SecretKeySpec skey = new SecretKeySpec(md.digest(key.generateSecret()), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, skey, makeIv());
            return Base64.encodeBytes(cipher.doFinal(msg.getBytes()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String cifrar(String msg, String clave) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, makeKey(clave), makeIv());
            return Base64.encodeBytes(cipher.doFinal(msg.getBytes()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String descifrar1(String msg_cif , KeyAgreement key) {
        String decrypted = "";
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            SecretKeySpec skey = new SecretKeySpec(md.digest(key.generateSecret()), "AES");
            cipher.init(Cipher.DECRYPT_MODE, skey, makeIv());
            decrypted = new String(cipher.doFinal(Base64.decode(msg_cif)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return decrypted;
    }

    public static String descifrar(String msg_cif, String clave) {
        String decrypted = "";
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, makeKey(clave), makeIv());
            decrypted = new String(cipher.doFinal(Base64.decode(msg_cif)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return decrypted;
    }

    static AlgorithmParameterSpec makeIv() {
        try {
            return new IvParameterSpec(ENCRYPTION_IV.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    static Key makeKey() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] key = md.digest(ENCRYPTION_KEY.getBytes("UTF-8"));
            return new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return null;
    }

    static Key makeKey(String clave) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] key = md.digest(clave.getBytes("UTF-8"));
            return new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return null;
    }
}
