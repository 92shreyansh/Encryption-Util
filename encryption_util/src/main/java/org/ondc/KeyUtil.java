package org.ondc;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyUtil {
    public static class DHKeyPair {
        private String publicKey;
        private String privateKey;

        public DHKeyPair(KeyPair keyPair) {
            this.publicKey = keyToString(keyPair.getPublic());
            this.privateKey = keyToString(keyPair.getPrivate());
        }

        public String getPublicKey() {
            return publicKey;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        @Override
        public String toString() {
            return "DHKeyPair [publicKey=" + publicKey + ", privateKey=" + privateKey + "]";
        }
        

    }

    public static DHKeyPair generateKeyPair() {
        DHKeyPair generatKeyPair = null;
        try {
            KeyPair keyPair = KeyPairGenerator.getInstance("X25519").generateKeyPair();
            generatKeyPair = new DHKeyPair(keyPair);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return generatKeyPair;
    }

    public static String generateSharedKey(String privateKeyStr, String publicKeyStr){
        String sharedKey = null;
        KeyAgreement ka;
        try {
            Key privateKey = privateKeyFromString(privateKeyStr);
            Key publicKey = publicKeyFromString(publicKeyStr);
            ka = KeyAgreement.getInstance("X25519", "BC");
            ka.init(privateKey);
            ka.doPhase(publicKey, true);
            SecretKey sKey = ka.generateSecret("X25519");
            sharedKey = keyToString(sKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sharedKey;
    }

    public static String keyToString(Key key) {
        byte[] encodedKey = key.getEncoded();
        return Base64.getEncoder().encodeToString(encodedKey);
    }

    public static PublicKey publicKeyFromString(String publicKeyStr) throws Exception {
        byte[] encodedKey = Base64.getDecoder().decode(publicKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance("X25519");
        return keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
    }

    public static PrivateKey privateKeyFromString(String privateKeyStr) throws Exception {
        byte[] encodedKey = Base64.getDecoder().decode(privateKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance("X25519");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
    }

    public static SecretKey sharedKeyFromString(String sharedKeyString) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(sharedKeyString);
        return new SecretKeySpec(decodedKey, "X25519");
    }
}
