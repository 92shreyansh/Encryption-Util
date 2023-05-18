package org.ondc;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

public class EncryptionUtil {
    public static class EncryptionPayload {
        @SerializedName("encrypted_data")
        private String encrypedData;
        private String nonce;
        private String hmac;

        public String getEncrypedData() {
            return encrypedData;
        }

        public void setEncrypedData(String encrypedData) {
            this.encrypedData = encrypedData;
        }

        public String getNonce() {
            return nonce;
        }

        public void setNonce(String nonce) {
            this.nonce = nonce;
        }

        public String getHmac() {
            return hmac;
        }

        public void setHmac(String hmac) {
            this.hmac = hmac;
        }

        public String toBase64String() {
            return bytesToString(new Gson().toJson(this).getBytes());
        }

    }

    public static EncryptionPayload encryptData(String key, String data) {
        EncryptionPayload encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKey sKey = KeyUtil.sharedKeyFromString(key);
            SecretKeySpec keySpec = new SecretKeySpec(sKey.getEncoded(), "X25519");
            SecureRandom secureRandom = new SecureRandom();
            byte[] iv = new byte[12];
            secureRandom.nextBytes(iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(128, iv));
            byte[] eData = cipher.doFinal(data.getBytes());
            encryptedData = new EncryptionPayload();
            int tagLengthBytes = 128 / 8;
            byte[] authTag = new byte[tagLengthBytes];
            ByteBuffer ciphertextBuffer = ByteBuffer.wrap(eData);
            ciphertextBuffer.get(authTag);
            encryptedData.setEncrypedData(bytesToString(eData));
            encryptedData.setNonce(bytesToString(iv));
            encryptedData.setHmac(bytesToString(authTag));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptedData;
    }

    public static String decryptData(String key, EncryptionPayload encryptedData) {
        String rawData = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] nonce = Base64.getDecoder().decode(encryptedData.getNonce());
            byte[] authTagBytes = Base64.getDecoder().decode(encryptedData.getHmac());
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData.getEncrypedData());
            SecretKey sKey = KeyUtil.sharedKeyFromString(key);
            SecretKeySpec keySpec = new SecretKeySpec(sKey.getEncoded(), "X25519");
            cipher.init(Cipher.DECRYPT_MODE, sKey, new GCMParameterSpec(128, nonce));
            cipher.updateAAD(authTagBytes);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(128, nonce));
            byte[] dData = cipher.doFinal(encryptedBytes);
            rawData = new String(dData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return rawData;
    }

    private static String bytesToString(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}
