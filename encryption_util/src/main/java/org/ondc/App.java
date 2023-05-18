package org.ondc;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ondc.EncryptionUtil.EncryptionPayload;
import org.ondc.KeyUtil.DHKeyPair;

import com.google.gson.Gson;

public class App {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        DHKeyPair keyPair1 = KeyUtil.generateKeyPair();
        System.out.println("Key Pair 1 ==> "+ keyPair1.toString());
        DHKeyPair keyPair2 = KeyUtil.generateKeyPair();
        System.out.println("Key Pair 2 ==> "+ keyPair2.toString());

        String sharedKey1 = KeyUtil.generateSharedKey(keyPair1.getPrivateKey(), keyPair2.getPublicKey());
        System.out.println("SharedKey1 ==> "+ sharedKey1);
        String sharedKey2 = KeyUtil.generateSharedKey(keyPair2.getPrivateKey(), keyPair1.getPublicKey());
        System.out.println("SharedKey2 ==> "+ sharedKey2);

        System.out.println("sharedKey1 == sharedKey2 ==> " + sharedKey1.equals(sharedKey2));


        String rawData = "Hello This is ONDC Test Data";
        EncryptionPayload payload = EncryptionUtil.encryptData(sharedKey1, rawData);
        System.out.println("Payload ===> " + new Gson().toJson(payload));

        String decryptedData =  EncryptionUtil.decryptData(sharedKey2, payload);
        System.out.println("Decrypted Data ===> " + decryptedData);


    }
}
