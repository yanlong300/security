package rsademo;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Receiver {
    private  String publicKey;

    private  String privateKey;

    public Receiver() {
        try {
            //生成公钥私钥
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(512);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
            this.publicKey = Util.base64Encoder(rsaPublicKey.getEncoded());
            this.privateKey = Util.base64Encoder(rsaPrivateKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
    public String getPublicKey() {
        return publicKey;
    }

    public String decoder(String src) throws Exception {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Util.base64Decoder(privateKey));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey key = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] encryptedData = Util.base64Decoder(src);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] cache;
        // 对数据分段解密
        for (int i = 0, offSet = 0; inputLen - offSet > 0; i++, offSet = i * Util.MAX_DECRYPT_BLOCK) {
            if (inputLen - offSet > Util.MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, Util.MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
        }

        byte[] decryptedData = out.toByteArray();
        out.close();
        String res = new String(decryptedData);
        System.out.println("接收方私钥解密：" + res);
        return res;
    }

    public  boolean verify(String senderPublicKey,String src) throws Exception {
        String[] str = src.split(",");
        String msgStr = str[0];
        String signStr = str[1].split("=")[1];
        //用公钥验签
        //用公钥验签
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Util.base64Decoder(senderPublicKey));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey senderPK = keyFactory.generatePublic(x509EncodedKeySpec);
        Signature signature = Signature.getInstance("MD5withRSA");
        signature.initVerify(senderPK);
        signature.update(Util.base64Decoder(signStr));
        boolean res = signature.verify(msgStr.getBytes());
        System.out.println("验签："+res);
        return res;
    }
}
