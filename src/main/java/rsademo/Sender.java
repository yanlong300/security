package rsademo;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Sender {

    private String publicKey;

    private  String privateKey;

    /**
     * 构造方法创建公钥私钥
     */
    public Sender() {
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
    /**
     获取公钥
     */
    public String getPublicKey() {
        return publicKey;
    }

    /**
     * 使用私钥签名
     * @param msg 消息
     */
    public String sign(String msg) throws Exception{
        //执行签名
        //用私钥签名
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Util.base64Decoder(privateKey));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        Signature signature = Signature.getInstance("MD5withRSA");
        signature.initSign(privateKey);
        signature.update(msg.getBytes());
        byte[] result = signature.sign();
        String signMsg = Util.base64Encoder(result);
        System.out.println("发送方将数据签名："+ signMsg);
        return signMsg;
    }
    /**
     * 加密数据
     * 加密数据需要分段进行
     * 、
     */
    public String encode(String receiverPublicKey,String src) throws Exception {
        // 公钥加密
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Util.base64Decoder(receiverPublicKey));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey receiverPK = keyFactory.generatePublic(x509EncodedKeySpec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, receiverPK);
        byte[] data = src.getBytes();
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > Util.MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, Util.MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * Util.MAX_ENCRYPT_BLOCK;
        }
        byte[] result = out.toByteArray();
        out.close();
        String res = Util.base64Encoder(result);
        System.out.println("接收方公钥加密：" + res);
        return res;
    }


}
