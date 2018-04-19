package asymmetrickeyencryption;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

/**
 * 非对称加密算法DH
 */
public class DH {
    private static final String BASE_STRING ="security DHTest";


    public static void main(String[] args) throws Exception {
        jdkDHFlow();
        //jdkDH(BASE_STRING);

    }

    /**
     * DH加密流程
     * @throws Exception
     */
    public static void jdkDHFlow() throws Exception {
        //1.发送方构建公钥私钥
        KeyPair senderKeyPair = jdkSenderPublicKey();
        //2.发送方发布公钥
        byte[] senderPublicKeyEncode = senderKeyPair.getPublic().getEncoded();
        //3.接收方构建公钥私钥->接收方通过发送方公钥构建公钥私钥
        KeyPair receiverKeyPair = jdkreceiverPublicKey(senderPublicKeyEncode);
        //4.接收方发布公钥
        byte[] receiverPublicKeyEncode = receiverKeyPair.getPublic().getEncoded();
        //5.发送方构建对称加密的秘钥->依据接收方公钥和自己的公钥私钥构建
        SecretKey senderDesKey = jdkGetSecretKey(senderKeyPair,receiverPublicKeyEncode);
        //6.接收方构建对称加密秘钥->依据发送方公钥和接收方公钥撕咬构建
        SecretKey receiverDesKey = jdkGetSecretKey(receiverKeyPair,senderPublicKeyEncode);
        //对比双方对称加密秘钥是否安相同
        if(Objects.equals(receiverDesKey,senderDesKey)){
            System.out.println("双方秘钥相同");
        }
        //7.发送方加密
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE,senderDesKey);
        byte[] result = cipher.doFinal(BASE_STRING.getBytes());
        System.out.println("JDK DH 加密:"+ Base64.encodeBase64String(result));
        //8.接收方解密
        cipher.init(Cipher.DECRYPT_MODE,receiverDesKey);
        result = cipher.doFinal(result);
        System.out.println("JDK DH 解密:"+new String(result));
    }

    /**
     * 发送方构建发送方公钥
     * @return 构建完成的公钥
     */
    public static KeyPair jdkSenderPublicKey() throws NoSuchAlgorithmException {
        //1.初始化发送方秘钥
        KeyPairGenerator senderKeyPairGenerator = KeyPairGenerator.getInstance("DH");
        senderKeyPairGenerator.initialize(512);
        //生成秘钥
        KeyPair senderKeyPair = senderKeyPairGenerator.generateKeyPair();
        return  senderKeyPair;
    }

    /**
     * 依据发送方公钥生成接收方公钥
     * @param senderPublicKey 发送方公钥
     * @return 接收方公钥
     */
    public static KeyPair jdkreceiverPublicKey(byte[] senderPublicKey) throws Exception {
        KeyFactory receiverKeyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(senderPublicKey);
        PublicKey receiverPublicKey = receiverKeyFactory.generatePublic(x509EncodedKeySpec);
        //使用和发送方一样的参数初始化
        DHParameterSpec dhParameterSpec = ((DHPublicKey) receiverPublicKey).getParams();
        KeyPairGenerator receiverKeyPairGenerator = KeyPairGenerator.getInstance("DH");
        //发送方公钥解析出来的dhParameterSpec
        receiverKeyPairGenerator.initialize(dhParameterSpec);
        KeyPair receiverKeyPair = receiverKeyPairGenerator.generateKeyPair();
        return receiverKeyPair;
    }

    /**
     * 自己的公钥私钥与对方的公钥构建 对称秘钥
     * @param keyPair 自己秘钥对
     * @param publicKey 对方公钥
     * @return 本地对称加密秘钥
     */
    public static SecretKey jdkGetSecretKey(KeyPair keyPair,byte[] publicKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
        PublicKey senderPublicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(keyPair.getPrivate());
        keyAgreement.doPhase(senderPublicKey,true);
        SecretKey secretKey = keyAgreement.generateSecret("DES");
        return  secretKey;
    }

    public static void jdkDH(String str) throws Exception {
        //1.初始化发送方秘钥
        KeyPairGenerator senderKeyPairGenerator = KeyPairGenerator.getInstance("DH");
        senderKeyPairGenerator.initialize(512);
        //生成秘钥
        KeyPair senderKeyPair = senderKeyPairGenerator.generateKeyPair();
        //获取发送方公钥
        byte[] publicKey = senderKeyPair.getPublic().getEncoded();

        //2.初始化接收方秘钥
        KeyFactory receiverKeyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
        PublicKey receiverPublicKey = receiverKeyFactory.generatePublic(x509EncodedKeySpec);
        //使用和发送方一样的参数初始化
        DHParameterSpec dhParameterSpec = ((DHPublicKey) receiverPublicKey).getParams();
        KeyPairGenerator receiverKeyPairGenerator = KeyPairGenerator.getInstance("DH");
        //发送方公钥解析出来的dhParameterSpec
        receiverKeyPairGenerator.initialize(dhParameterSpec);
        KeyPair receiverKeyPair = receiverKeyPairGenerator.generateKeyPair();
        //接收方私钥
        PrivateKey receiverPrivateKey = receiverKeyPair.getPrivate();
        //接收方公钥
        byte[] receiverPublicKeyEnc = receiverKeyPair.getPublic().getEncoded();

        //3.秘钥构建
        //构建接收方秘钥
        KeyAgreement receiverKeyAgreement = KeyAgreement.getInstance("DH");
        receiverKeyAgreement.init(receiverPrivateKey);
        receiverKeyAgreement.doPhase(receiverPublicKey,true);
        //生成接收方本地秘钥
        SecretKey receiverDesKey = receiverKeyAgreement.generateSecret("DES");
        //构建发送方秘钥
        KeyFactory senderKeyFactory = KeyFactory.getInstance("DH");
        x509EncodedKeySpec = new X509EncodedKeySpec(receiverPublicKeyEnc);
        PublicKey senderPublicKey = senderKeyFactory.generatePublic(x509EncodedKeySpec);
        KeyAgreement senderKeyAgreement = KeyAgreement.getInstance("DH");
        senderKeyAgreement.init(senderKeyPair.getPrivate());
        senderKeyAgreement.doPhase(senderPublicKey,true);
        SecretKey senderDesKey = senderKeyAgreement.generateSecret("DES");
        if(Objects.equals(receiverDesKey,senderDesKey)){
            System.out.println("双方秘钥相同");
        }

        //4.加密 解密
        //加密
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE,senderDesKey);
        byte[] result = cipher.doFinal(str.getBytes());
        System.out.println("JDK DH 加密:"+ Base64.encodeBase64String(result));
        //解密
        cipher.init(Cipher.DECRYPT_MODE,receiverDesKey);
        result = cipher.doFinal(result);
        System.out.println("JDK DH 解密:"+new String(result));
    }
}
