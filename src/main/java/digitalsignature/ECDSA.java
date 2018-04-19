package digitalsignature;

import org.apache.commons.codec.binary.Base64;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class ECDSA {

    private static final String BASE_STRING ="security ECDSATest";

    public static void main(String[] args) throws Exception {
        jdkECDSA();
    }

    public static void jdkECDSA() throws Exception{
        //生成秘钥
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();

        //签名
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(ecPrivateKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(BASE_STRING.getBytes());
        byte[] result = signature.sign();
        System.out.println("JDK ECDSA 签名:"+ Base64.encodeBase64String(result));


        //验签
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(ecPublicKey.getEncoded());
        keyFactory = KeyFactory.getInstance("EC");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(publicKey);
        signature.update(BASE_STRING.getBytes());
        boolean res = signature.verify(result);
        System.out.println("JDK ECDSA 验签结果："+res);

    }

}
