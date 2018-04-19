package asymmetrickeyencryption;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.spec.DHParameterSpec;
import java.security.*;

/**
 * 公钥加密算法
 * BC 实现
 */
public class ElGamal {

    private static final String BASE_STRING = "security DHTest";

    public static void main(String[] args) throws Exception {
        BCElGamal();
    }

    public static void BCElGamal() throws Exception {
        //添加bc加密工具
        Security.addProvider(new BouncyCastleProvider());
        //生成秘钥
        AlgorithmParameterGenerator algorithmParameterGenerator = AlgorithmParameterGenerator.getInstance("ElGamal");
        algorithmParameterGenerator.init(256);
        AlgorithmParameters algorithmParameters = algorithmParameterGenerator.generateParameters();
        DHParameterSpec dhParameterSpec = algorithmParameters.getParameterSpec(DHParameterSpec.class);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ElGamal");
        keyPairGenerator.initialize(dhParameterSpec,new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        System.out.println("ElGamal 公钥：" + Base64.encodeBase64String(publicKey.getEncoded()));
        System.out.println("ElGamal 私钥：" + Base64.encodeBase64String(privateKey.getEncoded()));

    }
}
