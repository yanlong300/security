package messagedigest;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 消息摘要算法MD系列实现
 */
public class MD5 {
    private static final String BASE_STRING ="security mdTest";

    public static void main(String[] args) throws NoSuchAlgorithmException {
        BCMD4(BASE_STRING);
        BCMD5(BASE_STRING);
        jdkMD2(BASE_STRING);
        jdkMD5(BASE_STRING);
    }

    /**
     * JDK实现MD2
     */
    public static void jdkMD2(String str) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("MD2");
        byte[] enStr = messageDigest.digest(str.getBytes());
        //将二进制转换为16禁止输出
        System.out.println("JDK的MD2摘要:"+new String(Hex.encodeHex(enStr)));
    }

    /**
     * bouncyCastle实现MD4
     */
    public static void BCMD4(String str){
        Digest digest = new MD4Digest();
        byte[] b = str.getBytes();
        digest.update(b,0,b.length);
        byte[] enStr = new byte[digest.getDigestSize()];
        digest.doFinal(enStr,0);
        //将二进制转换为16禁止输出
        System.out.println("B C的MD4摘要:"+new String(org.bouncycastle.util.encoders.Hex.toHexString(enStr)));
    }

    /**
     * bouncyCastle实现MD5
     */
    public static void BCMD5(String str){
        Digest digest = new MD5Digest();
        byte[] b = str.getBytes();
        digest.update(b,0,b.length);
        byte[] enStr = new byte[digest.getDigestSize()];
        digest.doFinal(enStr,0);
        //将二进制转换为16禁止输出
        System.out.println("B C的MD5摘要:"+new String(org.bouncycastle.util.encoders.Hex.toHexString(enStr)));
    }

    /**
     * JDK实现MD5
     */
    public static void jdkMD5(String str) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        byte[] enStr = messageDigest.digest(str.getBytes());
        //将二进制转换为16禁止输出
        System.out.println("JDK的MD5摘要:"+new String(Hex.encodeHex(enStr)));
    }
}
