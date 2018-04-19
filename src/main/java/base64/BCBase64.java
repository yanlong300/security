package base64;


import org.bouncycastle.util.encoders.Base64;

/**
 * BouncyCastle实现Base64算法
 */
public class BCBase64 {
    private static final String BASE_STRING ="security base64";
    
    public static void main(String[] args) {
        System.out.println("原始字符串： " + BASE_STRING);
        byte[] encStr = Base64.encode(BASE_STRING.getBytes());
        System.out.println("Base64编码后： " + new String(encStr));
        String deStr = new String(Base64.decode(encStr));
        System.out.println("Base64解码后： "+deStr);
       
    }
}
