package rsademo;


import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.IOException;

public class Util {
    public static final int MAX_ENCRYPT_BLOCK = 53;
    public static final int MAX_DECRYPT_BLOCK = 64;

    public static String base64Encoder(byte[] bytes){
        BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encode(bytes);
    }

    public static byte[] base64Decoder(String str) throws IOException {
        BASE64Decoder decoder = new BASE64Decoder();
        return decoder.decodeBuffer(str);
    }


}
