# Java中加密算法介绍及其实现

## 1.Base64编码算法

###  Base64简介
>**Base64是网络上最常见的用于传输8Bit字节码的编码方式之一，Base64就是一种基于64个可打印字符来表示二进制数据的方法。可查看RFC2045～RFC2049，上面有MIME的详细规范。**

**Base64编码是从二进制到字符的过程，可用于在HTTP环境下传递较长的标识信息。例如，在Java Persistence系统Hibernate中，就采用了Base64来将一个较长的唯一标识符（一般为128-bit的UUID）编码为一个字符串，用作HTTP表单和HTTP GET URL中的参数。在其他应用程序中，也常常需要把二进制数据编码为适合放在URL（包括隐藏表单域）中的形式。此时，采用Base64编码具有不可读性，需要解码后才能阅读。**

码表

| 索引     | 编码     | 索引     | 编码     | 索引     | 编码     | 索引  | 编码|
| :-----: | :------: |:-----: | :------: |:-----: | :------: |:------: | :------: |
|0|A|17|R|34|i|51|z|
|1|B|18|S|35|j|52|0|
|2|C|19|T|36|k|53|1|
|3|D|20|U|37|l|54|2|
|4|E|21|V|38|m|55|3|
|5|F|22|W|39|n|56|4|
|6|G|23|X|40|o|57|5|
|7|H|24|Y|41|p|58|6|
|8|I|25|Z|42|q|59|7|
|9|J|26|a|43|r|60|8|
|10|K|27|b|44|s|61|9|
|11|L|28|c|45|t|62|+|
|12|M|29|d|46|u|63|/|
|13|N|30|e|47|v|
|14|O|31|f|48|w|
|15|P|32|g|49|x|
|16|Q|33|h|50|y|

>**特点：加密原理简单**

### Base64实现
一般的来说加密数据需要使用到如下三个包  
JDK：java.security  
CC： Commons Codec  
BC： Bouncy Castle  

#### JDK实现
JDK 1.7写法
```Java
//加密
public static String jdkBase64Encoder(String str){
    BASE64Encoder encoder = new BASE64Encoder();
    return encoder.encode(str.getBytes());
}
//解密
public static String jdkBase64decoder(String str) throws IOException {
    BASE64Decoder decoder = new BASE64Decoder();
    return new String(decoder.decodeBuffer(str));
}
//调用
public static void main(String[] args) throws IOException {
    System.out.println("原始字符串： " + BASE_STRING);
    String enStr = jdkBase64Encoder(BASE_STRING);
    System.out.println("Base64编码后： " + enStr);
    String deStr = jdkBase64decoder(enStr);
    System.out.println("Base64解码后： "+deStr);
}
```
结果
>原始字符串： security base64  
Base64编码后： c2VjdXJpdHkgYmFzZTY0  
Base64解码后： security base64  

JDK1.8+写法
```Java
public static String jdkBase64Encoder(String str){
    String desc = Base64.getEncoder().encodeToString(str.getBytes(StandardCharsets.UTF_8));  
    System.out.println("加密后的字符串为:"+desc);  
}

public static String jdkBase64decoder(String str) throws IOException {
    String unDecodeStr=new String(Base64.getDecoder().decode(str),StandardCharsets.UTF_8);  
    System.out.println("解密后的字符串为"+unDecodeStr);  
}
```

#### Commons Codec实现
CC包的写法是简化了许多,类似JDK1.8的写法。
MAVEN依赖
```html
<dependency>
    <groupId>commons-codec</groupId>
    <artifactId>commons-codec</artifactId>
    <version>1.10</version>
</dependency>
```

```Java
import org.apache.commons.codec.binary.Base64;

import java.io.IOException;

/**
 * CommonCodec Base64
 * @author yanlong
 */
public class CCBase64 {
    private static final String BASE_STRING ="security base64";

    public static void main(String[] args) throws IOException {
        System.out.println("原始字符串： " + BASE_STRING);
        byte[] encStr = Base64.encodeBase64(BASE_STRING.getBytes());
        System.out.println("Base64编码后： " + new String(encStr));
        String deStr = new String(Base64.encodeBase64(encStr));
        System.out.println("Base64解码后： "+deStr);
    }
}
```
#### Bouncy Castle实现
MAVEN依赖
```html
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcpkix-jdk15on</artifactId>
    <version>1.55</version>
</dependency>
```

```Java
import org.bouncycastle.util.encoders.Base64;

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
```
BC的调用代码相较于CC和JDK更少了。



## 2.消息摘要算法（Message-Digest Algorithm）及其实现

### MD算法简介
>**消息摘要算法的主要特征是加密过程不需要密钥，并且经过加密的数据无法被解密，只有输入相同的明文数据经过相同的消息摘要算法才能得到相同的密文。消息摘要算法不存在密钥的管理与分发问题，适合于分布式网络上使用。由于其加密计算的工作量相当巨大，所以以前的这种算法通常只用于数据量有限的情况下的加密，例如计算机的口令就是用不可逆加密算法加密的。近年来，随着计算机性能的飞速改善，加密速度不再成为限制这种加密技术发展的桎梏，因而消息摘要算法应用的领域不断增加。**

消息摘要算法主要应用在**数字签名**领域，作为对明文的摘要算法。著名的摘要算法有RSA公司的MD5算法和SHA-1算法及其大量的变体。

>**特点：单向加密，长度统一**


### MD算法实现
一般的加密算法实现通过两个包实现  
JDK：java.security  
BC： Bouncy Castle  

#### 1.MD2
```Java
public static void jdkMD2(String str) throws NoSuchAlgorithmException {
    MessageDigest messageDigest = MessageDigest.getInstance("MD2");
    byte[] enStr = messageDigest.digest(str.getBytes());
    //将二进制转换为16进制输出
    System.out.println("JDK的MD2摘要:"+new String(Hex.encodeHex(enStr)));
}
```

#### 2.MD4
```Java
public static void BCMD4(String str) throws NoSuchAlgorithmException {
    Digest digest = new MD4Digest();
    byte[] b = str.getBytes();
    digest.update(b,0,b.length);
    byte[] enStr = new byte[digest.getDigestSize()];
    digest.doFinal(enStr,0);
    //将二进制转换为16禁止输出
    System.out.println("B C的MD4摘要:"+new String(org.bouncycastle.util.encoders.Hex.toHexString(enStr)));
}
```
#### 3.MD5
BC实现
```Java
public static void BCMD5(String str) throws NoSuchAlgorithmException {
      Digest digest = new MD5Digest();
      byte[] b = str.getBytes();
      digest.update(b,0,b.length);
      byte[] enStr = new byte[digest.getDigestSize()];
      digest.doFinal(enStr,0);
      //将二进制转换为16禁止输出
      System.out.println("B C的MD5摘要:"+new String(org.bouncycastle.util.encoders.Hex.toHexString(enStr)));
  }
```
JDK实现
```Java
public static void jdkMD5(String str) throws NoSuchAlgorithmException {
    MessageDigest messageDigest = MessageDigest.getInstance("MD5");
    byte[] enStr = messageDigest.digest(str.getBytes());
    //将二进制转换为16进制输出
    System.out.println("JDK的MD5摘要："+Hex.encodeHex(enStr));
}
```
调用
```Java
public static void main(String[] args) throws NoSuchAlgorithmException {
    BCMD4(BASE_STRING);
    BCMD5(BASE_STRING);
    jdkMD2(BASE_STRING);
    jdkMD5(BASE_STRING);
}
```

结果
>B C的MD4摘要:28427b7d90e25002467da60396b79a94  
B C的MD5摘要:6ddee10117cee5ef77cae7e747385ee2  
JDK的MD2摘要:3cce751973fd1c6957b4d60bbf0d9153  
JDK的MD5摘要:6ddee10117cee5ef77cae7e747385ee2  


#### 4.SHA
一般的加密算法实现通过两个包实现  
JDK：java.security  
BC： Bouncy Castle    
CC一般是对JDK简化操作  

##### SHA-1
JDK实现
```Java
public static void jdkSHA1(String str) throws NoSuchAlgorithmException {
   MessageDigest messageDigest = MessageDigest.getInstance("SHA");
   byte[] enStr = messageDigest.digest(str.getBytes());
   //将二进制转换为16进制输出
   System.out.println("JDK的SHA摘要:"+new String(Hex.encodeHex(enStr)));
}
```
BC实现
```Java
public static void BCSHA1(String str) throws NoSuchAlgorithmException {
      Digest digest = new SHA1Digest();
      byte[] b = str.getBytes();
      digest.update(b,0,b.length);
      byte[] enStr = new byte[digest.getDigestSize()];
      digest.doFinal(enStr,0);
      //将二进制转换为16禁止输出
      System.out.println("B C的SHA1摘要:"+new String(org.bouncycastle.util.encoders.Hex.toHexString(enStr)));
  }
```
CC实现
```java
public static void CCSHA1(String str){
    String enStr = DigestUtils.sha1Hex(BASE_STRING.getBytes());
    System.out.println("C C的SHA1摘要:"+enStr);

}
```


##### SHA224
BC单独实现
```Java
public static void BCSHA224(String str) throws NoSuchAlgorithmException {
    Digest digest = new SHA224Digest();
    byte[] b = str.getBytes();
    digest.update(b,0,b.length);
    byte[] enStr = new byte[digest.getDigestSize()];
    digest.doFinal(enStr,0);
    //将二进制转换为16禁止输出
    System.out.println("B C的SHA224摘要:"+new String(org.bouncycastle.util.encoders.Hex.toHexString(enStr)));
}
```

JDK实现与BC配合实现
```Java
public static void jdkAndBCSHA224(String str) throws NoSuchAlgorithmException {
    Security.addProvider(new BouncyCastleProvider());
    MessageDigest messageDigest = MessageDigest.getInstance("SHA224");
    byte[] enStr = messageDigest.digest(str.getBytes());
    //将二进制转换为16禁止输出
    System.out.println("JDK+BC的SHA224摘要:"+new String(Hex.encodeHex(enStr)));
}
```

调用
```Java
public static void main(String[] args) throws NoSuchAlgorithmException {
    jdkSHA1(BASE_STRING);
    BCSHA1(BASE_STRING);
    CCSHA1(BASE_STRING);
    BCSHA224(BASE_STRING);
    jdkAndBCSHA224(BASE_STRING);
}
```


结果  
>JDK的SHA1摘要:4a6db077ec2ea85697bfe5e97feffed7616dda96  
B C的SHA1摘要:4a6db077ec2ea85697bfe5e97feffed7616dda96  
C C的SHA1摘要:4a6db077ec2ea85697bfe5e97feffed7616dda96
B C的SHA224摘要   :f86ded290c11f45253ba0a47c30a23ab7121721e76f8dc071aee98cc  
JDK+BC的SHA224摘要:f86ded290c11f45253ba0a47c30a23ab7121721e76f8dc071aee98cc  

#### MAC 加秘钥的摘要算法
JDK实现
```Java
public static void jdkHmacMD5(String str) throws Exception {
    //初始化 KeyGenerator
    KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacMD5");
    //生成秘钥
    SecretKey secretKey = keyGenerator.generateKey();
    //获取秘钥
    byte[] key = secretKey.getEncoded();

    //还原秘钥
    SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacMD5");
    //获取mac实例 初始化MAC
    Mac mac = Mac.getInstance(secretKeySpec.getAlgorithm());
    mac.init(secretKey);
    //执行摘要算法
    byte[] encBytes = mac.doFinal(str.getBytes());
    System.out.println(Hex.toHexString(encBytes));
}

```
BC实现
```Java
public static void BCHmacMD5(String str){

    HMac hMac = new HMac(new MD5Digest());
    hMac.init(new KeyParameter(Hex.decode("aaaaaaaaaa")));
    hMac.update(str.getBytes(),0,str.getBytes().length);
    byte[] hmacMD5 = new byte[hMac.getMacSize()];
    hMac.doFinal(hmacMD5,0);
    System.out.println(Hex.toHexString(hmacMD5));

}

```
## 3.对称加密算法(Symmetric-key algorithm)

### 对称加密算法(Symmetric-key algorithm)简介
>**对称加密算法是应用较早的加密算法，技术成熟。在对称加密算法中，数据发信方将明文（原始数据）和加密密钥一起经过特殊加密算法处理后，使其变成复杂的加密密文发送出去。收信方收到密文后，若想解读原文，则需要使用加密用过的密钥及相同算法的逆算法对密文进行解密，才能使其恢复成可读明文。在对称加密算法中，使用的密钥只有一个，发收信双方都使用这个密钥对数据进行加密和解密，这就要求解密方事先必须知道加密密钥。**

对称加密(也叫私钥加密)指加密和解密使用相同密钥的加密算法。有时又叫传统密码算法，就是加密密钥能够从解密密钥中推算出来，同时解密密钥也可以从加密密钥中推算出来。而在大多数的对称算法中，加密密钥和解密密钥是相同的，所以也称这种加密算法为秘密密钥算法或单密钥算法。它要求发送方和接收方在安全通信之前，商定一个密钥。对称算法的安全性依赖于密钥，泄漏密钥就意味着任何人都可以对他们发送或接收的消息解密，所以密钥的保密性对通信的安全性至关重要。

>**特点：解密加密使用相同秘钥，计算量小，算法简单，加密效率高**


### 对称加密算法实现

#### DES加密 （不安全）
Jdk实现DES
```Java
public static void jdkDES(String str) throws Exception {
     //系统自动生成key
     byte[] key = KeyGenerator.getInstance("DES").generateKey().getEncoded();

     //转换秘钥
     DESKeySpec desKeySpec = new DESKeySpec(key);
     SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
     Key convertSecretKey = secretKeyFactory.generateSecret(desKeySpec);

     //加密
     //加密模式 DES
     Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
     //初始化加密工具
     cipher.init(Cipher.ENCRYPT_MODE,convertSecretKey);
     byte[] enBytes = cipher.doFinal(str.getBytes());
     //展示
     System.out.println("Jdk DES Encrypt:"+ Hex.toHexString(enBytes));

     //解密
     cipher.init(Cipher.DECRYPT_MODE,convertSecretKey);
     byte[] deBytes = cipher.doFinal(enBytes);
     System.out.println("Jdk DES Decrypt:"+new String(deBytes));

 }
```
BC实现DES

```Java
public static void BCDES(String str) throws Exception {
        //向JDK中添加算法
        Security.addProvider(new BouncyCastleProvider());
        //系统自动生成key
        byte[] key = KeyGenerator.getInstance("DES").generateKey().getEncoded();

        //转换秘钥
        DESKeySpec desKeySpec = new DESKeySpec(key);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        Key convertSecretKey = secretKeyFactory.generateSecret(desKeySpec);

        //加密
        //加密模式 DES
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        //初始化加密工具
        cipher.init(Cipher.ENCRYPT_MODE,convertSecretKey);
        byte[] enBytes = cipher.doFinal(str.getBytes());
        //展示
        System.out.println("Jdk DES Encrypt:"+ Hex.toHexString(enBytes));

        //解密
        cipher.init(Cipher.DECRYPT_MODE,convertSecretKey);
        byte[] deBytes = cipher.doFinal(enBytes);
        System.out.println("Jdk DES Decrypt:"+new String(deBytes));

    }
```

#### TripleDES（三重DES）
JDK实现
```Java
public static void  jdkTripleDES(String str) throws Exception{
     //系统自动生成key
     KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
     //依据算法自定义Key长度 init(168);
     keyGenerator.init(new SecureRandom());
     byte[] key = keyGenerator.generateKey().getEncoded();

     //转换秘钥
     DESedeKeySpec desKeySpec = new DESedeKeySpec(key);
     SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DESede");
     Key convertSecretKey = secretKeyFactory.generateSecret(desKeySpec);

     //加密
     //加密模式 DES
     Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
     //初始化加密工具
     cipher.init(Cipher.ENCRYPT_MODE,convertSecretKey);
     byte[] enBytes = cipher.doFinal(str.getBytes());
     //展示
     System.out.println("Jdk TripleDES Encrypt:"+ Hex.toHexString(enBytes));

     //解密
     cipher.init(Cipher.DECRYPT_MODE,convertSecretKey);
     byte[] deBytes = cipher.doFinal(enBytes);
     System.out.println("Jdk TripleDES Decrypt:"+new String(deBytes));
 }
```

BC+JDK实现
```Java
public static void  BCTripleDES(String str) throws Exception{
    Security.addProvider(new BouncyCastleProvider());
    //系统自动生成key
    KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
    //依据算法自定义Key长度 init(168);
    keyGenerator.init(new SecureRandom());
    byte[] key = keyGenerator.generateKey().getEncoded();

    //转换秘钥
    DESedeKeySpec desKeySpec = new DESedeKeySpec(key);
    SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DESede");
    Key convertSecretKey = secretKeyFactory.generateSecret(desKeySpec);

    //加密
    //加密模式 DES
    Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
    //初始化加密工具
    cipher.init(Cipher.ENCRYPT_MODE,convertSecretKey);
    byte[] enBytes = cipher.doFinal(str.getBytes());
    //展示
    System.out.println("BC+Jdk TripleDES Encrypt:"+ Hex.toHexString(enBytes));

    //解密
    cipher.init(Cipher.DECRYPT_MODE,convertSecretKey);
    byte[] deBytes = cipher.doFinal(enBytes);
    System.out.println("BC+Jdk TripleDES Decrypt:"+new String(deBytes));
}
```

#### AES加密
AES加密及其解密需要的参数
![java集合](.\img\AES.png)
AES加密流程
![java集合](.\img\AES加密流程.png)

```Java
public static void jdkAES(String str) throws Exception {
    //系统自动生成key
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    keyGenerator.init(128);
    byte[] key = keyGenerator.generateKey().getEncoded();

    //转换秘钥
    Key convertSecretKey = new SecretKeySpec(key, "AES");

    //加密
    //加密模式 DES
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    //初始化加密工具
    cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
    byte[] enBytes = cipher.doFinal(str.getBytes());
    //展示
    System.out.println("Jdk DES Encrypt:" + Hex.toHexString(enBytes));

    //解密
    cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
    byte[] deBytes = cipher.doFinal(enBytes);
    System.out.println("Jdk DES Decrypt:" + new String(deBytes));
}

```
BC+JDK实现类似于DES的方式

#### PBE(Password Based Encryption)加密
>**PBE（Password Based Encryption，基于口令加密）是一种基于口令的加密算法，其特点是使用口令代替了密钥，而口令由用户自己掌管，采用随机数杂凑多重加密等方法保证数据的安全性。PBE算法在加密过程中并不是直接使用口令来加密，而是加密的密钥由口令生成，这个功能由PBE算法中的KDF函数完成。KDF函数的实现过程为：将用户输入的口令首先通过“盐”（salt）的扰乱产生准密钥，再将准密钥经过散列函数多次迭代后生成最终加密密钥，密钥生成后，PBE算法再选用对称加密算法对数据进行加密，可以选择DES、3DES、RC5等对称加密算法。**

常用加密方式
![PBE](.\img\PBE.png)
加密流程
![PBE加密流程](.\img\PBE加密流程.png)
加

JDK实现
```Java
/**
 * 基于口令的对称加密算法PBE
 */
public class PBE {

    private static final String BASE_STRING ="security PBETest";

    private static final String BASE_PWD="security Pwd";

    public static void main(String[] args) throws Exception {
        jdkPBE(BASE_STRING);

    }

    public static void jdkPBE(String str) throws Exception {
        //初始化盐
        SecureRandom random = new SecureRandom();
        byte[] salt = random.generateSeed(8);

        //口令于秘钥
        PBEKeySpec pbeKeySpec = new PBEKeySpec(BASE_PWD.toCharArray());
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWITHMD5andDES");
        Key key = factory.generateSecret(pbeKeySpec);

        //加密
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt,100);
        Cipher cipher = Cipher.getInstance("PBEWITHMD5andDES");
        cipher.init(Cipher.ENCRYPT_MODE,key,pbeParameterSpec);
        byte[] enBytes = cipher.doFinal(str.getBytes());
        System.out.println("JDK PBE 加密："+ Base64.encodeBase64String(enBytes));

        cipher.init(Cipher.DECRYPT_MODE,key,pbeParameterSpec);
        byte[] deBytes = cipher.doFinal(enBytes);
        System.out.println("JDK PBE 解密："+new String(deBytes));
    }
}

```
其他实现方式只需修改加密方式


## 4.非对称加密算法

### 非对称加密算法简介
>**非对称加密算法需要两个密钥：公开密钥（publickey）和私有密钥（privatekey）。公开密钥与私有密钥是一对，如果用公开密钥对数据进行加密，只有用对应的私有密钥才能解密；如果用私有密钥对数据进行加密，那么只有用对应的公开密钥才能解密。因为加密和解密使用的是两个不同的密钥，所以这种算法叫作非对称加密算法。 非对称加密算法实现机密信息交换的基本过程是：甲方生成一对密钥并将其中的一把作为公用密钥向其它方公开；得到该公用密钥的乙方使用该密钥对机密信息进行加密后再发送给甲方；甲方再用自己保存的另一把专用密钥对加密后的信息进行解密。**

另一方面，甲方可以使用乙方的公钥对机密信息进行签名后再发送给乙方；乙方再用自己的私匙对数据进行验签。  
甲方只能用其专用密钥解密由其公用密钥加密后的任何信息。 非对称加密算法的保密性比较好，它消除了最终用户交换密钥的需要。  
非对称密码体制的特点：算法强度复杂、安全性依赖于算法与密钥但是由于其算法复杂，而使得加密解密速度没有对称加密解密的速度快。对称密码体制中只有一种密钥，并且是非公开的，如果要解密就得让对方知道密钥。所以保证其安全性就是保证密钥的安全，而非对称密钥体制有两种密钥，其中一个是公开的，这样就可以不需要像对称密码那样传输对方的密钥了。这样安全性就大了很多。

>**特点：加密等级高，传输安全**

### 非对称加密算法实现

#### DH秘钥交换算法
解决对称加密传输安全的问题、构建本地秘钥。

| 秘钥长度    | 默认   |工作模式|填充方式|实现方|
| :-------: | :----: | :----: | :----: | :----: |
| 512~1024位 | 1024位 |   无  |无       |JDK    |

###### 流程
![DH](.\img\DH.png)
1.发送方构建公钥私钥。
2.发送方发布发送方公钥。
3.接收方接收发送方公钥构建接收方公钥私钥。
4.接收方发布接收方公钥。
5.发送方通过发送方的私钥和接收方的公钥构建对称加密秘钥用于加密。
6.接收方通过接收方的私钥和发送方的公钥构建对称加密秘钥用于解密。
7.发送方通过秘钥加密数据并发送。
8.接收方接收数据并通过秘钥解密数据。

1.初始化发送方秘钥  
- KeyPairGenerator 生成Keypair
- KeyPair 秘钥对（公钥 私钥）
- Publickey 公钥

2.初始化接收方秘钥
- KeyFactory 生成秘钥
- X509EncodedKeySpec 根据ASN.1进行编码 按照某种规范生成秘钥
- DHPublicKey DH公钥
- DHParameterSpec DH参数集合
- KeyGenerator
- PricateKey 私钥

3.秘钥构建
- KeyAgreement 秘钥提供协议
- SecretKey 秘密秘钥对称秘钥 生成分组秘密秘钥
- KeyFactory
- X509EncodedKeySpec
- Publickey

4.加密、解密
- Cipher 加密解密提供密码功能 JCE核心


```Java
//流程实现
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
    //6.接收方构建对称加密秘钥->依据发送方公钥和接收方公钥私钥构建
    SecretKey receiverDesKey = jdkGetSecretKey(receiverKeyPair,senderPublicKeyEncode);
    //对比双方对称加密秘钥是否安相同 查看是否测试成功
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
```


#### RSA因子分解算法
唯一广泛接受的实现类型  
数字加密&数字签名  
公钥加密 私钥解密  
私钥加密 公钥解密  

工作实现以及填充模式
![RSA](.\img\RSA.png)

加解密流程
![RSA](.\img\RSA加解密流程.png)

```Java
package asymmetrickeyencryption;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 大数因子分解 64的整数倍
 */
public class RSA {

    private static final String BASE_STRING = "security DHTest";

    public static void main(String[] args) throws Exception {
        jdkRSA();

    }

    public static void jdkRSA() throws Exception {
        //1.初始化秘钥
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(512);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        System.out.println("RSAPublicKey:" + Base64.encodeBase64String(rsaPublicKey.getEncoded()));
        System.out.println("RSAPrivateKey:" + Base64.encodeBase64String(rsaPrivateKey.getEncoded()));

        //2.私钥加密
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] result = cipher.doFinal(BASE_STRING.getBytes());
        System.out.println("JDK RSA 私钥加密:" + Base64.encodeBase64String(result));
        //公钥解密
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
        KeyFactory keyFactory1 = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        Cipher cipher1 = Cipher.getInstance("RSA");
        cipher1.init(Cipher.DECRYPT_MODE, publicKey);
        result = cipher1.doFinal(result);
        System.out.println("JDK RSA 公钥解密:" + new String(result));


        //3 公钥加密
        x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
        keyFactory = KeyFactory.getInstance("RSA");
        publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        result = cipher.doFinal(BASE_STRING.getBytes());
        System.out.println("JDK RSA 公钥加密：" + Base64.encodeBase64String(result));

        //私钥解密
        pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
        keyFactory = KeyFactory.getInstance("RSA");
        privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        result = cipher.doFinal(result);
        System.out.println("JDK RSA 私钥解密：" + new String(result));


    }

}
```
#### ELGamal离散对数加密算法
工作实现以及填充模式
![RSA](.\img\ElGamal.png)

加解密流程
![RSA](.\img\ElGamal流程.png)

秘钥的构建
```java
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
```
加密解密方式与RSA相同


## 数字签名
>**数字签名（又称公钥数字签名、电子签章）是一种类似写在纸上的普通的物理签名，但是使用了公钥加密领域的技术实现，用于鉴别数字信息的方法。一套数字签名通常定义两种互补的运算，一个用于签名，另一个用于验证。
数字签名，就是只有信息的发送者才能产生的别人无法伪造的一段数字串，这段数字串同时也是对信息的发送者发送信息真实性的一个有效证明。
数字签名是非对称密钥加密技术与数字摘要技术的应用。**

> 特点： 数据完整性验证、认证数据来源、抗否认等

### RSA算法
加解密流程
![RSA](.\img\RSA-数字签名.png)

仅仅实现签名 验签
```java
public static void jdkRSA() throws  Exception{
   //初始化秘钥
   KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
   keyPairGenerator.initialize(512);
   KeyPair keyPair =keyPairGenerator.generateKeyPair();
   RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
   RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();

   //执行签名
   //用私钥签名
   PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
   KeyFactory keyFactory = KeyFactory.getInstance("RSA");
   PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
   Signature signature = Signature.getInstance("MD5withRSA");
   signature.initSign(privateKey);
   signature.update(BASE_STRING.getBytes());
   byte[] result = signature.sign();
   System.out.println("JDK RSA 签名："+ Hex.toHexString(result));


   //用公钥验签
   X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
   keyFactory = KeyFactory.getInstance("RSA");
   PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
   signature = Signature.getInstance("MD5withRSA");
   signature.initVerify(publicKey);
   signature.update(BASE_STRING.getBytes());
   boolean res = signature.verify(result);
   System.out.println("JDK RSA 验签："+res);
}

```
### DSA算法
DSA 算法和RSA算法完全相似

```java
public static void DSA() throws Exception{
    //创建秘钥
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
    keyPairGenerator.initialize(512);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    DSAPublicKey dsaPublicKey = (DSAPublicKey) keyPair.getPublic();
    DSAPrivateKey dsaPrivateKey = (DSAPrivateKey) keyPair.getPrivate();

    //签名
    PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(dsaPrivateKey.getEncoded());
    KeyFactory keyFactory = KeyFactory.getInstance("DSA");
    PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    Signature signature = Signature.getInstance("SHA1withDSA");
    signature.initSign(privateKey);
    signature.update(BASE_STRING.getBytes());
    byte[] result = signature.sign();
    System.out.println("JDK DSA 签名："+ Base64.encodeBase64String(result));

    //验签
    X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(dsaPublicKey.getEncoded());
    keyFactory = KeyFactory.getInstance("DSA");
    PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
    signature = Signature.getInstance("SHA1withDSA");
    signature.initVerify(publicKey);
    signature.update(BASE_STRING.getBytes());
    boolean res = signature.verify(result);
    System.out.println("JDK DSA 验签是否通过："+res);
}
```
### ECDSA算法（椭圆曲线数字签名算法）
速度快、强度高、签名短的特点；
序列号验证算法
加解密流程
![ECDSA](.\img\ECDSA.png)

```java

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

```


### 加密技术的应用--数字签名RSA版本
三方支付系统签名验证流程

甲方传输一段报文给乙方

甲方发送操作：
1. 甲方 组织报文
2. 使用甲方私钥签名报文（摘要算法）
3. 将报文和签名合并
4. 使用乙方公钥将合并后的数据加密（非对称加密）
5. 传输到乙方  

乙方接收操作：  
1. 使用乙方私钥将加密数据打开 （非对称加密）
2. 分开报文和签名
3. 使用甲方公钥重新签名报文（摘要算法）
4. 验证乙方签名后的报文和甲方传输的报文是否一样
5. 如果一样接收数据成功


