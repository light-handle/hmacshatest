package com.kaplan.hmacsha;

//signature = hmac-sha1( shared_secret, date + api_key )


import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Formatter;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HmacShaTest
{
    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
    private static String api_key = "thisapikey";
    private static String share_secret = "1234";

    private static String toHexString(byte[] bytes) {
        Formatter formatter = new Formatter();

        for (byte b : bytes) {
            formatter.format("%02x", b);
        }

        return formatter.toString();
    }

    public static String calculateRFC2104HMAC(String data, String key)
            throws SignatureException, NoSuchAlgorithmException, InvalidKeyException
    {
        SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);
        Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
        mac.init(signingKey);
        return toHexString(mac.doFinal(data.getBytes()));
    }

    public static void main( String[] args ) throws InterruptedException, NoSuchAlgorithmException, InvalidKeyException, SignatureException

    {
        long epoch;
        String epochString;
        String keyPlusEpoch;
        String hmac;

        for (int i=0; i<100; i++)
        {
            epoch = System.currentTimeMillis() / 1000L;
            System.out.println("Epoch long is: " + epoch);

            epochString = String.valueOf(epoch);
            System.out.println("Epoch is: " + epochString);

            keyPlusEpoch = epochString + api_key;
            System.out.println("KeyPlusEpoch is: " + keyPlusEpoch);

            hmac = calculateRFC2104HMAC(share_secret, keyPlusEpoch);
            System.out.println("Hmac signature is: " + hmac);
            System.out.println();

            Thread.sleep(1000);
        }
    }
}
