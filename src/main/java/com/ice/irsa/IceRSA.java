package com.ice.irsa;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created by Ice on 22-01-2017
 *
 */
public class IceRSA
{
    private BigInteger n, d, e;
    private int bitlen = 2048;

    public IceRSA(BigInteger newn, BigInteger newe) {
        n = newn;
        e = newe;
    }

    public IceRSA(int bits) {
        bitlen = bits;
        SecureRandom r = new SecureRandom();
        BigInteger p = new BigInteger(bitlen / 2, 100, r);
        BigInteger q = new BigInteger(bitlen / 2, 100, r);
        n = p.multiply(q);
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q
                .subtract(BigInteger.ONE));
        e = new BigInteger("3");
        while (m.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("2"));
        }
        d = e.modInverse(m);
    }

    public BigInteger quickPow(BigInteger x, BigInteger n)
    {
        if(n.compareTo(BigInteger.ZERO) == 0) return BigInteger.ONE;
        if(n.getLowestSetBit() == 0)
            return x.multiply(quickPow(x,n.subtract(BigInteger.ONE).divide(new BigInteger("2"))).pow(2));
        return quickPow(x, n.divide(new BigInteger("2"))).pow(2);
    }

    public synchronized String encrypt(String message) {
        return (new BigInteger(message.getBytes())).modPow(e, n).toString();
    }

    public synchronized BigInteger encrypt(BigInteger message) {
        return message.modPow(e, n);
    }

    public synchronized String decrypt(String message) {
        return new String((new BigInteger(message)).modPow(d, n).toByteArray());
    }

    public synchronized BigInteger decrypt(BigInteger message) {
        return message.modPow(d, n);
    }

    public String signMessage(String message)
    {
        return new String((new BigInteger(message)).modPow(d, n).toByteArray());
    }

    public BigInteger signMessage(BigInteger message)
    {
        return message.modPow(d, n);
    }

    public boolean checkSignature(BigInteger signature, BigInteger message)
    {
        return signature.modPow(e,n).compareTo(message) == 0;
    }

    public synchronized BigInteger getN() {
        return n;
    }

    public synchronized BigInteger getE() {
        return e;
    }

    public static void main(String[] args) {
        IceRSA rsa = new IceRSA(2048);

        String text1 = "Peace is a lie, there is only passion. Through passion, I gain strength.";
        System.out.println("Plaintext: " + text1);
        BigInteger plaintext = new BigInteger(text1.getBytes());

        BigInteger encrypted = rsa.encrypt(plaintext);
        System.out.println("Ciphertext: " + encrypted);
        BigInteger signature = rsa.signMessage(new BigInteger(text1.getBytes()));

        plaintext = rsa.decrypt(encrypted);
        String decrypted = new String(plaintext.toByteArray());
        System.out.println("Plaintext: " + decrypted);

        System.out.println("Signed: " + rsa.checkSignature(signature, new BigInteger(text1.getBytes())));

    }
}
