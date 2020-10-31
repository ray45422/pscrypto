Add-Type -TypeDefinition @'
using System;
using System.Numerics;
using System.Collections.Generic;
public class KeyInfo
{
    public DateTime CreationTime { get; }
    public int Algorithm { get; }
    public string AlgorithmName { get; }
    public string FingerPrint { get; }
    public string KeyID { get; }
    public PublicKey Key { get; }
    public KeyInfo(string fingerPrint, int algorithm, string algorithmName, DateTime creationTime, bool isSecret, Dictionary<string, byte[]> dict)
    {
        this.CreationTime = creationTime;
        this.Algorithm = algorithm;
        this.AlgorithmName = algorithmName;
        this.FingerPrint = fingerPrint;
        this.KeyID = fingerPrint.Substring(fingerPrint.Length - 8, 8);
        this.Key = PublicKey.CreateInstance(algorithm, isSecret, dict);
    }
}
public abstract class PublicKey
{
    public static PublicKey CreateInstance(int algorithm, bool isSecret, Dictionary<string, byte[]> dict)
    {
        switch(algorithm)
        {
            case 1:
                if(isSecret)
                {
                    return new RSAKey(
                        (byte[])dict["PublicKey"],
                        (byte[])dict["Exponent"],
                        (byte[])dict["PrivateKey"],
                        (byte[])dict["Prime1"],
                        (byte[])dict["Prime2"],
                        (byte[])dict["U"]
                        );
                }
                return new RSAKey((byte[])dict["PublicKey"], (byte[])dict["Exponent"]);
        }
        return new NotImplementedPublicKey();
    }
    abstract public byte[] Encrypt(byte[] n);
    abstract public byte[] Decrypt(byte[] n);
    abstract public byte[] Sign(byte[] n);
    abstract public byte[] Verify(byte[] n);
}
public class NotImplementedPublicKey : PublicKey
{
    override public byte[] Encrypt(byte[] n)
    {
        return null;
    }
    override public byte[] Decrypt(byte[] n)
    {
        return null;
    }
    override public byte[] Sign(byte[] n)
    {
        return null;
    }
    override public byte[] Verify(byte[] n)
    {
        return null;
    }
}
public class RSAKey : PublicKey
{
    bool hasPrivateKey;
    ulong bit = 0;
    BigInteger n = BigInteger.Zero;
    BigInteger e = BigInteger.Zero;
    BigInteger p = BigInteger.Zero;
    BigInteger q = BigInteger.Zero;
    BigInteger d = BigInteger.Zero;
    BigInteger u = BigInteger.Zero;
    public bool HasPrivateKey
    {
        get { return this.hasPrivateKey; }
    }
    public ulong Bit
    {
        get { return this.bit; }
    }
    public BigInteger PublicKey
    {
        get { return this.n; }
    }
    public BigInteger Exponent
    {
        get { return this.e; }
    }
    public BigInteger PrivateKey
    {
        get { return this.d; }
    }
    private static BigInteger BytesToBigInteger(byte[] n)
    {
        var tmp = new byte[n.Length + 1];
        Array.Copy(n, 0, tmp, 1, n.Length);
        Array.Reverse(tmp);
        return new BigInteger(tmp);
    }
    private static byte[] Padding(byte[] orig, byte[] target)
    {
        var diff = orig.Length - target.Length;
        if(diff <= 0)
        {
            return target;
        }
        var tmp = new byte[orig.Length];
        Array.Copy(target, 0, tmp, diff, target.Length);
        return tmp;
    }
    public RSAKey(byte[] n, byte[] e)
        : this(BytesToBigInteger(n), BytesToBigInteger(e))
    {
    }
    public RSAKey(BigInteger n, BigInteger e)
    {
        this.hasPrivateKey = false;
        this.bit = (ulong)(n.ToByteArray().LongLength * 8);
        this.n = n;
        this.e = e;
    }
    public RSAKey(byte[] n, byte[] e, byte[] d, byte[] p, byte[] q, byte[] u)
        : this(BytesToBigInteger(n), BytesToBigInteger(e), BytesToBigInteger(d), BytesToBigInteger(p), BytesToBigInteger(q), BytesToBigInteger(u))
    {
    }
    public RSAKey(BigInteger n, BigInteger e, BigInteger d, BigInteger p, BigInteger q, BigInteger u)
    {
        this.hasPrivateKey = true;
        this.bit = (ulong)(d.ToByteArray().LongLength * 8);
        this.n = n;
        this.e = e;
        this.d = d;
        this.p = p;
        this.q = q;
        this.u = u;
    }
    public RSAKey(byte[] e, byte[] p, byte[] q)
        : this(BytesToBigInteger(e), BytesToBigInteger(p), BytesToBigInteger(q))
    {
    }
    public RSAKey(BigInteger e, BigInteger p, BigInteger q)
    {
        if(e != BigInteger.Zero)
        {
            throw new Exception("not work");
        }
        this.e = e;
        this.p = p;
        this.q = q;
        this.n = p * q;
        var o = (this.p - BigInteger.One) * (this.q - BigInteger.One);
        this.d = ModInv(this.e, o);
        this.bit = (ulong)(this.d.ToByteArray().LongLength * 8);
    }
    private BigInteger[] Egcd(BigInteger a, BigInteger b)
    {
        if(b == BigInteger.Zero)
        {
            return new BigInteger[] {a, BigInteger.One, BigInteger.Zero};
        }
        var v = Egcd(b, a % b);
        var d = v[0];
        var x = v[2];
        var y = v[1];
        y -= a / b * x;
        v[0] = d;
        v[1] = x;
        v[2] = y;
        return v;
    }
    private BigInteger ModInv(BigInteger a, BigInteger n)
    {
        var v = Egcd(a, n);
        if(v[0] != BigInteger.One)
        {
            throw new Exception("Moduler inverse does not exist");
        }
        var x = v[1];
        if(x < BigInteger.Zero)
        {
            x += n;
        }
        return x;
    }
    public override byte[] Encrypt(byte[] n)
    {
        var result = Encrypt(BytesToBigInteger(n)).ToByteArray(true, true);
        return Padding(n, result);
    }
    public BigInteger Encrypt(BigInteger n)
    {
        return BigInteger.ModPow(n, this.e, this.n);
    }
    public override byte[] Decrypt(byte[] n)
    {
        if(!hasPrivateKey)
        {
            throw new InvalidOperationException("No Secretkey");
        }
        var result = Decrypt(BytesToBigInteger(n)).ToByteArray(true, true);
        return Padding(n, result);
    }
    public BigInteger Decrypt(BigInteger n)
    {
        if(!hasPrivateKey)
        {
            throw new InvalidOperationException("No Secretkey");
        }
        return BigInteger.ModPow(n, this.d, this.n);
    }
    public override byte[] Sign(byte[] n)
    {
        if(!hasPrivateKey)
        {
            throw new InvalidOperationException("No Secretkey");
        }
        return Decrypt(n);
    }
    public BigInteger Sign(BigInteger n)
    {
        if(!hasPrivateKey)
        {
            throw new InvalidOperationException("No Secretkey");
        }
        return Decrypt(n);
    }
    public override byte[] Verify(byte[] n)
    {
        return Encrypt(n);
    }
    public BigInteger Verify(BigInteger n)
    {
        return Encrypt(n);
    }
}
'@
