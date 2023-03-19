# Honoo.BouncyCastle.Helpers

<!-- @import "[TOC]" {cmd="toc" depthFrom=1 depthTo=6 orderedList=false} -->

<!-- code_chunk_output -->

- [Honoo.BouncyCastle.Helpers](#honoobouncycastlehelpers)
  - [INTRODUCTION](#introduction)
  - [USAGE](#usage)
    - [NuGet](#nuget)
    - [Namespace](#namespace)
    - [Hash](#hash)
    - [HMAC](#hmac)
    - [CMAC](#cmac)
    - [MAC](#mac)
    - [Symmetric encryption](#symmetric-encryption)
    - [Asymmetric encryption](#asymmetric-encryption)
    - [Signature](#signature)
    - [Certificate](#certificate)
    - [ECDH](#ecdh)
  - [BUG](#bug)
  - [LICENSE](#license)

<!-- /code_chunk_output -->

## INTRODUCTION

BouncyCastle's helpers. Refactoring by System.Security.Cryptography code styles.

## USAGE

### NuGet

<https://www.nuget.org/packages/Honoo.BouncyCastle/>

### Namespace

```c#

using Honoo.BouncyCastle;

```

### Hash

```c#

private static void Demo1()
{
    SHA1 sha1 = new SHA1();
    _ = sha1.ComputeHash(_input);
}

```

### HMAC

```c#

private static void Demo2()
{

}

```

### CMAC

```c#

private static void Demo3()
{

}

```

### MAC

```c#

private static void Demo4()
{

}

```

### Symmetric encryption

```c#

private static void Demo1()
{
    AES alg1 = new AES { Mode = SymmetricCipherMode.CTR, Padding = SymmetricPaddingMode.TBC };
    AES alg2 = new AES { Mode = SymmetricCipherMode.CTR, Padding = SymmetricPaddingMode.TBC };
    byte[] key = new byte[16];
    byte[] iv = new byte[16];
    Common.SecureRandom.NextBytes(key);
    Common.SecureRandom.NextBytes(iv);
    alg1.GenerateParameters(key, iv);
    alg2.GenerateParameters(key, iv);
    byte[] enc = alg1.EncryptFinal(_input);
    byte[] dec = alg2.DecryptFinal(enc);
}

private static void Demo2()
{
    AES alg1 = new AES { Mode = SymmetricCipherMode.EAX, Padding = SymmetricPaddingMode.NoPadding };
    AES alg2 = new AES { Mode = SymmetricCipherMode.EAX, Padding = SymmetricPaddingMode.NoPadding };
    byte[] key = new byte[16];
    byte[] nonce = new byte[22];
    Common.SecureRandom.NextBytes(key);
    Common.SecureRandom.NextBytes(nonce);
    alg1.GenerateParameters(key, nonce, 64, new byte[] { 0x01, 0x02, 0x03 });
    alg2.GenerateParameters(key, nonce, 64, new byte[] { 0x01, 0x02, 0x03 });
    byte[] enc = alg1.EncryptFinal(_input);
    byte[] dec = alg2.DecryptFinal(enc);
}

private static void Demo3()
{
    H128 alg1 = new H128();
    H128 alg2 = new H128();
    byte[] key = new byte[16];
    byte[] iv = new byte[16];
    Common.SecureRandom.NextBytes(key);
    Common.SecureRandom.NextBytes(iv);
    alg1.GenerateParameters(key, iv);
    alg2.GenerateParameters(key, iv);
    byte[] enc = alg1.EncryptFinal(_input);
    byte[] dec = alg2.DecryptFinal(enc);
}

```

### Asymmetric encryption

```c#

private static void Demo1()
{
    RSA rsa1 = new RSA { Padding = AsymmetricPaddingMode.ISO9796_1 };
    rsa1.GenerateKeyPair(512);
    string pem = rsa1.ExportPem(false);

    RSA rsa2 = new RSA { Padding = AsymmetricPaddingMode.ISO9796_1 };
    rsa2.ImportPem(pem);

    byte[] enc = rsa2.Encrypt(_input);
    _ = rsa1.Decrypt(enc);
}

```

### Signature

```c#

private static void Demo1()
{
    RSA rsa1 = new RSA()
    {
        SignaturePadding = RSASignaturePaddingMode.PKCS1,
        HashAlgorithm = HashAlgorithmName.SHA384
    };
    RSA rsa2 = new RSA()
    {
        SignaturePadding = RSASignaturePaddingMode.PKCS1,
        HashAlgorithm = HashAlgorithmName.SHA384
    };
    var pem = rsa1.ExportPem(false);
    rsa2.ImportPem(pem);
    byte[] signature = rsa1.SignFinal(_input);
    _ = rsa2.VerifyFinal(_input, signature);
}

```

### Certificate

```c#

private static void Demo()
{
    string caSignatureAlgorithmName = "SHA512withECDSA";
    string userSignatureAlgorithmName = "SHA256withECDSA";
    //
    // CA build self.
    //
    _ = SignatureAlgorithmHelper.TryGetAlgorithm(caSignatureAlgorithmName, out ISignatureAlgorithm caSignatureAlgorithm);
    AsymmetricCipherKeyPair caKeyPair = caSignatureAlgorithm.AsymmetricAlgorithm.GenerateKeyPair();
    //
    X509NameEntity[] caDN = new X509NameEntity[]
    {
        new X509NameEntity(X509NameLabel.C,"CN"),
        new X509NameEntity(X509NameLabel.CN,"TEST Root CA")
    };
    X509ExtensionEntity[] caExtensions = new X509ExtensionEntity[]
    {
        new X509ExtensionEntity(X509ExtensionLabel.BasicConstraints, true, new BasicConstraints(false)),
        new X509ExtensionEntity(X509ExtensionLabel.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign))
    };
    X509Certificate caCert = X509Helper.GenerateIssuerCertificate(caSignatureAlgorithm,
                                                                    caKeyPair,
                                                                    caDN,
                                                                    caExtensions,
                                                                    DateTime.UtcNow.AddDays(-3),
                                                                    DateTime.UtcNow.AddDays(120));
    X509RevocationEntity[] revocationEntities = new X509RevocationEntity[]
    {
        new X509RevocationEntity(new BigInteger("12345678901"), DateTime.UtcNow.AddDays(-2), null),
        new X509RevocationEntity(new BigInteger("12345678902"), DateTime.UtcNow.AddDays(-2), null)
    };

    X509Crl caCrl = X509Helper.GenerateCrl(caSignatureAlgorithm,
                                            caKeyPair.Private,
                                            caCert,
                                            revocationEntities,
                                            null,
                                            DateTime.UtcNow.AddDays(-2),
                                            DateTime.UtcNow.AddDays(30));
    //
    // User create csr and sand to CA.
    //
    AsymmetricCipherKeyPair userKeyPair = SignatureAlgorithms.GOST3411withECGOST3410.AsymmetricAlgorithm.GenerateKeyPair();
    X509NameEntity[] userDN = new X509NameEntity[]
    {
        new X509NameEntity(X509NameLabel.C,"CN"),
        new X509NameEntity(X509NameLabel.CN,"TEST User")
    };
    X509ExtensionEntity[] userExtensions = null;
    Pkcs10CertificationRequest userCsr = X509Helper.GenerateCsr(SignatureAlgorithms.GOST3411withECGOST3410, userKeyPair, userDN, userExtensions);
    //
    // CA extract csr and create user cert.
    //
    X509Helper.ExtractCsr(userCsr,
                            out AsymmetricKeyParameter userPublicKey,
                            out IList<X509NameEntity> userDNExtracted,
                            out IList<X509ExtensionEntity> userExtensionsExtracted);
    X509Certificate userCert = X509Helper.GenerateSubjectCertificate(userSignatureAlgorithmName,
                                                                        caKeyPair.Private,
                                                                        caCert,
                                                                        userPublicKey,
                                                                        userDNExtracted,
                                                                        userExtensionsExtracted,
                                                                        DateTime.UtcNow.AddDays(-1),
                                                                        DateTime.UtcNow.AddDays(90));
    //
    //
    // Print
    //
    Console.WriteLine("====  CA Cert  ===========================");
    Console.WriteLine(caCert.ToString());
    Console.WriteLine("====  CA Crl  ============================");
    Console.WriteLine(caCrl.ToString());
    Console.WriteLine("====  User Cert  =========================");
    Console.WriteLine(userCert.ToString());
    Console.WriteLine();
    //
    // User verify cert.
    //
    bool validated;
    try
    {
        caCrl.Verify(caCert.GetPublicKey());
        userCert.Verify(caCert.GetPublicKey());
        validated = true;
    }
    catch
    {
        validated = false;
    }
    Console.WriteLine("Verify user cert - " + validated);
}

```

### ECDH

```c#

private static void Demo1()
{
    IECDHAlice ecdhA = new ECDH().GetAliceInterface();
    IECDHBob ecdhB = new ECDH().GetBobInterface();

    // Alice work
    ecdhA.GenerateParameters(384);
    byte[] p = ecdhA.P;
    byte[] g = ecdhA.G;
    byte[] materialAlice = ecdhA.MaterialAlice;

    // Bob work
    ecdhB.GenerateParameters(p, g, materialAlice);
    byte[] pmsBob = ecdhB.DeriveKeyMaterial(true);
    byte[] materialBob = ecdhB.MaterialBob;

    // Alice work
    byte[] pmsAlice = ecdhA.DeriveKeyMaterial(materialBob, true);

    //
    bool same = pmsAlice.SequenceEqual(pmsBob);
    Console.WriteLine($"ECDH {same}");
    Console.WriteLine(BitConverter.ToString(pmsAlice).Replace("-", ""));
    Console.WriteLine(BitConverter.ToString(pmsBob).Replace("-", ""));
}

```

## BUG

BouncyCastle 1.9.0 has not been fixed

1. RC5-32, RC5-64 does not support KeyParameter, only RC5Parameters. (feature?)
2. GCM cipher mode cannot be resue. The algorithm instance needs to be recreated every time.
3. OCB cipher mode supported null(0) Nonce/IV size but BouncyCastle cannot set that.
4. The signature algorithm SHA256withECDSA points to SHA224withECDSA at Org.BouncyCastle.Cms.DefaultSignatureAlgorithmIdentifierFinder.
5. SM2Signer does not reset the hash algorithm automatically. must be Reset() manually.

## LICENSE

This project based on MIT license.
