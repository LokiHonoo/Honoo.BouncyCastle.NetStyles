# Honoo.BouncyCastle.NetStyles

<!-- @import "[TOC]" {cmd="toc" depthFrom=1 depthTo=6 orderedList=false} -->

<!-- code_chunk_output -->

- [Honoo.BouncyCastle.NetStyles](#honoobouncycastlenetstyles)
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

<https://www.nuget.org/packages/Honoo.BouncyCastle.NetStyles/>

### Namespace

```c#

using Honoo.BouncyCastle.NetStyles;

```

### Hash

```c#

private static void Demo1()
{
    SHA1 sha1 = new SHA1();
    _ = sha1.ComputeFinal(_input);

    HashAlgorithm sha256 = HashAlgorithm.Create(HashAlgorithmName.SHA256);
    sha256.Update(_input);
    _ = sha256.ComputeFinal();
}

```

### HMAC

```c#

private static void Demo2()
{
    HMAC hmac1 = HMAC.Create(HMACName.HMAC_SM3);
    byte[] key = new byte[66]; // Any length.
    Buffer.BlockCopy(_keyExchangePms, 0, key, 0, key.Length);
    hmac1.ImportParameters(key);
    _ = hmac1.ComputeHash(_input);
    HMAC hmac2 = HMAC.Create(HMACName.HMAC_SM3);
    hmac2.ImportParameters(key);
    _ = hmac2.ComputeHash(_input);
}

```

### CMAC

```c#

private static void Demo3()
{
    CMAC cmac1 = CMAC.Create(CMACName.AES_CMAC);
    byte[] key = new byte[192 / 8]; // 192 = AES legal key size bits.
    Buffer.BlockCopy(_keyExchangePms, 0, key, 0, key.Length);
    cmac1.ImportParameters(key);
    _ = cmac1.ComputeHash(_input);
    CMAC cmac2 = CMAC.Create(CMACName.AES_CMAC);
    cmac2.ImportParameters(key);
    _ = cmac2.ComputeHash(_input);
}

```

### MAC

```c#

private static void Demo4()
{
    MAC mac1 = MAC.Create(MACName.Rijndael224_MAC);
    mac1.Mode = SymmetricCipherMode.CBC;
    mac1.Padding = SymmetricPaddingMode.TBC;
    byte[] key = new byte[160 / 8];  // 160 = Rijndael legal key size bits.
    byte[] iv = new byte[224 / 8];   // 224 = CBC mode limit same as Rijndael block size bits.
    Buffer.BlockCopy(_keyExchangePms, 0, key, 0, key.Length);
    Buffer.BlockCopy(_keyExchangePms, 0, iv, 0, iv.Length);
    mac1.ImportParameters(key, iv);
    _ = mac1.ComputeHash(_input);
    MAC mac2 = MAC.Create(MACName.Rijndael224_MAC);
    mac2.ImportParameters(key, iv);
    _ = mac2.ComputeHash(_input);
}

```

### Symmetric encryption

```c#

private static void Demo1()
{
    SymmetricAlgorithm alg1 = SymmetricAlgorithm.Create(SymmetricAlgorithmName.Rijndael224);
    alg1.Mode = SymmetricCipherMode.CTR;
    alg1.Padding = SymmetricPaddingMode.TBC;
    Rijndael alg2 = new Rijndael(224) { Mode = SymmetricCipherMode.CTR, Padding = SymmetricPaddingMode.TBC };
    byte[] key = new byte[160 / 8];  // 160 = Rijndael legal key size bits.
    byte[] iv = new byte[224 / 8];   // 224 = CTR mode limit same as Rijndael block size bits.
    Buffer.BlockCopy(_keyExchangePms, 0, key, 0, key.Length);
    Buffer.BlockCopy(_keyExchangePms, 0, iv, 0, iv.Length);
    alg1.ImportParameters(key, iv);
    alg2.ImportParameters(key, iv);
    byte[] enc = alg1.EncryptFinal(_input);
    _ = alg2.DecryptFinal(enc);
}

private static void Demo3()
{
    SymmetricAlgorithm alg1 = SymmetricAlgorithm.Create(SymmetricAlgorithmName.HC128);
    HC128 alg2 = new HC128();
    byte[] key = new byte[128 / 8];  // 128 = HC128 legal key size bits.
    byte[] iv = new byte[128 / 8];   // 256 = HC128 legal iv size bits.
    Buffer.BlockCopy(_keyExchangePms, 0, key, 0, key.Length);
    Buffer.BlockCopy(_keyExchangePms, 0, iv, 0, iv.Length);
    alg1.ImportParameters(key, iv);
    alg2.ImportParameters(key, iv);
    byte[] enc = alg1.EncryptFinal(_input);
    _ = alg2.DecryptFinal(enc);
}

```

### Asymmetric encryption

```c#

private static void Demo1()
{
    RSA rsa1 = new RSA();
    string pem = rsa1.ExportPem(false);

    RSA rsa2 = (RSA)AsymmetricAlgorithm.Create(AsymmetricAlgorithmName.RSA);
    rsa2.ImportPem(pem);

    byte[] enc = rsa2.Encrypt(_input);
    _ = rsa1.Decrypt(enc);
}

private static void Demo2()
{
    IAsymmetricEncryptionAlgorithm elGamal1 = new ElGamal().GetEncryptionInterface();
    byte[] keyInfo = elGamal1.ExportKeyInfo(false);

    IAsymmetricEncryptionAlgorithm elGamal2 = (IAsymmetricEncryptionAlgorithm)AsymmetricAlgorithm.Create(AsymmetricAlgorithmName.ElGamal);
    elGamal1.ImportKeyInfo(keyInfo);

    byte[] enc = elGamal2.Encrypt(_input);
    _ = elGamal1.Decrypt(enc);
}

```

### Signature

```c#

private static void Demo()
{
    ECDSA alg1 = (ECDSA)AsymmetricAlgorithm.Create(SignatureAlgorithmName.SHA256withECDSA);
    string pem = alg1.ExportPem(false);
    if (SignatureAlgorithmName.TryGetAlgorithmName("sha256withecdsa", out SignatureAlgorithmName name))
    {
        IAsymmetricSignatureAlgorithm alg2 = AsymmetricAlgorithm.Create(name).GetSignatureInterface();
        alg2.ImportPem(pem);

        byte[] signature = alg1.SignFinal(_input);
        alg2.VerifyUpdate(_input);
        _ = alg2.VerifyFinal(signature);
    }
}

```

### Certificate

```c#

```

### ECDH

```c#

private static void Demo()
{
    IKeyExchangeA keA = new ECDH().GetKeyExchangeAInterface();
    IKeyExchangeB keB = new ECDH().GetKeyExchangeBInterface();

    // Alice work
    keA.GenerateParameters(384);
    byte[] p = keA.P;
    byte[] g = keA.G;
    byte[] publicKeyA = keA.PublicKeyA;

    // Bob work
    keB.GenerateParameters(p, g, publicKeyA);
    byte[] pmsB = keB.DeriveKeyMaterial(true);
    byte[] publicKeyB = keB.PublicKeyB;

    // Alice work
    byte[] pmsA = keA.DeriveKeyMaterial(publicKeyB, true);

    //
    bool same = pmsA.SequenceEqual(pmsB);
    Console.WriteLine($"ECDH {same}");
    Console.WriteLine(BitConverter.ToString(pmsA).Replace("-", ""));
    Console.WriteLine(BitConverter.ToString(pmsB).Replace("-", ""));
}

```

## BUG

BouncyCastle 1.9.0 has not been fixed

1. RC5-32, RC5-64 does not support KeyParameter, only RC5Parameters. (feature?)
2. GCM cipher mode cannot be auto resue. The algorithm instance needs to be recreated every time.
3. GOFB cipher mode N3, N4 value omitted at reset. The cipher instance needs to be recreated every time.
4. OCB cipher mode supported null(0) iv size but BouncyCastle cannot set that.
5. The signature algorithm SHA256withECDSA points to SHA224withECDSA at Org.BouncyCastle.Cms.DefaultSignatureAlgorithmIdentifierFinder.
6. SM2Signer does not reset the hash algorithm automatically. must be Reset() manually.

## LICENSE

This project based on MIT license.
