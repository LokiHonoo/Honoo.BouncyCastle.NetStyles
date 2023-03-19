using Honoo.BouncyCastle;

namespace Test
{
    internal static class Temporaries
    {
        internal static void Test()
        {
            byte[] input = new byte[123];
            Common.Random.NextBytes(input);
            DES des1 = new DES() { Mode = SymmetricCipherMode.GOFB, Padding = SymmetricPaddingMode.PKCS7 };
            byte[] key = new byte[8];
            byte[] iv = new byte[8];
            Common.Random.NextBytes(key);
            Common.Random.NextBytes(iv);
            des1.ImportParameters(key, iv);
            byte[] enc1 = des1.EncryptFinal(input);
            des1.ExportParameters(out byte[] key1, out byte[] iv1);
            byte[] enc2 = des1.EncryptFinal(input);
            des1.ExportParameters(out byte[] key2, out byte[] iv2);
            DES des2 = new DES() { Mode = SymmetricCipherMode.GOFB, Padding = SymmetricPaddingMode.PKCS7 };
            des2.ImportParameters(key, iv);
            byte[] dec1 = des2.DecryptFinal(enc1);
            byte[] dec2 = des2.DecryptFinal(enc2);
        }
    }
}