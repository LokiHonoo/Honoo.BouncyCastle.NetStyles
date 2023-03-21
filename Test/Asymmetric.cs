using Honoo.BouncyCastle;
using System;
using System.Linq;
using System.Text;

namespace Test
{
    internal static class Asymmetric
    {
        private static readonly byte[] _input = new byte[15];
        private static int _diff = 0;
        private static int _ignore = 0;
        private static int _total = 0;

        static Asymmetric()
        {
            Common.Random.NextBytes(_input);
        }

        internal static void Test()
        {
            _total = 0;
            _diff = 0;
            _ignore = 0;
            Demo();
            DoDSA();
            DoRSA();
            DoElGamal();
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine($"Total= {_total}  Diff= {_diff}  Ignore= {_ignore}");
            Console.ReadKey(true);
        }

        private static void Demo()
        {
            RSA rsa1 = new RSA();
            string pem = rsa1.ExportPem(false);

            RSA rsa2 = (RSA)AsymmetricAlgorithm.Create(AsymmetricAlgorithmName.RSA);
            rsa2.ImportPem(pem);

            byte[] enc = rsa2.Encrypt(_input);
            _ = rsa1.Decrypt(enc);
        }

        private static void DoDSA()
        {
            var net = new System.Security.Cryptography.DSACryptoServiceProvider();
            DSA alg1 = new DSA();
            DSA alg2 = new DSA();
            System.Security.Cryptography.DSAParameters parameters1 = net.ExportParameters(true);
            System.Security.Cryptography.DSAParameters parameters2 = net.ExportParameters(false);
            alg1.ImportParameters(parameters1);
            alg2.ImportParameters(parameters2);
            string xml1 = net.ToXmlString(true);
            string xml2 = net.ToXmlString(false);
            alg1.ImportXml(xml1);
            alg2.ImportXml(xml2);
        }

        private static void DoElGamal()
        {
            ElGamal alg1 = new ElGamal();
            ElGamal alg2 = new ElGamal();
            string pem1 = alg1.ExportPem(DEKAlgorithmName.RC2_40_CFB, "12345");
            string pem2 = alg1.ExportPem(true);
            string pem3 = alg1.ExportPem(false);
            alg2.ImportPem(pem1, "12345");
            alg2.ImportPem(pem2);
            alg2.ImportPem(pem3);
            byte[] keyInfo1 = alg1.ExportKeyInfo(PBEAlgorithmName.PBEwithSHAand3KeyDESedeCBC, "12345");
            byte[] keyInfo2 = alg1.ExportKeyInfo(true);
            byte[] keyInfo3 = alg1.ExportKeyInfo(false);
            alg2.ImportKeyInfo(keyInfo1, "12345");
            alg2.ImportKeyInfo(keyInfo2);
            alg2.ImportKeyInfo(keyInfo3);
            var paddings = (AsymmetricEncryptionPaddingMode[])Enum.GetValues(typeof(AsymmetricEncryptionPaddingMode));
            foreach (var padding in paddings)
            {
                if (padding == AsymmetricEncryptionPaddingMode.ISO9796_1)
                {
                    continue;
                }
                _total++;
                alg1.Padding = padding;
                alg2.Padding = padding;
                StringBuilder title = new StringBuilder();
                title.Append($"{alg1.Name}-{alg1.KeySize}/{padding}".PadRight(24));
                title.Append($"{alg2.EncryptInputLength}/{alg2.EncryptOutputLength}/{alg2.DecryptInputLength}/{alg2.DecryptOutputLength}".PadRight(16));
                title.Append($"{alg1.EncryptInputLength}/{alg1.EncryptOutputLength}/{alg1.DecryptInputLength}/{alg1.DecryptOutputLength}");
                alg2.Encrypt(_input);
                byte[] enc = alg2.Encrypt(_input);
                alg1.Decrypt(enc);
                byte[] dec = alg1.Decrypt(enc);
                WriteResult(title.ToString(), _input, enc, dec);
            }
        }

        private static void DoRSA()
        {
            var net = new System.Security.Cryptography.RSACryptoServiceProvider(1280);
            RSA alg1 = new RSA();
            RSA alg2 = new RSA();
            System.Security.Cryptography.RSAParameters parameters1 = net.ExportParameters(true);
            System.Security.Cryptography.RSAParameters parameters2 = net.ExportParameters(false);
            alg1.ImportParameters(parameters1);
            alg2.ImportParameters(parameters2);
            string xml1 = alg1.ExportXml(true);
            string xml2 = alg1.ExportXml(false);
            alg2.ImportXml(xml1);
            alg2.ImportXml(xml2);
            {
                _total++;
                alg2.Padding = AsymmetricEncryptionPaddingMode.OAEP;
                alg2.Encrypt(_input);
                byte[] enc = alg2.Encrypt(_input);
                byte[] dec = net.Decrypt(enc, true);
                WriteResult($"{alg1.Name}-{alg1.KeySize}/{alg1.Padding} BC <--> NET", _input, enc, dec);
            }
            var paddings = (AsymmetricEncryptionPaddingMode[])Enum.GetValues(typeof(AsymmetricEncryptionPaddingMode));
            foreach (var padding in paddings)
            {
                _total++;
                alg1.Padding = padding;
                alg2.Padding = padding;
                StringBuilder title = new StringBuilder();
                title.Append($"{alg1.Name}-{alg1.KeySize}/{padding}".PadRight(24));
                title.Append($"{alg2.EncryptInputLength}/{alg2.EncryptOutputLength}/{alg2.DecryptInputLength}/{alg2.DecryptOutputLength}".PadRight(16));
                title.Append($"{alg1.EncryptInputLength}/{alg1.EncryptOutputLength}/{alg1.DecryptInputLength}/{alg1.DecryptOutputLength}");
                alg2.Encrypt(_input);
                byte[] enc = alg2.Encrypt(_input);
                alg1.Decrypt(enc);
                byte[] dec = alg1.Decrypt(enc);
                WriteResult(title.ToString(), _input, enc, dec);
            }
        }

        private static void WriteResult(string title, byte[] input, byte[] enc, byte[] dec)
        {
            string message = (title + " ").PadRight(70, '-');
            if (dec.SequenceEqual(input))
            {
                Console.WriteLine($"{message} same");
            }
            else
            {
                Console.WriteLine($"{message} diff");
                Console.WriteLine($"  org   {BitConverter.ToString(input).Replace('-', char.MinValue)}");
                Console.WriteLine($"  enc   {BitConverter.ToString(enc).Replace('-', char.MinValue)}");
                Console.WriteLine($"  dec   {BitConverter.ToString(dec).Replace('-', char.MinValue)}");
                _diff++;
            }
        }
    }
}