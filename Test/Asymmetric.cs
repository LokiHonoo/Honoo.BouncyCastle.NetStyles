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
            Common.SecureRandom.NextBytes(_input);
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
            DoECDSA();
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine($"Total= {_total}  Diff= {_diff}  Ignore= {_ignore}");
            Console.ReadKey(true);
        }

        private static void Demo()
        {
            RSA rsa1 = new RSA { Padding = AsymmetricPaddingMode.ISO9796_1 };
            rsa1.GenerateKeyPair(512);
            string pem = rsa1.ExportPem(false);

            RSA rsa2 = new RSA { Padding = AsymmetricPaddingMode.ISO9796_1 };
            rsa2.ImportPem(pem);

            byte[] enc = rsa2.Encrypt(_input);
            _ = rsa1.Decrypt(enc);
        }

        private static void DoECDSA()
        {
            ECDSA alg1 = new ECDSA();
            ECDSA alg2 = new ECDSA();
            string pem1 = alg1.ExportPem(true);
            string pem2 = alg1.ExportPem(false);
            string pem3 = alg1.ExportPem(DEKAlgorithmName.RC2_64_OFB, "12345");
            alg2.ImportPem(pem1);
            alg2.ImportPem(pem2);
            alg2.ImportPem(pem3, "12345");
        }

        private static void DoDSA()
        {
            var net = new System.Security.Cryptography.DSACryptoServiceProvider();
            DSA alg1 = new DSA();
            DSA alg2 = new DSA();
            string pem1 = alg1.ExportPem(true);
            string pem2 = alg1.ExportPem(false);
            string pem3 = alg1.ExportPem(DEKAlgorithmName.BLOWFISH_CBC, "12345");
            alg2.ImportPem(pem1);
            alg2.ImportPem(pem2);
            alg2.ImportPem(pem3, "12345");
            System.Security.Cryptography.DSAParameters parameters1 = net.ExportParameters(true);
            System.Security.Cryptography.DSAParameters parameters2 = net.ExportParameters(false);
            alg1.ImportParameters(parameters1);
            alg2.ImportParameters(parameters2);
            string xml1 = net.ToXmlString(true);
            string xml2 = net.ToXmlString(false);
            alg1.FromXmlString(xml1);
            alg2.FromXmlString(xml2);
        }

        private static void DoElGamal()
        {
            ElGamal alg1 = new ElGamal();
            ElGamal alg2 = new ElGamal();
            string pem1 = alg1.ExportPem(true);
            string pem2 = alg1.ExportPem(false);
            string pem3 = alg1.ExportPem(DEKAlgorithmName.RC2_40_CFB, "12345");
            alg2.ImportPem(pem1);
            alg2.ImportPem(pem2);
            alg2.ImportPem(pem3, "12345");

            var paddings = (AsymmetricPaddingMode[])Enum.GetValues(typeof(AsymmetricPaddingMode));
            foreach (var padding in paddings)
            {
                if (padding == AsymmetricPaddingMode.ISO9796_1)
                {
                    continue;
                }
                _total++;
                alg1.Padding = padding;
                alg2.Padding = padding;
                byte[] enc = alg2.Encrypt(_input);
                byte[] dec = alg1.Decrypt(enc);
                StringBuilder title = new StringBuilder();
                title.Append($"{alg1.Name}-{alg1.KeySize}/{padding}".PadRight(24));
                title.Append($"Enc {alg2.EncryptInputLength}/{alg2.EncryptOutputLength}".PadRight(15));
                title.Append($"Dec {alg1.DecryptInputLength}/{alg1.DecryptOutputLength}");
                WriteResult(title.ToString(), _input, enc, dec);
            }
        }

        private static void DoRSA()
        {
            var net = new System.Security.Cryptography.RSACryptoServiceProvider(1280);
            RSA alg1 = new RSA();
            RSA alg2 = new RSA();
            string pem1 = alg1.ExportPem(true);
            string pem2 = alg1.ExportPem(false);
            string pem3 = alg1.ExportPem(DEKAlgorithmName.BLOWFISH_CBC, "12345");
            alg2.ImportPem(pem1);
            alg2.ImportPem(pem2);
            alg2.ImportPem(pem3, "12345");
            System.Security.Cryptography.RSAParameters parameters1 = alg1.ExportParameters(true);
            System.Security.Cryptography.RSAParameters parameters2 = alg1.ExportParameters(false);
            alg2.ImportParameters(parameters1);
            alg2.ImportParameters(parameters2);
            string xml1 = alg1.ToXmlString(true);
            string xml2 = alg1.ToXmlString(false);
            alg2.FromXmlString(xml1);
            alg2.FromXmlString(xml2);

            System.Security.Cryptography.RSAParameters parameters3 = net.ExportParameters(true);
            string xml3 = net.ToXmlString(false);
            alg1.ImportParameters(parameters3);
            alg2.FromXmlString(xml3);
            {
                _total++;
                alg2.Padding = AsymmetricPaddingMode.OAEP;
                byte[] enc = alg2.Encrypt(_input);
                byte[] dec = net.Decrypt(enc, true);
                WriteResult("RSA BouncyCastle <--> .NET", _input, enc, dec);
            }
            var paddings = (AsymmetricPaddingMode[])Enum.GetValues(typeof(AsymmetricPaddingMode));
            foreach (var padding in paddings)
            {
                _total++;
                alg1.Padding = padding;
                alg2.Padding = padding;
                byte[] enc = alg2.Encrypt(_input);
                byte[] dec = alg1.Decrypt(enc);
                StringBuilder title = new StringBuilder();
                title.Append($"{alg1.Name}-{alg1.KeySize}/{padding}".PadRight(24));
                title.Append($"Enc {alg2.EncryptInputLength}/{alg2.EncryptOutputLength}".PadRight(15));
                title.Append($"Dec {alg1.DecryptInputLength}/{alg1.DecryptOutputLength}");
                WriteResult(title.ToString(), _input, enc, dec);
            }
        }

        private static void WriteResult(string title, byte[] input, byte[] enc, byte[] dec)
        {
            string message = (title + " ").PadRight(60, '-');
            if (dec.SequenceEqual(input))
            {
                Console.WriteLine($"{message} same");
            }
            else
            {
                Console.WriteLine($"{message} diff <--");
                Console.WriteLine($"  org   {BitConverter.ToString(input).Replace('-', char.MinValue)}");
                Console.WriteLine($"  enc   {BitConverter.ToString(enc).Replace('-', char.MinValue)}");
                Console.WriteLine($"  dec   {BitConverter.ToString(dec).Replace('-', char.MinValue)}");
                _diff++;
            }
        }
    }
}