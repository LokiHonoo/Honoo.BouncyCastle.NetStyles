using Honoo.BouncyCastle.NetStyles;
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
            Demo1();
            Demo2();
            DoSM2();
            DoECDSA();
            DoDSA();
            DoRSA();
            DoElGamal();
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine($"Total= {_total}  Diff= {_diff}  Ignore= {_ignore}");
            Console.ReadKey(true);
        }

        private static void Demo1()
        {
            RSA rsa1 = new RSA();
            string pem = rsa1.ExportPem(false);

            RSA rsa2 = (RSA)AsymmetricAlgorithm.Create(AsymmetricAlgorithmName.RSA);
            rsa2.ImportPem(pem);

            byte[] enc = rsa2.Encrypt(_input);
            byte[] dec = rsa1.Decrypt(enc);
            WriteResult("RSA DEMO", _input, enc, dec);
        }

        private static void Demo2()
        {
            IAsymmetricEncryptionAlgorithm elGamal1 = new ElGamal();
            byte[] keyInfo = elGamal1.ExportKeyInfo(false);

            IAsymmetricEncryptionAlgorithm elGamal2 = (IAsymmetricEncryptionAlgorithm)AsymmetricAlgorithm.Create(AsymmetricAlgorithmName.ElGamal);
            elGamal2.ImportKeyInfo(keyInfo);

            byte[] enc = elGamal2.Encrypt(_input);
            byte[] dec = elGamal1.Decrypt(enc);
            WriteResult("ElGamal DEMO", _input, enc, dec);
        }

        private static void DoDSA()
        {
            var net = new System.Security.Cryptography.DSACryptoServiceProvider();
            DSA alg1 = new DSA();
            DSA alg2 = new DSA();
            System.Security.Cryptography.DSAParameters parameters1 = net.ExportParameters(true);
            System.Security.Cryptography.DSAParameters parameters2 = net.ExportParameters(false);
            alg1.ImportNetParameters(parameters1);
            alg2.ImportNetParameters(parameters2);
            string xml1 = net.ToXmlString(true);
            string xml2 = net.ToXmlString(false);
            alg1.ImportXml(xml1);
            alg2.ImportXml(xml2);
            var pirKey = alg1.ExportParameters(true);
            var pubKey = alg1.ExportParameters(false);
            alg2.ImportParameters(pirKey);
            alg2.ImportParameters(pubKey);
        }

        private static void DoECDSA()
        {
            ECDSA alg1 = new ECDSA();
            var curves = (EllipticCurve[])Enum.GetValues(typeof(EllipticCurve));
            foreach (var curve in curves)
            {
                alg1.GenerateParameters(curve);
                alg1.ExportPem(false);
            }
        }

        private static void DoElGamal()
        {
            ElGamal alg1 = new ElGamal();
            ElGamal alg2 = new ElGamal();
            var pirKey = alg1.ExportParameters(true);
            var pubKey = alg1.ExportParameters(false);
            alg2.ImportParameters(pirKey);
            alg2.ImportParameters(pubKey);
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
                title.Append(alg2.GetLegalInputLength(true).ToString().PadRight(12));
                title.Append(alg1.GetLegalInputLength(false).ToString().PadRight(12));
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
            alg1.ImportNetParameters(parameters1);
            alg2.ImportNetParameters(parameters2);
            var pirKey = alg1.ExportParameters(true);
            var pubKey = alg1.ExportParameters(false);
            alg2.ImportParameters(pirKey);
            alg2.ImportParameters(pubKey);
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
                title.Append(alg2.GetLegalInputLength(true).ToString().PadRight(12));
                title.Append(alg1.GetLegalInputLength(false).ToString().PadRight(12));
                alg2.Encrypt(_input);
                byte[] enc = alg2.Encrypt(_input);
                alg1.Decrypt(enc);
                byte[] dec = alg1.Decrypt(enc);
                WriteResult(title.ToString(), _input, enc, dec);
            }
        }

        private static void DoSM2()
        {
            byte[] bytes = new byte[16777];
            Common.Random.NextBytes(bytes);
            SM2 alg1 = new SM2();
            SM2 alg2 = new SM2();
            alg1.HashAlgorithmName = HashAlgorithmName.SHA256;
            alg1.GenerateParameters(SM2EllipticCurve.WapiP192v1);
            var pirKey = alg1.ExportParameters(true);
            var pubKey = alg1.ExportParameters(false);
            alg2.ImportParameters(pirKey);
            alg2.ImportParameters(pubKey);
            alg2.Encrypt(bytes);
            byte[] enc = alg2.Encrypt(bytes);
            alg1.Decrypt(enc);
            byte[] dec = alg1.Decrypt(enc);
            StringBuilder title = new StringBuilder();
            title.Append(alg1.Name.PadRight(24));
            title.Append(alg2.GetLegalInputLength(true).ToString().PadRight(12));
            title.Append(alg1.GetLegalInputLength(false).ToString().PadRight(12));
            WriteResult(title.ToString(), bytes, enc, dec);
        }

        private static void WriteResult(string title, byte[] input, byte[] enc, byte[] dec)
        {
            StringBuilder message1 = new StringBuilder();
            message1.Append((title + " ").PadRight(50, ' '));
            message1.Append($"{input.Length}/{enc.Length}/{dec.Length} ");
            string message = message1.ToString().PadRight(80, '-');
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