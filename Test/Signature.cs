using Honoo.BouncyCastle;
using System;

namespace Test
{
    internal static class Signature
    {
        private static readonly byte[] _input = new byte[15];
        private static int _diff = 0;
        private static int _ignore = 0;
        private static int _total = 0;

        static Signature()
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
            DoECDSA();
            DoAll();
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine($"Total= {_total}  Diff= {_diff}  Ignore= {_ignore}");
            Console.ReadKey(true);
        }

        private static void Demo()
        {
            ECDSA alg1 = (ECDSA)AsymmetricAlgorithm.Create(SignatureAlgorithmName.SHA256withECDSA);
            IAsymmetricSignatureAlgorithm alg2 = AsymmetricAlgorithm.Create(SignatureAlgorithmName.SHA256withECDSA).GetSignatureInterface();

            var pem = alg1.ExportPem(false);
            alg2.ImportPem(pem);

            byte[] signature = alg1.SignFinal(_input);
            _ = alg2.VerifyFinal(_input, signature);
        }

        private static void DoAll()
        {
            var names = SignatureAlgorithmName.GetNames();
            foreach (var name in names)
            {
                _total++;
                var alg1 = AsymmetricAlgorithm.Create(name).GetSignatureInterface();
                var alg2 = AsymmetricAlgorithm.Create(name).GetSignatureInterface();
                string pem1 = alg1.ExportPem(true);
                string pem2 = alg1.ExportPem(false);
                alg2.ImportPem(pem1);
                alg2.ImportPem(pem2);
                byte[] signature = alg1.SignFinal(_input);
                bool same = alg2.VerifyFinal(_input, signature);
                WriteResult(alg1.SignatureAlgorithm, same);
            }
        }

        private static void DoDSA()
        {
            var net = System.Security.Cryptography.DSA.Create();
            var parameters = net.ExportParameters(true);
            DSA alg1 = new DSA() { HashAlgorithm = HashAlgorithmName.SHA1, SignatureEncoding = DSASignatureEncodingMode.Plain };
            DSA alg2 = new DSA() { HashAlgorithm = HashAlgorithmName.SHA1, SignatureEncoding = DSASignatureEncodingMode.Plain };
            alg1.ImportParameters(parameters);
            alg2.ImportParameters(parameters);
            {
                _total++;
                byte[] signature = alg1.SignFinal(_input);
                SHA1 sha1 = new SHA1();
                bool same = net.VerifySignature(sha1.ComputeHash(_input), signature);
                WriteResult($"{alg1.SignatureAlgorithm} BC <--> NET", same);
            }
            {
                _total++;
                SHA1 sha1 = new SHA1();
                byte[] signature = net.CreateSignature(sha1.ComputeHash(_input));
                bool same = alg2.VerifyFinal(_input, signature);
                WriteResult($"{alg2.SignatureAlgorithm} BC <--> NET", same);
            }
        }

        private static void DoECDSA()
        {
            ECDSA alg1 = new ECDSA() { HashAlgorithm = HashAlgorithmName.BLAKE2s256 };
            ECDSA alg2 = new ECDSA() { HashAlgorithm = HashAlgorithmName.BLAKE2s256 };
            var pem = alg1.ExportPem(false);
            alg2.ImportPem(pem);
            var extensions = (ECDSASignatureExtension[])Enum.GetValues(typeof(ECDSASignatureExtension));
            foreach (var extension in extensions)
            {
                _total++;
                alg1.SignatureExtension = extension;
                alg2.SignatureExtension = extension;
                byte[] signature = alg1.SignFinal(_input);
                bool same = alg2.VerifyFinal(_input, signature);
                WriteResult(alg1.SignatureAlgorithm, same);
            }
        }

        private static void DoRSA()
        {
            var net = new System.Security.Cryptography.RSACryptoServiceProvider();
            RSA alg1 = new RSA() { HashAlgorithm = HashAlgorithmName.SHA512 };
            RSA alg2 = new RSA() { HashAlgorithm = HashAlgorithmName.SHA512 };
            var parameters = alg1.ExportParameters(true);
            alg2.ImportParameters(parameters);
            net.ImportParameters(parameters);
            {
                _total++;
                byte[] signature = alg1.SignFinal(_input);
                bool same = net.VerifyData(_input, "SHA512", signature);
                WriteResult($"{alg1.SignatureAlgorithm} BC <--> NET", same);
            }
            {
                _total++;
                byte[] signature = net.SignData(_input, "SHA512");
                bool same = alg1.VerifyFinal(_input, signature);
                WriteResult($"{alg1.SignatureAlgorithm} BC <--> NET", same);
            }
            var paddings = (RSASignaturePaddingMode[])Enum.GetValues(typeof(RSASignaturePaddingMode));
            foreach (var padding in paddings)
            {
                _total++;
                alg1.SignaturePadding = padding;
                alg2.SignaturePadding = padding;
                byte[] signature = alg1.SignFinal(_input);
                bool same = alg2.VerifyFinal(_input, signature);
                WriteResult(alg1.SignatureAlgorithm, same);
            }
        }

        private static void WriteResult(string title, bool same)
        {
            string message = (title + " ").PadRight(30, '-');
            if (same)
            {
                Console.WriteLine($"{message} same");
            }
            else
            {
                Console.WriteLine($"{message} diff <--");
                _diff++;
            }
        }
    }
}