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
            DoECDSA();
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine($"Total= {_total}  Diff= {_diff}  Ignore= {_ignore}");
            Console.ReadKey(true);
        }

        private static void Demo()
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
                WriteResult("DSA BouncyCastle <--> .NET", same);
            }
            {
                _total++;
                SHA1 sha1 = new SHA1();
                byte[] signature = net.CreateSignature(sha1.ComputeHash(_input));
                bool same = alg2.VerifyFinal(_input, signature);
                WriteResult("DSA BouncyCastle <--> .NET", same);
            }
        }

        private static void DoECDSA()
        {
            ECDSA alg1 = new ECDSA() { HashAlgorithm = HashAlgorithmName.BLAKE2s256 };
            ECDSA alg2 = new ECDSA() { HashAlgorithm = HashAlgorithmName.BLAKE2s256 };
            var pem = alg1.ExportPem(false);
            alg2.ImportPem(pem);
            {
                _total++;
                byte[] signature = alg1.SignFinal(_input);
                bool same = alg2.VerifyFinal(_input, signature);
                WriteResult(alg1.SignatureAlgorithm, same);
            }
            {
                _total++;
                alg1.SignatureExtension = ECDSASignatureExtension.Plain;
                alg2.SignatureExtension = ECDSASignatureExtension.Plain;
                byte[] signature = alg1.SignFinal(_input);
                bool same = alg2.VerifyFinal(_input, signature);
                WriteResult(alg1.SignatureAlgorithm, same);
            }
            {
                _total++;
                alg1.SignatureExtension = ECDSASignatureExtension.ECNR;
                alg2.SignatureExtension = ECDSASignatureExtension.ECNR;
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
            var parameters = alg1.ExportParameters(false);
            alg2.ImportParameters(parameters);
            net.ImportParameters(parameters);
            {
                _total++;
                byte[] signature = alg1.SignFinal(_input);
                bool same = net.VerifyData(_input, "SHA512", signature);
                WriteResult("RSA BouncyCastle <--> .NET", same);
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