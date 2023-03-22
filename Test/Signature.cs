using Honoo.BouncyCastle.NetStyles;
using System;
using System.Collections.Generic;

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
            DoEd25519();
            DoEd448();
            DoAll();
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine($"Total= {_total}  Diff= {_diff}  Ignore= {_ignore}");
            Console.ReadKey(true);
        }

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
                bool same = alg2.VerifyFinal(signature);
                WriteResult(alg1.SignatureAlgorithm, same);
            }
        }

        private static void DoAll()
        {
            var algorithmNames = new List<SignatureAlgorithmName>(SignatureAlgorithmName.GetNames());
            string[] mechanisms = new string[]
            {
                "BLAKE2s128withSM2",
                "SHA512/376withCVC-ECDSA",
                "Skein264-512withECGOST3410-2001",
                "SHA3-256withECGOST3410-2001",
                "BLAKE2b64withSM2",
            };
            foreach (var mechanism in mechanisms)
            {
                SignatureAlgorithmName.TryGetAlgorithmName(mechanism, out SignatureAlgorithmName algorithmName);
                algorithmNames.Add(algorithmName);
            }
            foreach (var algorithmName in algorithmNames)
            {
                _total++;
                SignatureAlgorithmName.TryGetAlgorithmName(algorithmName.Name, out SignatureAlgorithmName algorithmName2);
                var alg1 = AsymmetricAlgorithm.Create(algorithmName).GetSignatureInterface();
                var alg2 = AsymmetricAlgorithm.Create(algorithmName2).GetSignatureInterface();
                string pem1 = alg1.ExportPem(DEKAlgorithmName.DES_EDE3_OFB, "12345");
                string pem2 = alg1.ExportPem(true);
                string pem3 = alg1.ExportPem(false);
                alg2.ImportPem(pem1, "12345");
                alg2.ImportPem(pem2);
                alg2.ImportPem(pem3);
                byte[] keyInfo1 = alg1.ExportKeyInfo(PBEAlgorithmName.PBEwithSHAand2KeyDESedeCBC, "12345");
                byte[] keyInfo2 = alg1.ExportKeyInfo(true);
                byte[] keyInfo3 = alg1.ExportKeyInfo(false);
                alg2.ImportKeyInfo(keyInfo1, "12345");
                alg2.ImportKeyInfo(keyInfo2);
                alg2.ImportKeyInfo(keyInfo3);
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
                bool same = net.VerifySignature(sha1.ComputeFinal(_input), signature);
                WriteResult($"{alg1.SignatureAlgorithm} BC <--> NET", same);
            }
            {
                _total++;
                SHA1 sha1 = new SHA1();
                byte[] signature = net.CreateSignature(sha1.ComputeFinal(_input));
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

        private static void DoEd25519()
        {
            Ed25519 alg1 = new Ed25519();
            Ed25519 alg2 = new Ed25519();
            var pem = alg1.ExportPem(false);
            alg2.ImportPem(pem);
            var instances = (Ed25519SignatureInstance[])Enum.GetValues(typeof(Ed25519SignatureInstance));
            foreach (var instance in instances)
            {
                _total++;
                alg1.SignatureInstance = instance;
                alg2.SignatureInstance = instance;
                byte[] signature = alg1.SignFinal(_input);
                bool same = alg2.VerifyFinal(_input, signature);
                WriteResult(alg1.SignatureAlgorithm, same);
            }
        }

        private static void DoEd448()
        {
            Ed448 alg1 = new Ed448();
            Ed448 alg2 = new Ed448();
            var pem = alg1.ExportPem(false);
            alg2.ImportPem(pem);
            var instances = (Ed448SignatureInstance[])Enum.GetValues(typeof(Ed448SignatureInstance));
            foreach (var instance in instances)
            {
                _total++;
                alg1.SignatureInstance = instance;
                alg2.SignatureInstance = instance;
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
                alg1.SignUpdate(_input);
                byte[] signature = alg1.SignFinal();
                bool same = net.VerifyData(_input, "SHA512", signature);
                WriteResult($"{alg1.SignatureAlgorithm} BC <--> NET", same);
            }
            {
                _total++;
                byte[] signature = net.SignData(_input, "SHA512");
                alg2.VerifyUpdate(_input);
                bool same = alg2.VerifyFinal(signature);
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