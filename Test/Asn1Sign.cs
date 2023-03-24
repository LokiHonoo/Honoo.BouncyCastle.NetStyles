using Honoo.BouncyCastle.NetStyles;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Text;

namespace Test
{
    internal class Asn1Sign
    {
        private static readonly byte[] _input = new byte[15];

        static Asn1Sign()
        {
            Common.Random.NextBytes(_input);
        }

        internal static void Test()
        {
            DoAll();
            Console.WriteLine();
            Console.WriteLine();
            Console.ReadKey(true);
        }

        private static void DoAll()
        {
            X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
            BigInteger sn = new BigInteger(128, new SecureRandom());
            generator.SetIssuerDN(new X509Name("CN=rrrrr"));
            generator.SetNotBefore(DateTime.Today);
            generator.SetNotAfter(DateTime.Today.AddDays(1));
            generator.SetSerialNumber(sn);
            generator.SetSubjectDN(new X509Name("CN=rrrrr"));
            foreach (var algorithmName in SignatureAlgorithmName.GetNames())
            {
                StringBuilder builder = new StringBuilder();
                builder.Append(algorithmName.Name.PadRight(30));
                var key = AsymmetricAlgorithm.Create(algorithmName).ExportParameters();
                generator.SetPublicKey(key.Public);
                try
                {
                    var aaa = new Asn1SignatureFactory(algorithmName.Name, key.Private);
                    generator.Generate(aaa);
                    builder.Append("Name OK     ");
                }
                catch (Exception ex)
                {
                    builder.Append("            ");
                }
                try
                {
                    var aaa = new Asn1SignatureFactory(algorithmName.Oid, key.Private);
                    generator.Generate(aaa);
                    builder.Append("Oid OK     ");
                }
                catch (Exception)
                {
                    builder.Append("           ");
                }
                Console.WriteLine(builder.ToString());
            }
        }
    }
}