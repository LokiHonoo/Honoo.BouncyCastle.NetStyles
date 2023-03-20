using Honoo.BouncyCastle;
using System;

namespace Test
{
    internal static class Temporaries
    {
        internal static void Test()
        {
            ECGOST3410 alg1 = new ECGOST3410();
            ECGOST3410 alg2 = new ECGOST3410();
            string pem1 = alg1.ExportPem(DEKAlgorithmName.RC2_64_OFB, "12345");
            string pem2 = alg1.ExportPem(true);
            string pem3 = alg1.ExportPem(false);
            alg2.ImportPem(pem1, "12345");
            alg2.ImportPem(pem2);
            alg2.ImportPem(pem3);
            byte[] info1 = alg1.ExportKeyInfo(PBEAlgorithmName.PBEwithSHAand3KeyDESedeCBC, "12345");
            byte[] info2 = alg1.ExportKeyInfo(true);
            byte[] info3 = alg1.ExportKeyInfo(false);
            alg2.ImportKeyInfo(info1, "12345");
            alg2.ImportKeyInfo(info2);
            alg2.ImportKeyInfo(info3);

            var ccc = (ECGOST3410EllipticCurve[])Enum.GetValues(typeof(ECGOST3410EllipticCurve));
            foreach (var item in ccc)
            {
                alg1.GenerateParameters(item);
                byte[] info = alg1.ExportKeyInfo(PBEAlgorithmName.PBEwithSHAand3KeyDESedeCBC, "12345");
                alg2.ImportKeyInfo(info, "12345");
                info = alg1.ExportKeyInfo(true);
                alg2.ImportKeyInfo(info);
                info = alg1.ExportKeyInfo(false);
                alg2.ImportKeyInfo(info);
            }
             Console.ReadKey(true);
        }
    }
}