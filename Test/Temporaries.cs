using Honoo.BouncyCastle.NetStyles;
using System;
using System.Diagnostics;
using System.Linq;

namespace Test
{
    internal static class Temporaries
    {
        internal static void Test()
        {
            ECGOST3410 alg = new ECGOST3410();
            var aaa = (ECGOST3410EllipticCurve[])Enum.GetValues(typeof(ECGOST3410EllipticCurve));
            foreach ( var x in aaa) {

                alg.GenerateParameters(x);

                alg.SignFinal(new byte[1330]);
               var a= alg.ExportPem(true);
                alg.ImportPem(a);
            }


            SM2 sM2 = new SM2();
            sM2.GenerateParameters( SM2EllipticCurve.WapiP192v1 );
            sM2.SignFinal(new byte[1330]);
            var bb = alg.ExportPem(true);
            sM2.ImportPem(bb);
            sM2.GenerateParameters(SM2EllipticCurve.Sm2P256v1);
            sM2.SignFinal(new byte[1330]);
            var cc = alg.ExportPem(true);
            sM2.ImportPem(cc);
            Console.ReadKey(true);
        }


    }
}