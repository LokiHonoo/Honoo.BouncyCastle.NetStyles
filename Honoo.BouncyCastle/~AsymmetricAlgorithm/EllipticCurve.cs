namespace Honoo.BouncyCastle
{
    /// <summary>
    /// ECDSA elliptic curve.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("CodeQuality", "IDE0079:请删除不必要的忽略", Justification = "<挂起>")]
    public enum EllipticCurve
    {
#pragma warning disable CS1591 // 缺少对公共可见类型或成员的 XML 注释

        // X962NamedCurves

        Prime192v1 = 1,
        Prime192v2,
        Prime192v3,
        Prime239v1,
        Prime239v2,
        Prime239v3,
        Prime256v1,

        C2Pnb163v1,
        C2Pnb163v2,
        C2Pnb163v3,
        C2Pnb176w1,
        C2Tnb191v1,
        C2Tnb191v2,
        C2Tnb191v3,
        C2Pnb208w1,
        C2Tnb239v1,
        C2Tnb239v2,
        C2Tnb239v3,
        C2Pnb272w1,
        C2Pnb304w1,
        C2Tnb359v1,
        C2Pnb368w1,
        C2Tnb431r1,

        // SecNamedCurves

        SecP112r1,
        SecP112r2,
        SecP128r1,
        SecP128r2,
        SecP160k1,
        SecP160r1,
        SecP160r2,
        SecP192k1,
        SecP192r1,
        SecP224k1,
        SecP224r1,
        SecP256k1,
        SecP256r1,
        SecP384r1,
        SecP521r1,

        SecT113r1,
        SecT113r2,
        SecT131r2,
        SecT131r1,
        SecT163k1,
        SecT163r1,
        SecT163r2,
        SecT193r1,
        SecT193r2,
        SecT233k1,
        SecT233r1,
        SecT239k1,
        SecT283k1,
        SecT283r1,
        SecT409k1,
        SecT409r1,
        SecT571k1,
        SecT571r1,

        // NistNamedCurves

        NistP192,
        NistP224,
        NistP256,
        NistP384,
        NistP521,

        NistB163,
        NistB233,
        NistB283,
        NistB409,
        NistB571,

        NistK163,
        NistK233,
        NistK283,
        NistK409,
        NistK571,

        // TeleTrusTNamedCurves

        BrainpoolP160R1,
        BrainpoolP160T1,
        BrainpoolP192R1,
        BrainpoolP192T1,
        BrainpoolP224R1,
        BrainpoolP224T1,
        BrainpoolP256R1,
        BrainpoolP256T1,
        BrainpoolP320R1,
        BrainpoolP320T1,
        BrainpoolP384R1,
        BrainpoolP384T1,
        BrainpoolP512R1,
        BrainpoolP512T1,

        // AnssiNamedCurves

        FRP256v1,

        // ECGost3410NamedCurves

        GostR3410_2001_CryptoPro_A,
        GostR3410_2001_CryptoPro_B,
        GostR3410_2001_CryptoPro_C,
        GostR3410_2001_CryptoPro_XchA,
        GostR3410_2001_CryptoPro_XchB,
        Tc26_Gost3410_12_256_ParamSetA,
        Tc26_Gost3410_12_512_ParamSetA,
        Tc26_Gost3410_12_512_ParamSetB,
        Tc26_Gost3410_12_512_ParamSetC,

        // GMNamedCurves

        Sm2P256v1,
        WapiP192v1,

#pragma warning restore CS1591 // 缺少对公共可见类型或成员的 XML 注释
    }
}