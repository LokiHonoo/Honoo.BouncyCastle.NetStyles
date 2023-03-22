using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Bsi;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Eac;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X9;
using System;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Signature algorithm name.
    /// </summary>
    public sealed class SignatureAlgorithmName : IEquatable<SignatureAlgorithmName>
    {
        #region Delegate

        internal delegate AsymmetricAlgorithm GetAlgorithmCallback();

        #endregion Delegate

        #region RSA

        /// <summary></summary>
        public static SignatureAlgorithmName MD2withRSA { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.MD2, RSASignaturePaddingMode.PKCS1);

        /// <summary></summary>
        public static SignatureAlgorithmName MD5withRSA { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.MD5, RSASignaturePaddingMode.PKCS1);

        /// <summary></summary>
        public static SignatureAlgorithmName RIPEMD128withRSA { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.RIPEMD128, RSASignaturePaddingMode.PKCS1);

        /// <summary></summary>
        public static SignatureAlgorithmName RIPEMD160withRSA { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.RIPEMD160, RSASignaturePaddingMode.PKCS1);

        /// <summary></summary>
        public static SignatureAlgorithmName RIPEMD256withRSA { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.RIPEMD256, RSASignaturePaddingMode.PKCS1);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA1withRSA { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA1, RSASignaturePaddingMode.PKCS1);

        /// <summary>
        /// PSSwithRSA.
        /// </summary>
        public static SignatureAlgorithmName SHA1withRSAandMGF1 { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA1, RSASignaturePaddingMode.MGF1);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA224withRSA { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA224, RSASignaturePaddingMode.PKCS1);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA224withRSAandMGF1 { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA224, RSASignaturePaddingMode.MGF1);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA256withRSA { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA256, RSASignaturePaddingMode.PKCS1);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA256withRSAandMGF1 { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA256, RSASignaturePaddingMode.MGF1);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA3_224withRSA { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA3_224, RSASignaturePaddingMode.PKCS1);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA3_256withRSA { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA3_256, RSASignaturePaddingMode.PKCS1);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA3_384withRSA { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA3_384, RSASignaturePaddingMode.PKCS1);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA3_512withRSA { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA3_512, RSASignaturePaddingMode.PKCS1);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA384withRSA { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA384, RSASignaturePaddingMode.PKCS1);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA384withRSAandMGF1 { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA384, RSASignaturePaddingMode.MGF1);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA512_224withRSA { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA512_224, RSASignaturePaddingMode.PKCS1);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA512_256withRSA { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA512_256, RSASignaturePaddingMode.PKCS1);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA512withRSA { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA512, RSASignaturePaddingMode.PKCS1);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA512withRSAandMGF1 { get; } = RSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA512, RSASignaturePaddingMode.MGF1);

        #endregion RSA

        #region ECDSA

        /// <summary></summary>
        public static SignatureAlgorithmName RIPEMD160withPLAIN_ECDSA { get; } = ECDSA.GetSignatureAlgorithmName(HashAlgorithmName.RIPEMD160, ECDSASignatureExtension.Plain);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA1withCVC_ECDSA { get; } = ECDSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA1, ECDSASignatureExtension.CVC);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA1withECDSA { get; } = ECDSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA1, ECDSASignatureExtension.ECDSA);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA1withPLAIN_ECDSA { get; } = ECDSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA1, ECDSASignatureExtension.Plain);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA224withCVC_ECDSA { get; } = ECDSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA224, ECDSASignatureExtension.CVC);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA224withECDSA { get; } = ECDSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA224, ECDSASignatureExtension.ECDSA);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA224withPLAIN_ECDSA { get; } = ECDSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA224, ECDSASignatureExtension.Plain);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA256withCVC_ECDSA { get; } = ECDSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA256, ECDSASignatureExtension.CVC);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA256withECDSA { get; } = ECDSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA256, ECDSASignatureExtension.ECDSA);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA256withPLAIN_ECDSA { get; } = ECDSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA256, ECDSASignatureExtension.Plain);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA3_224withECDSA { get; } = ECDSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA3_224, ECDSASignatureExtension.ECDSA);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA3_256withECDSA { get; } = ECDSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA3_256, ECDSASignatureExtension.ECDSA);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA3_384withECDSA { get; } = ECDSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA3_384, ECDSASignatureExtension.ECDSA);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA3_512withECDSA { get; } = ECDSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA3_512, ECDSASignatureExtension.ECDSA);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA384withCVC_ECDSA { get; } = ECDSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA384, ECDSASignatureExtension.CVC);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA384withECDSA { get; } = ECDSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA384, ECDSASignatureExtension.ECDSA);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA384withPLAIN_ECDSA { get; } = ECDSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA384, ECDSASignatureExtension.Plain);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA512withCVC_ECDSA { get; } = ECDSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA512, ECDSASignatureExtension.CVC);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA512withECDSA { get; } = ECDSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA512, ECDSASignatureExtension.ECDSA);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA512withPLAIN_ECDSA { get; } = ECDSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA512, ECDSASignatureExtension.Plain);

        #endregion ECDSA

        #region DSA

        /// <summary></summary>
        public static SignatureAlgorithmName SHA1withDSA { get; } = DSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA1, DSASignatureEncodingMode.Standard);

        public static SignatureAlgorithmName SHA224withDSA { get; } = DSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA224, DSASignatureEncodingMode.Standard);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA256withDSA { get; } = DSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA256, DSASignatureEncodingMode.Standard);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA3_224withDSA { get; } = DSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA3_224, DSASignatureEncodingMode.Standard);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA3_256withDSA { get; } = DSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA3_256, DSASignatureEncodingMode.Standard);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA3_384withDSA { get; } = DSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA3_384, DSASignatureEncodingMode.Standard);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA3_512withDSA { get; } = DSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA3_512, DSASignatureEncodingMode.Standard);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA384withDSA { get; } = DSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA384, DSASignatureEncodingMode.Standard);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA512withDSA { get; } = DSA.GetSignatureAlgorithmName(HashAlgorithmName.SHA512, DSASignatureEncodingMode.Standard);

        #endregion DSA

        /// <summary></summary>
        public static SignatureAlgorithmName GOST3411withECGOST3410 { get; } = ECGOST3410.GetSignatureAlgorithmName(HashAlgorithmName.GOST3411);

        /// <summary></summary>
        public static SignatureAlgorithmName GOST3411withGOST3410 { get; } = GOST3410.GetSignatureAlgorithmName(HashAlgorithmName.GOST3411);

        /// <summary></summary>
        public static SignatureAlgorithmName SHA256withSM2 { get; } = SM2.GetSignatureAlgorithmName(HashAlgorithmName.SHA256);

        /// <summary></summary>
        public static SignatureAlgorithmName SM3withSM2 { get; } = SM2.GetSignatureAlgorithmName(HashAlgorithmName.SM3);

        #region Properties

        private readonly string _asn1Algorithm;
        private readonly GetAlgorithmCallback _getAlgorithm;
        private readonly string _name;
        private readonly string _oid;

        /// <summary>
        /// Gets this algorithm's name.
        /// </summary>
        public string Name => _name;

        /// <summary>
        /// Gets this algorithm's oid.
        /// </summary>
        public string Oid => _oid;

        internal string Asn1Algorithm => _asn1Algorithm;
        internal GetAlgorithmCallback GetAlgorithm => _getAlgorithm;

        #endregion Properties

        #region Construction

        internal SignatureAlgorithmName(string name, GetAlgorithmCallback getAlgorithm)
        {
            _name = name;
            DerObjectIdentifier oid = GetOid(name);
            _oid = oid == null ? string.Empty : oid.Id;
            _asn1Algorithm = GetAsn1AlgorithmName(name, oid);
            _getAlgorithm = getAlgorithm;
        }

        #endregion Construction

        /// <summary>
        /// Gets all algorithm names of the storage.
        /// </summary>
        /// <returns></returns>
        public static SignatureAlgorithmName[] GetNames()
        {
            return new SignatureAlgorithmName[]
            {
                SHA1withECDSA,
                SHA224withECDSA,
                SHA256withECDSA,
                SHA384withECDSA,
                SHA512withECDSA,
                SHA3_224withECDSA,
                SHA3_256withECDSA,
                SHA3_384withECDSA,
                SHA3_512withECDSA,

                SHA1withCVC_ECDSA,
                SHA224withCVC_ECDSA,
                SHA256withCVC_ECDSA,
                SHA384withCVC_ECDSA,
                SHA512withCVC_ECDSA,

                SHA1withPLAIN_ECDSA,
                SHA224withPLAIN_ECDSA,
                SHA256withPLAIN_ECDSA,
                SHA384withPLAIN_ECDSA,
                SHA512withPLAIN_ECDSA,
                RIPEMD160withPLAIN_ECDSA,

                SHA1withRSAandMGF1,
                SHA224withRSAandMGF1,
                SHA256withRSAandMGF1,
                SHA384withRSAandMGF1,
                SHA512withRSAandMGF1,

                MD2withRSA,
                MD5withRSA,
                RIPEMD128withRSA,
                RIPEMD160withRSA,
                RIPEMD256withRSA,
                SHA1withRSA,
                SHA224withRSA,
                SHA256withRSA,
                SHA384withRSA,
                SHA512withRSA,
                SHA3_224withRSA,
                SHA3_256withRSA,
                SHA3_384withRSA,
                SHA3_512withRSA,

                SHA512_224withRSA,
                SHA512_256withRSA,

                SHA1withDSA,
                SHA224withDSA,
                SHA256withDSA,
                SHA384withDSA,
                SHA512withDSA,
                SHA3_224withDSA,
                SHA3_256withDSA,
                SHA3_384withDSA,
                SHA3_512withDSA,

                GOST3411withGOST3410,

                GOST3411withECGOST3410,

                SHA256withSM2,
                SM3withSM2,
            };
        }

        /// <summary>
        /// Try get algorithm name from mechanism.
        /// </summary>
        /// <param name="mechanism">Algorithm mechanism.</param>
        /// <param name="algorithmName">Algorithm name.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithmName(string mechanism, out SignatureAlgorithmName algorithmName)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                algorithmName = null;
                return false;
            }
            mechanism = mechanism.Trim().Replace('_', '-').Replace('/', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "1.2.840.10045.4.1": case "SHA1WITHECDSA": case "SHA-1WITHECDSA": algorithmName = SHA1withECDSA; return true;
                case "1.2.840.10045.4.3.1": case "SHA224WITHECDSA": case "SHA-224WITHECDSA": algorithmName = SHA224withECDSA; return true;
                case "1.2.840.10045.4.3.2": case "SHA256WITHECDSA": case "SHA-256WITHECDSA": algorithmName = SHA256withECDSA; return true;
                case "1.2.840.10045.4.3.3": case "SHA384WITHECDSA": case "SHA-384WITHECDSA": algorithmName = SHA384withECDSA; return true;
                case "1.2.840.10045.4.3.4": case "SHA512WITHECDSA": case "SHA-512WITHECDSA": algorithmName = SHA512withECDSA; return true;
                case "2.16.840.1.101.3.4.3.9": case "SHA3-224WITHECDSA": case "SHA-3-224WITHECDSA": algorithmName = SHA3_224withECDSA; return true;
                case "2.16.840.1.101.3.4.3.10": case "SHA3-256WITHECDSA": case "SHA-3-256WITHECDSA": algorithmName = SHA3_256withECDSA; return true;
                case "2.16.840.1.101.3.4.3.11": case "SHA3-384WITHECDSA": case "SHA-3-384WITHECDSA": algorithmName = SHA3_384withECDSA; return true;
                case "2.16.840.1.101.3.4.3.12": case "SHA3-512WITHECDSA": case "SHA-3-512WITHECDSA": algorithmName = SHA3_512withECDSA; return true;

                case "0.4.0.127.0.7.2.2.2.2.1": case "SHA1WITHCVC-ECDSA": case "SHA-1WITHCVC-ECDSA": algorithmName = SHA1withCVC_ECDSA; return true;
                case "0.4.0.127.0.7.2.2.2.2.2": case "SHA224WITHCVC-ECDSA": case "SHA-224WITHCVC-ECDSA": algorithmName = SHA224withCVC_ECDSA; return true;
                case "0.4.0.127.0.7.2.2.2.2.3": case "SHA256WITHCVC-ECDSA": case "SHA-256WITHCVC-ECDSA": algorithmName = SHA256withCVC_ECDSA; return true;
                case "0.4.0.127.0.7.2.2.2.2.4": case "SHA384WITHCVC-ECDSA": case "SHA-384WITHCVC-ECDSA": algorithmName = SHA384withCVC_ECDSA; return true;
                case "0.4.0.127.0.7.2.2.2.2.5": case "SHA512WITHCVC-ECDSA": case "SHA-512WITHCVC-ECDSA": algorithmName = SHA512withCVC_ECDSA; return true;

                case "0.4.0.127.0.7.1.1.4.1.1": case "SHA1WITHPLAIN-ECDSA": case "SHA-1WITHPLAIN-ECDSA": algorithmName = SHA1withPLAIN_ECDSA; return true;
                case "0.4.0.127.0.7.1.1.4.1.2": case "SHA224WITHPLAIN-ECDSA": case "SHA-224WITHPLAIN-ECDSA": algorithmName = SHA224withPLAIN_ECDSA; return true;
                case "0.4.0.127.0.7.1.1.4.1.3": case "SHA256WITHPLAIN-ECDSA": case "SHA-256WITHPLAIN-ECDSA": algorithmName = SHA256withPLAIN_ECDSA; return true;
                case "0.4.0.127.0.7.1.1.4.1.4": case "SHA384WITHPLAIN-ECDSA": case "SHA-384WITHPLAIN-ECDSA": algorithmName = SHA384withPLAIN_ECDSA; return true;
                case "0.4.0.127.0.7.1.1.4.1.5": case "SHA512WITHPLAIN-ECDSA": case "SHA-512WITHPLAIN-ECDSA": algorithmName = SHA512withPLAIN_ECDSA; return true;
                case "0.4.0.127.0.7.1.1.4.1.6": case "RIPEMD160WITHPLAIN-ECDSA": case "RIPEMD-160WITHPLAIN-ECDSA": algorithmName = RIPEMD160withPLAIN_ECDSA; return true;

                case "1.2.840.113549.1.1.10": case "PSSWITHRSA": case "SHA1WITHRSAANDMGF1": case "SHA-1WITHRSAANDMGF1": algorithmName = SHA1withRSAandMGF1; return true;
                case "SHA224WITHRSAANDMGF1": case "SHA-224WITHRSAANDMGF1": algorithmName = SHA224withRSAandMGF1; return true;
                case "SHA256WITHRSAANDMGF1": case "SHA-256WITHRSAANDMGF1": algorithmName = SHA256withRSAandMGF1; return true;
                case "SHA384WITHRSAANDMGF1": case "SHA-384WITHRSAANDMGF1": algorithmName = SHA384withRSAandMGF1; return true;
                case "SHA512WITHRSAANDMGF1": case "SHA-512WITHRSAANDMGF1": algorithmName = SHA512withRSAandMGF1; return true;

                case "1.2.840.113549.1.1.2": case "MD2WITHRSA": algorithmName = MD2withRSA; return true;
                case "1.2.840.113549.1.1.4": case "MD5WITHRSA": algorithmName = MD5withRSA; return true;
                case "1.3.36.3.3.1.3": case "RIPEMD128WITHRSA": case "RIPEMD-128WITHRSA": algorithmName = RIPEMD128withRSA; return true;
                case "1.3.36.3.3.1.2": case "RIPEMD160WITHRSA": case "RIPEMD-160WITHRSA": algorithmName = RIPEMD160withRSA; return true;
                case "1.3.36.3.3.1.4": case "RIPEMD256WITHRSA": case "RIPEMD-256WITHRSA": algorithmName = RIPEMD256withRSA; return true;
                case "1.2.840.113549.1.1.5": case "SHA1WITHRSA": case "SHA-1WITHRSA": algorithmName = SHA1withRSA; return true;
                case "1.2.840.113549.1.1.14": case "SHA224WITHRSA": case "SHA-224WITHRSA": algorithmName = SHA224withRSA; return true;
                case "1.2.840.113549.1.1.11": case "SHA256WITHRSA": case "SHA-256WITHRSA": algorithmName = SHA256withRSA; return true;
                case "1.2.840.113549.1.1.12": case "SHA384WITHRSA": case "SHA-384WITHRSA": algorithmName = SHA384withRSA; return true;
                case "1.2.840.113549.1.1.13": case "SHA512WITHRSA": case "SHA-512WITHRSA": algorithmName = SHA512withRSA; return true;
                case "2.16.840.1.101.3.4.3.13": case "SHA3-224WITHRSA": case "SHA-3-224WITHRSA": algorithmName = SHA3_224withRSA; return true;
                case "2.16.840.1.101.3.4.3.14": case "SHA3-256WITHRSA": case "SHA-3-256WITHRSA": algorithmName = SHA3_256withRSA; return true;
                case "2.16.840.1.101.3.4.3.15": case "SHA3-384WITHRSA": case "SHA-3-384WITHRSA": algorithmName = SHA3_384withRSA; return true;
                case "2.16.840.1.101.3.4.3.16": case "SHA3-512WITHRSA": case "SHA-3-512WITHRSA": algorithmName = SHA3_512withRSA; return true;

                case "1.2.840.113549.1.1.15": case "SHA512-224WITHRSA": case "SHA-512-224WITHRSA": algorithmName = SHA512_224withRSA; return true;
                case "1.2.840.113549.1.1.16": case "SHA512-256WITHRSA": case "SHA-512-256WITHRSA": algorithmName = SHA512_256withRSA; return true;

                case "1.2.840.10040.4.3": case "SHA1WITHDSA": case "SHA-1WITHDSA": algorithmName = SHA1withDSA; return true;
                case "2.16.840.1.101.3.4.3.1": case "SHA224WITHDSA": case "SHA-224WITHDSA": algorithmName = SHA224withDSA; return true;
                case "2.16.840.1.101.3.4.3.2": case "SHA256WITHDSA": case "SHA-256WITHDSA": algorithmName = SHA256withDSA; return true;
                case "2.16.840.1.101.3.4.3.3": case "SHA384WITHDSA": case "SHA-384WITHDSA": algorithmName = SHA384withDSA; return true;
                case "2.16.840.1.101.3.4.3.4": case "SHA512WITHDSA": case "SHA-512WITHDSA": algorithmName = SHA512withDSA; return true;
                case "2.16.840.1.101.3.4.3.5": case "SHA3-224WITHDSA": case "SHA-3-224WITHDSA": algorithmName = SHA3_224withDSA; return true;
                case "2.16.840.1.101.3.4.3.6": case "SHA3-256WITHDSA": case "SHA-3-256WITHDSA": algorithmName = SHA3_256withDSA; return true;
                case "2.16.840.1.101.3.4.3.7": case "SHA3-384WITHDSA": case "SHA-3-384WITHDSA": algorithmName = SHA3_384withDSA; return true;
                case "2.16.840.1.101.3.4.3.8": case "SHA3-512WITHDSA": case "SHA-3-512WITHDSA": algorithmName = SHA3_512withDSA; return true;

                case "1.2.643.2.2.4": case "GOST3411WITHGOST3410": case "GOST3410": case "GOST3410-94": algorithmName = GOST3411withGOST3410; return true;

                case "1.2.643.2.2.3": case "GOST3411WITHECGOST3410": case "ECGOST3410": case "ECGOST3410-2001": algorithmName = GOST3411withECGOST3410; return true;

                case "1.2.156.10197.1.503": case "SHA256WITHSM2": case "SHA-256WITHSM2": algorithmName = SHA256withSM2; return true;
                case "1.2.156.10197.1.501": case "SM3WITHSM2": algorithmName = SM3withSM2; return true;

                case "ED25519": algorithmName = Ed25519.GetSignatureAlgorithmName(Ed25519SignatureInstance.Ed25519); return true;
                case "ED25519CTX": algorithmName = Ed25519.GetSignatureAlgorithmName(Ed25519SignatureInstance.Ed25519ctx); return true;
                case "ED25519PH": algorithmName = Ed25519.GetSignatureAlgorithmName(Ed25519SignatureInstance.Ed25519ph); return true;
                case "ED448": algorithmName = Ed448.GetSignatureAlgorithmName(Ed448SignatureInstance.Ed448); return true;
                case "ED448PH": algorithmName = Ed448.GetSignatureAlgorithmName(Ed448SignatureInstance.Ed448ph); return true;

                default: break;
            }
            string prefix;
            string suffix;
            int index = mechanism.IndexOf("WITH");
            if (index >= 0)
            {
                prefix = mechanism.Substring(0, index);
                suffix = mechanism.Substring(index + 4, mechanism.Length - index - 4);
                if (suffix != "ELGAMAL")
                {
                    if (HashAlgorithmName.TryGetAlgorithmName(prefix, out HashAlgorithmName hashAlgorithmName))
                    {
                        switch (suffix)
                        {
                            case "DSA":
                                algorithmName = DSA.GetSignatureAlgorithmName(hashAlgorithmName, DSASignatureEncodingMode.Standard);
                                return true;

                            case "ECDSA":
                                algorithmName = ECDSA.GetSignatureAlgorithmName(hashAlgorithmName, ECDSASignatureExtension.ECDSA);
                                return true;

                            case "ECNR":
                                algorithmName = ECDSA.GetSignatureAlgorithmName(hashAlgorithmName, ECDSASignatureExtension.ECNR);
                                return true;

                            case "CVC-ECDSA":
                                algorithmName = ECDSA.GetSignatureAlgorithmName(hashAlgorithmName, ECDSASignatureExtension.CVC);
                                return true;

                            case "PLAIN-ECDSA":
                                algorithmName = ECDSA.GetSignatureAlgorithmName(hashAlgorithmName, ECDSASignatureExtension.Plain);
                                return true;

                            case "RSA":
                                algorithmName = RSA.GetSignatureAlgorithmName(hashAlgorithmName, RSASignaturePaddingMode.PKCS1);
                                return true;

                            case "RSA/ISO9796-2":
                            case "RSAANDISO9796-2":
                            case "ISO9796-2":
                                algorithmName = RSA.GetSignatureAlgorithmName(hashAlgorithmName, RSASignaturePaddingMode.ISO9796_2);
                                return true;

                            case "RSAANDMGF1":
                                algorithmName = RSA.GetSignatureAlgorithmName(hashAlgorithmName, RSASignaturePaddingMode.MGF1);
                                return true;

                            case "RSA/X9.31":
                            case "RSA/X931":
                            case "RSAANDX931":
                            case "RSAANDX9.31":
                                algorithmName = RSA.GetSignatureAlgorithmName(hashAlgorithmName, RSASignaturePaddingMode.X931);
                                return true;

                            case "ECGOST3410":
                            case "ECGOST3410-2001":
                                algorithmName = ECGOST3410.GetSignatureAlgorithmName(hashAlgorithmName);
                                return true;

                            case "GOST3410":
                            case "GOST3410-94":
                                algorithmName = GOST3410.GetSignatureAlgorithmName(hashAlgorithmName);
                                return true;

                            case "SM2": algorithmName = SM2.GetSignatureAlgorithmName(hashAlgorithmName); return true;

                            default: break;
                        }
                    }
                }
            }
            algorithmName = null;
            return false;
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(SignatureAlgorithmName other)
        {
            return other._name.Equals(_name);
        }

        /// <summary>
        /// Return algorithm name.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return _name;
        }

        private static string GetAsn1AlgorithmName(string name, DerObjectIdentifier oid)
        {
            switch (name.ToUpperInvariant())
            {
                case "SHA1WITHRSAANDMGF1": return name;
                case "SHA224WITHRSAANDMGF1": return name;
                case "SHA256WITHRSAANDMGF1": return name;
                case "SHA384WITHRSAANDMGF1": return name;
                case "SHA512WITHRSAANDMGF1": return name;
                default: return oid == null ? name : oid.Id;
            }
        }

        private static DerObjectIdentifier GetOid(string mechanism)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                return null;
            }
            mechanism = mechanism.Trim().Replace('_', '-').Replace('/', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "1.2.840.10045.4.1": case "SHA1WITHECDSA": case "SHA-1WITHECDSA": return X9ObjectIdentifiers.ECDsaWithSha1;
                case "1.2.840.10045.4.3.1": case "SHA224WITHECDSA": case "SHA-224WITHECDSA": return X9ObjectIdentifiers.ECDsaWithSha224;
                case "1.2.840.10045.4.3.2": case "SHA256WITHECDSA": case "SHA-256WITHECDSA": return X9ObjectIdentifiers.ECDsaWithSha256;
                case "1.2.840.10045.4.3.3": case "SHA384WITHECDSA": case "SHA-384WITHECDSA": return X9ObjectIdentifiers.ECDsaWithSha384;
                case "1.2.840.10045.4.3.4": case "SHA512WITHECDSA": case "SHA-512WITHECDSA": return X9ObjectIdentifiers.ECDsaWithSha512;
                case "2.16.840.1.101.3.4.3.9": case "SHA3-224WITHECDSA": case "SHA-3-224WITHECDSA": return NistObjectIdentifiers.IdEcdsaWithSha3_224;
                case "2.16.840.1.101.3.4.3.10": case "SHA3-256WITHECDSA": case "SHA-3-256WITHECDSA": return NistObjectIdentifiers.IdEcdsaWithSha3_256;
                case "2.16.840.1.101.3.4.3.11": case "SHA3-384WITHECDSA": case "SHA-3-384WITHECDSA": return NistObjectIdentifiers.IdEcdsaWithSha3_384;
                case "2.16.840.1.101.3.4.3.12": case "SHA3-512WITHECDSA": case "SHA-3-512WITHECDSA": return NistObjectIdentifiers.IdEcdsaWithSha3_512;

                case "0.4.0.127.0.7.2.2.2.2.1": case "SHA1WITHCVC-ECDSA": case "SHA-1WITHCVC-ECDSA": return EacObjectIdentifiers.id_TA_ECDSA_SHA_1;
                case "0.4.0.127.0.7.2.2.2.2.2": case "SHA224WITHCVC-ECDSA": case "SHA-224WITHCVC-ECDSA": return EacObjectIdentifiers.id_TA_ECDSA_SHA_224;
                case "0.4.0.127.0.7.2.2.2.2.3": case "SHA256WITHCVC-ECDSA": case "SHA-256WITHCVC-ECDSA": return EacObjectIdentifiers.id_TA_ECDSA_SHA_256;
                case "0.4.0.127.0.7.2.2.2.2.4": case "SHA384WITHCVC-ECDSA": case "SHA-384WITHCVC-ECDSA": return EacObjectIdentifiers.id_TA_ECDSA_SHA_384;
                case "0.4.0.127.0.7.2.2.2.2.5": case "SHA512WITHCVC-ECDSA": case "SHA-512WITHCVC-ECDSA": return EacObjectIdentifiers.id_TA_ECDSA_SHA_512;

                case "0.4.0.127.0.7.1.1.4.1.1": case "SHA1WITHPLAIN-ECDSA": case "SHA-1WITHPLAIN-ECDSA": return BsiObjectIdentifiers.ecdsa_plain_SHA1;
                case "0.4.0.127.0.7.1.1.4.1.2": case "SHA224WITHPLAIN-ECDSA": case "SHA-224WITHPLAIN-ECDSA": return BsiObjectIdentifiers.ecdsa_plain_SHA224;
                case "0.4.0.127.0.7.1.1.4.1.3": case "SHA256WITHPLAIN-ECDSA": case "SHA-256WITHPLAIN-ECDSA": return BsiObjectIdentifiers.ecdsa_plain_SHA256;
                case "0.4.0.127.0.7.1.1.4.1.4": case "SHA384WITHPLAIN-ECDSA": case "SHA-384WITHPLAIN-ECDSA": return BsiObjectIdentifiers.ecdsa_plain_SHA384;
                case "0.4.0.127.0.7.1.1.4.1.5": case "SHA512WITHPLAIN-ECDSA": case "SHA-512WITHPLAIN-ECDSA": return BsiObjectIdentifiers.ecdsa_plain_SHA512;
                case "0.4.0.127.0.7.1.1.4.1.6": case "RIPEMD160WITHPLAIN-ECDSA": case "RIPEMD-160WITHPLAIN-ECDSA": return BsiObjectIdentifiers.ecdsa_plain_RIPEMD160;

                case "1.2.840.113549.1.1.10": case "PSSWITHRSA": case "SHA1WITHRSAANDMGF1": case "SHA-1WITHRSAANDMGF1": return PkcsObjectIdentifiers.IdRsassaPss;
                case "SHA224WITHRSAANDMGF1": case "SHA-224WITHRSAANDMGF1": return PkcsObjectIdentifiers.IdRsassaPss;
                case "SHA256WITHRSAANDMGF1": case "SHA-256WITHRSAANDMGF1": return PkcsObjectIdentifiers.IdRsassaPss;
                case "SHA384WITHRSAANDMGF1": case "SHA-384WITHRSAANDMGF1": return PkcsObjectIdentifiers.IdRsassaPss;
                case "SHA512WITHRSAANDMGF1": case "SHA-512WITHRSAANDMGF1": return PkcsObjectIdentifiers.IdRsassaPss;

                case "1.2.840.113549.1.1.2": case "MD2WITHRSA": return PkcsObjectIdentifiers.MD2WithRsaEncryption;
                case "1.2.840.113549.1.1.4": case "MD5WITHRSA": return PkcsObjectIdentifiers.MD5WithRsaEncryption;
                case "1.3.36.3.3.1.3": case "RIPEMD128WITHRSA": case "RIPEMD-128WITHRSA": return TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128;
                case "1.3.36.3.3.1.2": case "RIPEMD160WITHRSA": case "RIPEMD-160WITHRSA": return TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160;
                case "1.3.36.3.3.1.4": case "RIPEMD256WITHRSA": case "RIPEMD-256WITHRSA": return TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256;
                case "1.2.840.113549.1.1.5": case "SHA1WITHRSA": case "SHA-1WITHRSA": return PkcsObjectIdentifiers.Sha1WithRsaEncryption;
                case "1.2.840.113549.1.1.14": case "SHA224WITHRSA": case "SHA-224WITHRSA": return PkcsObjectIdentifiers.Sha224WithRsaEncryption;
                case "1.2.840.113549.1.1.11": case "SHA256WITHRSA": case "SHA-256WITHRSA": return PkcsObjectIdentifiers.Sha256WithRsaEncryption;
                case "1.2.840.113549.1.1.12": case "SHA384WITHRSA": case "SHA-384WITHRSA": return PkcsObjectIdentifiers.Sha384WithRsaEncryption;
                case "1.2.840.113549.1.1.13": case "SHA512WITHRSA": case "SHA-512WITHRSA": return PkcsObjectIdentifiers.Sha512WithRsaEncryption;
                case "2.16.840.1.101.3.4.3.13": case "SHA3-224WITHRSA": case "SHA-3-224WITHRSA": return NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224;
                case "2.16.840.1.101.3.4.3.14": case "SHA3-256WITHRSA": case "SHA-3-256WITHRSA": return NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256;
                case "2.16.840.1.101.3.4.3.15": case "SHA3-384WITHRSA": case "SHA-3-384WITHRSA": return NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384;
                case "2.16.840.1.101.3.4.3.16": case "SHA3-512WITHRSA": case "SHA-3-512WITHRSA": return NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512;

                case "1.2.840.113549.1.1.15": case "SHA512-224WITHRSA": case "SHA-512-224WITHRSA": return PkcsObjectIdentifiers.Sha512_224WithRSAEncryption;
                case "1.2.840.113549.1.1.16": case "SHA512-256WITHRSA": case "SHA-512-256WITHRSA": return PkcsObjectIdentifiers.Sha512_256WithRSAEncryption;

                case "1.2.840.10040.4.3": case "SHA1WITHDSA": case "SHA-1WITHDSA": return X9ObjectIdentifiers.IdDsaWithSha1;
                case "2.16.840.1.101.3.4.3.1": case "SHA224WITHDSA": case "SHA-224WITHDSA": return NistObjectIdentifiers.DsaWithSha224;
                case "2.16.840.1.101.3.4.3.2": case "SHA256WITHDSA": case "SHA-256WITHDSA": return NistObjectIdentifiers.DsaWithSha256;
                case "2.16.840.1.101.3.4.3.3": case "SHA384WITHDSA": case "SHA-384WITHDSA": return NistObjectIdentifiers.DsaWithSha384;
                case "2.16.840.1.101.3.4.3.4": case "SHA512WITHDSA": case "SHA-512WITHDSA": return NistObjectIdentifiers.DsaWithSha512;
                case "2.16.840.1.101.3.4.3.5": case "SHA3-224WITHDSA": case "SHA-3-224WITHDSA": return NistObjectIdentifiers.IdDsaWithSha3_224;
                case "2.16.840.1.101.3.4.3.6": case "SHA3-256WITHDSA": case "SHA-3-256WITHDSA": return NistObjectIdentifiers.IdDsaWithSha3_256;
                case "2.16.840.1.101.3.4.3.7": case "SHA3-384WITHDSA": case "SHA-3-384WITHDSA": return NistObjectIdentifiers.IdDsaWithSha3_384;
                case "2.16.840.1.101.3.4.3.8": case "SHA3-512WITHDSA": case "SHA-3-512WITHDSA": return NistObjectIdentifiers.IdDsaWithSha3_512;

                case "1.2.643.2.2.4": case "GOST3411WITHGOST3410": case "GOST3410": case "GOST3410-94": return CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94;

                case "1.2.643.2.2.3": case "GOST3411WITHECGOST3410": case "ECGOST3410": case "ECGOST3410-2001": return CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001;

                case "1.2.156.10197.1.503": case "SHA256WITHSM2": case "SHA-256WITHSM2": return GMObjectIdentifiers.sm2sign_with_sha256;
                case "1.2.156.10197.1.501": case "SM3WITHSM2": return GMObjectIdentifiers.sm2sign_with_sm3;

                default: return null;
            }
        }
    }
}