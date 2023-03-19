using Org.BouncyCastle.Asn1.Anssi;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using System.IO;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class ECDSA : AsymmetricAlgorithm
    {
        #region Properties

        private HashAlgorithmName _hashAlgorithm = HashAlgorithmName.SHA256;
        private bool _initialized = false;
        private AsymmetricKeyParameter _privateKey = null;
        private AsymmetricKeyParameter _publicKey = null;
        private ECDSASignatureExtension _signatureExtension = ECDSASignatureExtension.ECDSA;
        private ISigner _signer = null;
        private ISigner _verifier = null;

        /// <summary>
        /// Get or set Hash algorithm for signature.
        /// </summary>
        public HashAlgorithmName HashAlgorithm
        {
            get => _hashAlgorithm;
            set
            {
                if (value != _hashAlgorithm)
                {
                    _hashAlgorithm = value ?? throw new CryptographicException("This parameter can't be null.");
                    _signer = null;
                    _verifier = null;
                }
            }
        }

        /// <summary>
        /// Gets signature algorithm name.
        /// </summary>
        public string SignatureAlgorithm
        {
            get
            {
                string suffix;
                switch (_signatureExtension)
                {
                    case ECDSASignatureExtension.ECDSA: suffix = "ECDSA"; break;
                    case ECDSASignatureExtension.ECNR: suffix = "ECNR"; break;
                    case ECDSASignatureExtension.Plain: suffix = "PLAIN-ECDSA"; break;
                    case ECDSASignatureExtension.CVC: suffix = "CVC-ECDSA"; break;
                    default: throw new CryptographicException("Unsupported signature extension.");
                }
                return $"{_hashAlgorithm.Name}with{suffix}";
            }
        }

        /// <summary>
        /// Represents the signature extension used in the symmetric algorithm.
        /// </summary>
        public ECDSASignatureExtension SignatureExtension
        {
            get => _signatureExtension;
            set
            {
                if (value != _signatureExtension)
                {
                    _signer = null;
                    _verifier = null;
                    _signatureExtension = value;
                }
            }
        }

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the ECDSA class.
        /// </summary>
        public ECDSA() : base("ECDSA", AsymmetricAlgorithmKind.Signature)
        {
        }

        #endregion Construction

        /// <summary>
        /// Exports a pem string containing the asymmetric algorithm key information associated.
        /// </summary>
        /// <param name="includePrivate">true to include the private key; otherwise, false.</param>
        /// <returns></returns>
        public string ExportPem(bool includePrivate)
        {
            InspectKey();
            AsymmetricKeyParameter asymmetricKey = includePrivate ? _privateKey : _publicKey;
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(asymmetricKey);
                return writer.ToString();
            }
        }

        /// <summary>
        /// Exports a pem string containing the asymmetric algorithm private key information associated.
        /// </summary>
        /// <param name="dekAlgorithmName">DEK algorithm name.</param>
        /// <param name="password"></param>
        /// <returns></returns>
        public string ExportPem(DEKAlgorithmName dekAlgorithmName, string password)
        {
            InspectKey();
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(_privateKey, dekAlgorithmName.Name, password.ToCharArray(), Common.SecureRandom);
                return writer.ToString();
            }
        }

        /// <summary>
        /// Renew private key and public key of the algorithm.
        /// </summary>
        /// <param name="ellipticCurve">Elliptic curve to be uesd.</param>
        public void GenerateKeyPair(EllipticCurve ellipticCurve = EllipticCurve.Prime256v1)
        {
            X9ECParameters x9Parameters = GenerateX9(ellipticCurve);
            ECDomainParameters domainParameters = new ECDomainParameters(x9Parameters);
            ECKeyGenerationParameters generationParameters = new ECKeyGenerationParameters(domainParameters, Common.SecureRandom);
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.Init(generationParameters);
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
            _privateKey = keyPair.Private;
            _publicKey = keyPair.Public;
            _initialized = true;
            _signer = null;
            _verifier = null;
        }

        /// <summary>
        /// Imports a pem string that represents asymmetric algorithm key information.
        /// </summary>
        /// <param name="pem">A pem string that represents an asymmetric algorithm key.</param>
        public void ImportPem(string pem)
        {
            using (StringReader reader = new StringReader(pem))
            {
                object obj = new PemReader(reader).ReadObject();
                if (obj.GetType() == typeof(AsymmetricCipherKeyPair))
                {
                    AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)obj;
                    _privateKey = (ECPrivateKeyParameters)keyPair.Private;
                    _publicKey = keyPair.Public;
                }
                else
                {
                    _privateKey = null;
                    _publicKey = (ECPublicKeyParameters)obj;
                }
                _initialized = true;
                _signer = null;
                _verifier = null;
            }
        }

        /// <summary>
        /// Imports a pem string that represents asymmetric algorithm private key information.
        /// </summary>
        /// <param name="pem">A pem string that represents an asymmetric algorithm private key.</param>
        /// <param name="password"></param>
        public void ImportPem(string pem, string password)
        {
            using (StringReader reader = new StringReader(pem))
            {
                object obj = new PemReader(reader, new Password(password)).ReadObject();
                AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)obj;
                _privateKey = (ECPrivateKeyParameters)keyPair.Private;
                _publicKey = keyPair.Public;
                _initialized = true;
                _signer = null;
                _verifier = null;
            }
        }

        /// <summary>
        /// Signs the specified input bytes using the specified hash algorithm.
        /// </summary>
        /// <returns></returns>
        public byte[] SignFinal()
        {
            InspectKey();
            InspectSigner(true);
            return _signer.GenerateSignature();
        }

        /// <summary>
        /// Signs the specified input bytes using the specified hash algorithm.
        /// </summary>
        /// <param name="rgb">The input data for which to sign.</param>
        /// <returns></returns>
        public byte[] SignFinal(byte[] rgb)
        {
            return SignFinal(rgb, 0, rgb.Length);
        }

        /// <summary>
        /// Signs the specified input bytes using the specified hash algorithm.
        /// </summary>
        /// <param name="buffer">The data buffer.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        public byte[] SignFinal(byte[] buffer, int offset, int length)
        {
            InspectKey();
            InspectSigner(true);
            _signer.BlockUpdate(buffer, offset, length);
            return _signer.GenerateSignature();
        }

        /// <summary>
        /// Signs the specified input bytes using the specified hash algorithm.
        /// </summary>
        /// <param name="buffer">The data buffer.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        public void SignUpdate(byte[] buffer, int offset, int length)
        {
            InspectKey();
            InspectSigner(true);
            _signer.BlockUpdate(buffer, offset, length);
        }

        /// <summary>
        /// Verifies that a digital signature of the specified input bytes using the specified hash algorithm.
        /// </summary>
        /// <param name="signature">The signature data to be verified.</param>
        /// <returns></returns>
        public bool VerifyFinal(byte[] signature)
        {
            InspectKey();
            InspectSigner(false);
            return _verifier.VerifySignature(signature);
        }

        /// <summary>
        /// Verifies that a digital signature of the specified input bytes using the specified hash algorithm.
        /// </summary>
        /// <param name="rgb">The input data for which to compute the hash.</param>
        /// <param name="signature">The signature data to be verified.</param>
        /// <returns></returns>
        public bool VerifyFinal(byte[] rgb, byte[] signature)
        {
            return VerifyFinal(rgb, 0, rgb.Length, signature);
        }

        /// <summary>
        /// Verifies that a digital signature of the specified input bytes using the specified hash algorithm.
        /// </summary>
        /// <param name="buffer">The data buffer.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <param name="signature">The signature data to be verified.</param>
        /// <returns></returns>
        public bool VerifyFinal(byte[] buffer, int offset, int length, byte[] signature)
        {
            InspectKey();
            InspectSigner(false);
            _verifier.BlockUpdate(buffer, offset, length);
            return _verifier.VerifySignature(signature);
        }

        /// <summary>
        /// Verifies that a digital signature of the specified input bytes using the specified hash algorithm.
        /// </summary>
        /// <param name="buffer">The data buffer.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        public void VerifyUpdate(byte[] buffer, int offset, int length)
        {
            InspectKey();
            InspectSigner(false);
            _verifier.BlockUpdate(buffer, offset, length);
        }

        internal static AsymmetricAlgorithmName GetAlgorithmName()
        {
            return new AsymmetricAlgorithmName("ECDSA", AsymmetricAlgorithmKind.Signature, () => { return new ECDSA(); });
        }

        private static X9ECParameters GenerateX9(EllipticCurve ellipticCurve)
        {
            switch (ellipticCurve)
            {
                case EllipticCurve.Prime192v1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.Prime192v1);
                case EllipticCurve.Prime192v2: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.Prime192v2);
                case EllipticCurve.Prime192v3: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.Prime192v3);
                case EllipticCurve.Prime239v1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.Prime239v1);
                case EllipticCurve.Prime239v2: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.Prime239v2);
                case EllipticCurve.Prime239v3: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.Prime239v3);
                case EllipticCurve.Prime256v1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.Prime256v1);
                case EllipticCurve.C2Pnb163v1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Pnb163v1);
                case EllipticCurve.C2Pnb163v2: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Pnb163v2);
                case EllipticCurve.C2Pnb163v3: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Pnb163v3);
                case EllipticCurve.C2Pnb176w1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Pnb176w1);
                case EllipticCurve.C2Tnb191v1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Tnb191v1);
                case EllipticCurve.C2Tnb191v2: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Tnb191v2);
                case EllipticCurve.C2Tnb191v3: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Tnb191v3);
                case EllipticCurve.C2Pnb208w1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Pnb208w1);
                case EllipticCurve.C2Tnb239v1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Tnb239v1);
                case EllipticCurve.C2Tnb239v2: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Tnb239v2);
                case EllipticCurve.C2Tnb239v3: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Tnb239v3);
                case EllipticCurve.C2Pnb272w1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Pnb272w1);
                case EllipticCurve.C2Pnb304w1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Pnb304w1);
                case EllipticCurve.C2Tnb359v1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Tnb359v1);
                case EllipticCurve.C2Pnb368w1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Pnb368w1);
                case EllipticCurve.C2Tnb431r1: return X962NamedCurves.GetByOid(X9ObjectIdentifiers.C2Tnb431r1);

                case EllipticCurve.SecP112r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP112r1);
                case EllipticCurve.SecP112r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP112r2);
                case EllipticCurve.SecP128r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP128r1);
                case EllipticCurve.SecP128r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP128r2);
                case EllipticCurve.SecP160k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP160k1);
                case EllipticCurve.SecP160r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP160r1);
                case EllipticCurve.SecP160r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP160r2);
                case EllipticCurve.SecP192k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP192k1);
                case EllipticCurve.SecP192r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP192r1);
                case EllipticCurve.SecP224k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP224k1);
                case EllipticCurve.SecP224r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP224r1);
                case EllipticCurve.SecP256k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP256k1);
                case EllipticCurve.SecP256r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP256r1);
                case EllipticCurve.SecP384r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP384r1);
                case EllipticCurve.SecP521r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP521r1);
                case EllipticCurve.SecT113r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT113r1);
                case EllipticCurve.SecT113r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT113r2);
                case EllipticCurve.SecT131r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT131r2);
                case EllipticCurve.SecT131r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT131r1);
                case EllipticCurve.SecT163k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT163k1);
                case EllipticCurve.SecT163r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT163r1);
                case EllipticCurve.SecT163r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT163r2);
                case EllipticCurve.SecT193r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT193r1);
                case EllipticCurve.SecT193r2: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT193r2);
                case EllipticCurve.SecT233k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT233k1);
                case EllipticCurve.SecT233r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT233r1);
                case EllipticCurve.SecT239k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT239k1);
                case EllipticCurve.SecT283k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT283k1);
                case EllipticCurve.SecT283r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT283r1);
                case EllipticCurve.SecT409k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT409k1);
                case EllipticCurve.SecT409r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT409r1);
                case EllipticCurve.SecT571k1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT571k1);
                case EllipticCurve.SecT571r1: return SecNamedCurves.GetByOid(SecObjectIdentifiers.SecT571r1);

                case EllipticCurve.NistP192: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecP192r1);
                case EllipticCurve.NistP224: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecP224r1);
                case EllipticCurve.NistP256: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecP256r1);
                case EllipticCurve.NistP384: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecP384r1);
                case EllipticCurve.NistP521: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecP521r1);

                case EllipticCurve.NistB163: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecT163r2);
                case EllipticCurve.NistB233: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecT233r1);
                case EllipticCurve.NistB283: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecT283r1);
                case EllipticCurve.NistB409: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecT409r1);
                case EllipticCurve.NistB571: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecT571r1);

                case EllipticCurve.NistK163: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecT163k1);
                case EllipticCurve.NistK233: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecT233k1);
                case EllipticCurve.NistK283: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecT283k1);
                case EllipticCurve.NistK409: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecT409k1);
                case EllipticCurve.NistK571: return NistNamedCurves.GetByOid(SecObjectIdentifiers.SecT571k1);

                case EllipticCurve.BrainpoolP160R1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP160R1);
                case EllipticCurve.BrainpoolP160T1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP160T1);
                case EllipticCurve.BrainpoolP192R1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP192R1);
                case EllipticCurve.BrainpoolP192T1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP192T1);
                case EllipticCurve.BrainpoolP224R1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP224R1);
                case EllipticCurve.BrainpoolP224T1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP224T1);
                case EllipticCurve.BrainpoolP256R1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP256R1);
                case EllipticCurve.BrainpoolP256T1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP256T1);
                case EllipticCurve.BrainpoolP320R1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP320R1);
                case EllipticCurve.BrainpoolP320T1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP320T1);
                case EllipticCurve.BrainpoolP384R1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP384R1);
                case EllipticCurve.BrainpoolP384T1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP384T1);
                case EllipticCurve.BrainpoolP512R1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP512R1);
                case EllipticCurve.BrainpoolP512T1: return TeleTrusTNamedCurves.GetByOid(TeleTrusTObjectIdentifiers.BrainpoolP512T1);

                case EllipticCurve.FRP256v1: return AnssiNamedCurves.GetByOid(AnssiObjectIdentifiers.FRP256v1);

                case EllipticCurve.GostR3410_2001_CryptoPro_A: return ECGost3410NamedCurves.GetByOidX9(CryptoProObjectIdentifiers.GostR3410x2001CryptoProA);
                case EllipticCurve.GostR3410_2001_CryptoPro_B: return ECGost3410NamedCurves.GetByOidX9(CryptoProObjectIdentifiers.GostR3410x2001CryptoProB);
                case EllipticCurve.GostR3410_2001_CryptoPro_C: return ECGost3410NamedCurves.GetByOidX9(CryptoProObjectIdentifiers.GostR3410x2001CryptoProC);
                case EllipticCurve.GostR3410_2001_CryptoPro_XchA: return ECGost3410NamedCurves.GetByOidX9(CryptoProObjectIdentifiers.GostR3410x2001CryptoProXchA);
                case EllipticCurve.GostR3410_2001_CryptoPro_XchB: return ECGost3410NamedCurves.GetByOidX9(CryptoProObjectIdentifiers.GostR3410x2001CryptoProXchB);
                case EllipticCurve.Tc26_Gost3410_12_256_ParamSetA: return ECGost3410NamedCurves.GetByOidX9(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA);
                case EllipticCurve.Tc26_Gost3410_12_512_ParamSetA: return ECGost3410NamedCurves.GetByOidX9(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA);
                case EllipticCurve.Tc26_Gost3410_12_512_ParamSetB: return ECGost3410NamedCurves.GetByOidX9(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetB);
                case EllipticCurve.Tc26_Gost3410_12_512_ParamSetC: return ECGost3410NamedCurves.GetByOidX9(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetC);

                case EllipticCurve.WapiP192v1: return GMNamedCurves.GetByOid(GMObjectIdentifiers.wapip192v1);
                case EllipticCurve.Sm2P256v1: return GMNamedCurves.GetByOid(GMObjectIdentifiers.sm2p256v1);

                default: throw new CryptographicException("Unsupported elliptic curve.");
            }
        }

        private void InspectKey()
        {
            if (!_initialized)
            {
                GenerateKeyPair();
            }
        }

        private void InspectSigner(bool forSigning)
        {
            if (forSigning)
            {
                if (_signer == null)
                {
                    IDigest digest = _hashAlgorithm.GenerateDigest();
                    switch (_signatureExtension)
                    {
                        case ECDSASignatureExtension.ECDSA: _signer = new DsaDigestSigner(new ECDsaSigner(), digest); break;
                        case ECDSASignatureExtension.ECNR: _signer = new DsaDigestSigner(new ECNRSigner(), digest); break;
                        case ECDSASignatureExtension.Plain: _signer = new DsaDigestSigner(new ECDsaSigner(), digest, PlainDsaEncoding.Instance); break;
                        case ECDSASignatureExtension.CVC: _signer = new DsaDigestSigner(new ECDsaSigner(), digest, PlainDsaEncoding.Instance); break;
                        default: throw new CryptographicException("Unsupported signature extension.");
                    }
                    _signer.Init(true, _privateKey);
                }
            }
            else
            {
                if (_verifier == null)
                {
                    IDigest digest = _hashAlgorithm.GenerateDigest();
                    switch (_signatureExtension)
                    {
                        case ECDSASignatureExtension.ECDSA: _verifier = new DsaDigestSigner(new ECDsaSigner(), digest); break;
                        case ECDSASignatureExtension.ECNR: _verifier = new DsaDigestSigner(new ECNRSigner(), digest); break;
                        case ECDSASignatureExtension.Plain: _verifier = new DsaDigestSigner(new ECDsaSigner(), digest, PlainDsaEncoding.Instance); break;
                        case ECDSASignatureExtension.CVC: _verifier = new DsaDigestSigner(new ECDsaSigner(), digest, PlainDsaEncoding.Instance); break;
                        default: throw new CryptographicException("Unsupported signature extension.");
                    }
                    _verifier.Init(false, _publicKey);
                }
            }
        }
    }
}