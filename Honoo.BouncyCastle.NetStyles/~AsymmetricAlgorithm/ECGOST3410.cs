using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System.IO;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class ECGOST3410 : AsymmetricAlgorithm, ISignatureAlgorithm
    {
        #region Properties

        private const ECGOST3410EllipticCurve DEFAULT_CURVE = ECGOST3410EllipticCurve.GostR3410_2001_CryptoPro_A;
        private const string NAME = "ECGOST3410";
        private HashAlgorithmName _hashAlgorithmName = HashAlgorithmName.GOST3411;
        private ISigner _signer = null;
        private ISigner _verifier = null;

        /// <inheritdoc/>
        public HashAlgorithmName HashAlgorithmName
        {
            get => _hashAlgorithmName;
            set
            {
                if (value != _hashAlgorithmName)
                {
                    _signer = null;
                    _verifier = null;
                    _hashAlgorithmName = value ?? throw new CryptographicException("This hash algorithm can't be null.");
                }
            }
        }

        /// <inheritdoc/>
        public SignatureAlgorithmName SignatureAlgorithmName
        {
            get
            {
                string mechanism = GetSignatureAlgorithmMechanism(_hashAlgorithmName);
                SignatureAlgorithmName.TryGetAlgorithmName(mechanism, out SignatureAlgorithmName algorithmName);
                return algorithmName;
            }
        }

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the ECGOST3410 class.
        /// </summary>
        public ECGOST3410() : base(NAME, AsymmetricAlgorithmKind.Signature)
        {
        }

        #endregion Construction

        #region GenerateParameters

        /// <inheritdoc/>
        public override void GenerateParameters()
        {
            GenerateParameters(DEFAULT_CURVE);
        }

        /// <summary>
        /// Renew private key and public key of the algorithm.
        /// </summary>
        /// <param name="ellipticCurve">Elliptic curve to be uesd.</param>
        public void GenerateParameters(ECGOST3410EllipticCurve ellipticCurve = DEFAULT_CURVE)
        {
            ECKeyGenerationParameters generationParameters = new ECKeyGenerationParameters(GetNamedOid(ellipticCurve), Common.SecureRandom.Value);
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.Init(generationParameters);
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
            _privateKey = keyPair.Private;
            _publicKey = keyPair.Public;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        #endregion GenerateParameters

        #region Export/Import Parameters

        /// <inheritdoc/>
        public override void ImportKeyInfo(byte[] keyInfo)
        {
            ECPrivateKeyParameters privateKey = null;
            ECPublicKeyParameters publicKey = null;
            Asn1Object asn1 = Asn1Object.FromByteArray(keyInfo);
            try
            {
                PrivateKeyInfo priInfo = PrivateKeyInfo.GetInstance(asn1);
                privateKey = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(priInfo);
                var q = new FixedPointCombMultiplier().Multiply(privateKey.Parameters.G, privateKey.D);
                publicKey = new ECPublicKeyParameters(privateKey.AlgorithmName, q, privateKey.Parameters);
            }
            catch
            {
                try
                {
                    SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.GetInstance(asn1);
                    publicKey = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(pubInfo);
                }
                catch
                {
                }
            }
            _privateKey = privateKey;
            _publicKey = publicKey;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportKeyInfo(byte[] privateKeyInfo, string password)
        {
            Asn1Object asn1 = Asn1Object.FromByteArray(privateKeyInfo);
            EncryptedPrivateKeyInfo enc = EncryptedPrivateKeyInfo.GetInstance(asn1);
            PrivateKeyInfo priInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(password.ToCharArray(), enc);
            ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(priInfo);
            var q = new FixedPointCombMultiplier().Multiply(privateKey.Parameters.G, privateKey.D);
            ECPublicKeyParameters publicKey = new ECPublicKeyParameters(privateKey.AlgorithmName, q, privateKey.Parameters);
            _privateKey = privateKey;
            _publicKey = publicKey;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportParameters(AsymmetricKeyParameter asymmetricKey)
        {
            ECPrivateKeyParameters privateKey = null;
            ECPublicKeyParameters publicKey;
            if (asymmetricKey.IsPrivate)
            {
                privateKey = (ECPrivateKeyParameters)asymmetricKey;
                var q = new FixedPointCombMultiplier().Multiply(privateKey.Parameters.G, privateKey.D);
                publicKey = new ECPublicKeyParameters(privateKey.AlgorithmName, q, privateKey.Parameters);
            }
            else
            {
                publicKey = (ECPublicKeyParameters)asymmetricKey;
            }
            _privateKey = privateKey;
            _publicKey = publicKey;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportParameters(AsymmetricCipherKeyPair keyPair)
        {
            ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters)keyPair.Private;
            ECPublicKeyParameters publicKey = (ECPublicKeyParameters)keyPair.Public;
            _privateKey = privateKey;
            _publicKey = publicKey;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportPem(string keyPem)
        {
            using (StringReader reader = new StringReader(keyPem))
            {
                ECPrivateKeyParameters privateKey = null;
                ECPublicKeyParameters publicKey;
                object obj = new PemReader(reader).ReadObject();
                if (obj.GetType() == typeof(AsymmetricCipherKeyPair))
                {
                    AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)obj;
                    privateKey = (ECPrivateKeyParameters)keyPair.Private;
                    publicKey = (ECPublicKeyParameters)keyPair.Public;
                }
                else
                {
                    publicKey = (ECPublicKeyParameters)obj;
                }
                _privateKey = privateKey;
                _publicKey = publicKey;
                _signer = null;
                _verifier = null;
                _initialized = true;
            }
        }

        /// <inheritdoc/>
        public override void ImportPem(string privateKeyPem, string password)
        {
            using (StringReader reader = new StringReader(privateKeyPem))
            {
                object obj = new PemReader(reader, new Password(password)).ReadObject();
                AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)obj;
                ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters)keyPair.Private;
                ECPublicKeyParameters publicKey = (ECPublicKeyParameters)keyPair.Public;
                _privateKey = privateKey;
                _publicKey = publicKey;
                _signer = null;
                _verifier = null;
                _initialized = true;
            }
        }

        #endregion Export/Import Parameters

        #region Signature

        /// <inheritdoc/>
        public void Reset()
        {
            _signer?.Reset();
            _verifier?.Reset();
        }

        /// <inheritdoc/>
        public byte[] SignFinal()
        {
            InspectParameters();
            InspectSigner(true);
            return _signer.GenerateSignature();
        }

        /// <inheritdoc/>
        public byte[] SignFinal(byte[] rgb)
        {
            SignUpdate(rgb, 0, rgb.Length);
            return SignFinal();
        }

        /// <inheritdoc/>
        public byte[] SignFinal(byte[] buffer, int offset, int length)
        {
            SignUpdate(buffer, offset, length);
            return SignFinal();
        }

        /// <inheritdoc/>
        public void SignUpdate(byte[] rgb)
        {
            SignUpdate(rgb, 0, rgb.Length);
        }

        /// <inheritdoc/>
        public void SignUpdate(byte[] buffer, int offset, int length)
        {
            InspectParameters();
            InspectSigner(true);
            _signer.BlockUpdate(buffer, offset, length);
        }

        /// <inheritdoc/>
        public bool VerifyFinal(byte[] signature)
        {
            InspectParameters();
            InspectSigner(false);
            return _verifier.VerifySignature(signature);
        }

        /// <inheritdoc/>
        public bool VerifyFinal(byte[] rgb, byte[] signature)
        {
            VerifyUpdate(rgb, 0, rgb.Length);
            return VerifyFinal(signature);
        }

        /// <inheritdoc/>
        public bool VerifyFinal(byte[] buffer, int offset, int length, byte[] signature)
        {
            VerifyUpdate(buffer, offset, length);
            return VerifyFinal(signature);
        }

        /// <inheritdoc/>
        public void VerifyUpdate(byte[] rgb)
        {
            VerifyUpdate(rgb, 0, rgb.Length);
        }

        /// <inheritdoc/>
        public void VerifyUpdate(byte[] buffer, int offset, int length)
        {
            InspectParameters();
            InspectSigner(false);
            _verifier.BlockUpdate(buffer, offset, length);
        }

        #endregion Signature

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static ECGOST3410 Create()
        {
            return new ECGOST3410();
        }

        internal static AsymmetricAlgorithmName GetAlgorithmName()
        {
            return new AsymmetricAlgorithmName(NAME, AsymmetricAlgorithmKind.Signature, () => { return new ECGOST3410(); });
        }

        internal static SignatureAlgorithmName GetSignatureAlgorithmName(HashAlgorithmName hashAlgorithm)
        {
            return new SignatureAlgorithmName(GetSignatureAlgorithmMechanism(hashAlgorithm),
                                              () => { return new ECGOST3410() { _hashAlgorithmName = hashAlgorithm }; });
        }

        private static DerObjectIdentifier GetNamedOid(ECGOST3410EllipticCurve ellipticCurve)
        {
            switch (ellipticCurve)
            {
                case ECGOST3410EllipticCurve.GostR3410_2001_CryptoPro_A: return CryptoProObjectIdentifiers.GostR3410x2001CryptoProA;
                case ECGOST3410EllipticCurve.GostR3410_2001_CryptoPro_B: return CryptoProObjectIdentifiers.GostR3410x2001CryptoProB;
                case ECGOST3410EllipticCurve.GostR3410_2001_CryptoPro_C: return CryptoProObjectIdentifiers.GostR3410x2001CryptoProC;
                case ECGOST3410EllipticCurve.GostR3410_2001_CryptoPro_XchA: return CryptoProObjectIdentifiers.GostR3410x2001CryptoProXchA;
                case ECGOST3410EllipticCurve.GostR3410_2001_CryptoPro_XchB: return CryptoProObjectIdentifiers.GostR3410x2001CryptoProXchB;
                case ECGOST3410EllipticCurve.Tc26_Gost3410_12_256_ParamSetA: return RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA;
                //case ECGOST3410EllipticCurve.Tc26_Gost3410_12_512_ParamSetA: return RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA;
                //case ECGOST3410EllipticCurve.Tc26_Gost3410_12_512_ParamSetB: return RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetB;
                //case ECGOST3410EllipticCurve.Tc26_Gost3410_12_512_ParamSetC: return RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetC;
                default: throw new CryptographicException("Unsupported elliptic curve.");
            }
        }

        private static string GetSignatureAlgorithmMechanism(HashAlgorithmName hashAlgorithm)
        {
            return $"{hashAlgorithm.Name}with{NAME}";
        }

        private void InspectSigner(bool forSigning)
        {
            if (forSigning)
            {
                if (_signer == null)
                {
                    IDigest digest = _hashAlgorithmName.GetEngine();
                    _signer = new Gost3410DigestSigner(new ECGost3410Signer(), digest);
                    _signer.Init(true, _privateKey);
                }
            }
            else
            {
                if (_verifier == null)
                {
                    IDigest digest = _hashAlgorithmName.GetEngine();
                    _verifier = new Gost3410DigestSigner(new ECGost3410Signer(), digest);
                    _verifier.Init(false, _publicKey);
                }
            }
        }
    }
}