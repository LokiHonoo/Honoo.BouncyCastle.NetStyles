using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class ECGOST3410 : AsymmetricAlgorithm, IAsymmetricSignatureAlgorithm
    {
        #region Properties

        private const ECGOST3410EllipticCurve DEFAULT_CURVE = ECGOST3410EllipticCurve.GostR3410_2001_CryptoPro_A;
        private const string NAME = "ECGOST3410";
        private HashAlgorithmName _hashAlgorithm = HashAlgorithmName.GOST3411;
        private bool _initialized = false;
        private AsymmetricKeyParameter _privateKey = null;
        private AsymmetricKeyParameter _publicKey = null;
        private ISigner _signer = null;
        private ISigner _verifier = null;

        /// <inheritdoc/>
        public HashAlgorithmName HashAlgorithm
        {
            get => _hashAlgorithm;
            set
            {
                if (value != _hashAlgorithm)
                {
                    _signer = null;
                    _verifier = null;
                    _hashAlgorithm = value ?? throw new CryptographicException("This hash algorithm can't be null.");
                }
            }
        }

        /// <inheritdoc/>
        public string SignatureAlgorithm => GetSignatureAlgorithmMechanism(_hashAlgorithm);

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the ECGOST3410 class.
        /// </summary>
        public ECGOST3410() : base(NAME, AsymmetricAlgorithmKind.Signature)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static ECGOST3410 Create()
        {
            return new ECGOST3410();
        }

        #region GenerateParameters

        /// <inheritdoc/>
        public void GenerateParameters()
        {
            GenerateParameters(DEFAULT_CURVE);
        }

        /// <summary>
        /// Renew private key and public key of the algorithm.
        /// </summary>
        /// <param name="ellipticCurve">Elliptic curve to be uesd.</param>
        public void GenerateParameters(ECGOST3410EllipticCurve ellipticCurve = DEFAULT_CURVE)
        {
            X9ECParameters x9Parameters = GetX9ECParameters(ellipticCurve);
            ECDomainParameters domainParameters = new ECDomainParameters(x9Parameters);
            ECKeyGenerationParameters generationParameters = new ECKeyGenerationParameters(domainParameters, Common.SecureRandom);
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
        public byte[] ExportKeyInfo(bool includePrivate)
        {
            InspectParameters();
            if (includePrivate)
            {
                PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(_privateKey);
                return privateKeyInfo.GetEncoded();
            }
            else
            {
                SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(_publicKey);
                return publicKeyInfo.GetEncoded();
            }
        }

        /// <inheritdoc/>
        public byte[] ExportKeyInfo(PBEAlgorithmName pbeAlgorithmName, string password)
        {
            InspectParameters();
            byte[] salt = new byte[16];
            Common.SecureRandom.NextBytes(salt);
            EncryptedPrivateKeyInfo enc = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
                pbeAlgorithmName.Oid, password.ToCharArray(), salt, 2048, _privateKey);
            return enc.GetEncoded();
        }

        /// <inheritdoc/>
        public string ExportPem(bool includePrivate)
        {
            InspectParameters();
            AsymmetricKeyParameter asymmetricKey = includePrivate ? _privateKey : _publicKey;
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(asymmetricKey);
                return writer.ToString();
            }
        }

        /// <inheritdoc/>
        public string ExportPem(DEKAlgorithmName dekAlgorithmName, string password)
        {
            InspectParameters();
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(_privateKey, dekAlgorithmName.Name, password.ToCharArray(), Common.SecureRandom);
                return writer.ToString();
            }
        }

        /// <inheritdoc/>
        public void ImportKeyInfo(byte[] keyInfo)
        {
            ECPrivateKeyParameters privateKey = null;
            ECPublicKeyParameters publicKey = null;
            Asn1Object asn1 = Asn1Object.FromByteArray(keyInfo);
            try
            {
                PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.GetInstance(asn1);
                privateKey = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(privateKeyInfo);
                var q = new FixedPointCombMultiplier().Multiply(privateKey.Parameters.G, privateKey.D);
                publicKey = new ECPublicKeyParameters(privateKey.AlgorithmName, q, privateKey.Parameters);
            }
            catch
            {
                try
                {
                    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.GetInstance(asn1);
                    publicKey = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(publicKeyInfo);
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
        public void ImportKeyInfo(byte[] keyInfo, string password)
        {
            Asn1Object asn1 = Asn1Object.FromByteArray(keyInfo);
            EncryptedPrivateKeyInfo enc = EncryptedPrivateKeyInfo.GetInstance(asn1);
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(password.ToCharArray(), enc);
            ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(privateKeyInfo);
            var q = new FixedPointCombMultiplier().Multiply(privateKey.Parameters.G, privateKey.D);
            ECPublicKeyParameters publicKey = new ECPublicKeyParameters(privateKey.AlgorithmName, q, privateKey.Parameters);
            _privateKey = privateKey;
            _publicKey = publicKey;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public void ImportPem(string pem)
        {
            using (StringReader reader = new StringReader(pem))
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
        public void ImportPem(string pem, string password)
        {
            using (StringReader reader = new StringReader(pem))
            {
                object obj = new PemReader(reader, new Password(password)).ReadObject();
                AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)obj;
                _privateKey = (ECPrivateKeyParameters)keyPair.Private;
                _publicKey = (ECPublicKeyParameters)keyPair.Public;
                _signer = null;
                _verifier = null;
                _initialized = true;
            }
        }

        #endregion Export/Import Parameters

        /// <inheritdoc/>
        public override IAsymmetricEncryptionAlgorithm GetEncryptionInterface()
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public override IKeyExchangeA GetKeyExchangeAInterface()
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public override IKeyExchangeB GetKeyExchangeBInterface()
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public override IAsymmetricSignatureAlgorithm GetSignatureInterface()
        {
            return this;
        }

        /// <inheritdoc/>
        public void ResetSigner()
        {
            if (_signer != null)
            {
                _signer.Reset();
            }
            if (_verifier != null)
            {
                _verifier.Reset();
            }
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
        public void VerifyUpdate(byte[] buffer, int offset, int length)
        {
            InspectParameters();
            InspectSigner(false);
            _verifier.BlockUpdate(buffer, offset, length);
        }

        internal static AsymmetricAlgorithmName GetAlgorithmName()
        {
            return new AsymmetricAlgorithmName(NAME, AsymmetricAlgorithmKind.Signature, () => { return new ECGOST3410(); });
        }

        internal static SignatureAlgorithmName GetSignatureAlgorithmName(HashAlgorithmName hashAlgorithm)
        {
            return new SignatureAlgorithmName(GetSignatureAlgorithmMechanism(hashAlgorithm),
                                              () => { return new ECGOST3410() { HashAlgorithm = hashAlgorithm }; });
        }

        private static string GetSignatureAlgorithmMechanism(HashAlgorithmName hashAlgorithm)
        {
            return $"{hashAlgorithm.Name}with{NAME}";
        }

        private static X9ECParameters GetX9ECParameters(ECGOST3410EllipticCurve ellipticCurve)
        {
            switch (ellipticCurve)
            {
                case ECGOST3410EllipticCurve.GostR3410_2001_CryptoPro_A: return ECGost3410NamedCurves.GetByOidX9(CryptoProObjectIdentifiers.GostR3410x2001CryptoProA);
                case ECGOST3410EllipticCurve.GostR3410_2001_CryptoPro_B: return ECGost3410NamedCurves.GetByOidX9(CryptoProObjectIdentifiers.GostR3410x2001CryptoProB);
                case ECGOST3410EllipticCurve.GostR3410_2001_CryptoPro_C: return ECGost3410NamedCurves.GetByOidX9(CryptoProObjectIdentifiers.GostR3410x2001CryptoProC);
                case ECGOST3410EllipticCurve.GostR3410_2001_CryptoPro_XchA: return ECGost3410NamedCurves.GetByOidX9(CryptoProObjectIdentifiers.GostR3410x2001CryptoProXchA);
                case ECGOST3410EllipticCurve.GostR3410_2001_CryptoPro_XchB: return ECGost3410NamedCurves.GetByOidX9(CryptoProObjectIdentifiers.GostR3410x2001CryptoProXchB);
                case ECGOST3410EllipticCurve.Tc26_Gost3410_12_256_ParamSetA: return ECGost3410NamedCurves.GetByOidX9(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA);
                case ECGOST3410EllipticCurve.Tc26_Gost3410_12_512_ParamSetA: return ECGost3410NamedCurves.GetByOidX9(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA);
                case ECGOST3410EllipticCurve.Tc26_Gost3410_12_512_ParamSetB: return ECGost3410NamedCurves.GetByOidX9(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetB);
                case ECGOST3410EllipticCurve.Tc26_Gost3410_12_512_ParamSetC: return ECGost3410NamedCurves.GetByOidX9(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetC);
                default: throw new CryptographicException("Unsupported elliptic curve.");
            }
        }

        private void InspectParameters()
        {
            if (!_initialized)
            {
                GenerateParameters();
            }
        }

        private void InspectSigner(bool forSigning)
        {
            if (forSigning)
            {
                if (_signer == null)
                {
                    IDigest digest = _hashAlgorithm.GetEngine();
                    _signer = new Gost3410DigestSigner(new ECGost3410Signer(), digest);
                    _signer.Init(true, _privateKey);
                }
            }
            else
            {
                if (_verifier == null)
                {
                    IDigest digest = _hashAlgorithm.GetEngine();
                    _verifier = new Gost3410DigestSigner(new ECGost3410Signer(), digest);
                    _verifier.Init(false, _publicKey);
                }
            }
        }
    }
}