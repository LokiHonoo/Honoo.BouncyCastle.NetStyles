using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
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
    public sealed class SM2 : AsymmetricAlgorithm, IAsymmetricEncryptionAlgorithm, ISignatureAlgorithm
    {
        #region Properties

        private const SM2EllipticCurve DEFAULT_CURVE = SM2EllipticCurve.Sm2P256v1;
        private const int DEFAULT_KEY_SIZE = 256;
        private const string NAME = "SM2";
        private SM2Engine _decryptor = null;
        private bool _encryptionInitialized = false;
        private SM2Engine _encryptor = null;
        private HashAlgorithmName _hashAlgorithmName = HashAlgorithmName.SM3;
        private int _keySize = DEFAULT_KEY_SIZE;
        private ICipherParameters _publicEncryptionKey = null;
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
        /// Initializes a new instance of the SM2 class.
        /// </summary>
        public SM2() : base(NAME, AsymmetricAlgorithmKind.SignatureAndEncryption)
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
        public void GenerateParameters(SM2EllipticCurve ellipticCurve = DEFAULT_CURVE)
        {
            //X9ECParameters x9Parameters = GetX9ECParameters(ellipticCurve);
            //ECDomainParameters domainParameters = new ECDomainParameters(x9Parameters);
            ECKeyGenerationParameters generationParameters = new ECKeyGenerationParameters(GetNamedOid(ellipticCurve), Common.SecureRandom.Value);
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.Init(generationParameters);
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
            _privateKey = keyPair.Private;
            _publicKey = keyPair.Public;
            _keySize = ellipticCurve == SM2EllipticCurve.WapiP192v1 ? 192 : 256;
            _signer = null;
            _verifier = null;
            _initialized = true;
            _publicEncryptionKey = null;
            _encryptor = null;
            _decryptor = null;
            _encryptionInitialized = false;
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
            _keySize = publicKey.Parameters.Curve.FieldSize;
            _signer = null;
            _verifier = null;
            _initialized = true;
            _publicEncryptionKey = null;
            _encryptor = null;
            _decryptor = null;
            _encryptionInitialized = false;
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
            _keySize = publicKey.Parameters.Curve.FieldSize;
            _signer = null;
            _verifier = null;
            _initialized = true;
            _publicEncryptionKey = null;
            _encryptor = null;
            _decryptor = null;
            _encryptionInitialized = false;
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
            _keySize = publicKey.Parameters.Curve.FieldSize;
            _signer = null;
            _verifier = null;
            _initialized = true;
            _publicEncryptionKey = null;
            _encryptor = null;
            _decryptor = null;
            _encryptionInitialized = false;
        }

        /// <inheritdoc/>
        public override void ImportParameters(AsymmetricCipherKeyPair keyPair)
        {
            ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters)keyPair.Private;
            ECPublicKeyParameters publicKey = (ECPublicKeyParameters)keyPair.Public;
            _privateKey = privateKey;
            _publicKey = publicKey;
            _keySize = publicKey.Parameters.Curve.FieldSize;
            _signer = null;
            _verifier = null;
            _initialized = true;
            _publicEncryptionKey = null;
            _encryptor = null;
            _decryptor = null;
            _encryptionInitialized = false;
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
                _keySize = publicKey.Parameters.Curve.FieldSize;
                _signer = null;
                _verifier = null;
                _initialized = true;
                _publicEncryptionKey = null;
                _encryptor = null;
                _decryptor = null;
                _encryptionInitialized = false;
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
                _keySize = publicKey.Parameters.Curve.FieldSize;
                _signer = null;
                _verifier = null;
                _initialized = true;
                _publicEncryptionKey = null;
                _encryptor = null;
                _decryptor = null;
                _encryptionInitialized = false;
            }
        }

        #endregion Export/Import Parameters

        #region Encryption

        /// <inheritdoc/>
        public byte[] Decrypt(byte[] rgb)
        {
            return Decrypt(rgb, 0, rgb.Length);
        }

        /// <inheritdoc/>
        public byte[] Decrypt(byte[] inputBuffer, int offset, int length)
        {
            InspectParameters();
            InspectEncryptionParameters();
            if (_decryptor == null)
            {
                _decryptor = GetCipher(false);
            }
            return _decryptor.ProcessBlock(inputBuffer, offset, length);
        }

        /// <inheritdoc/>
        public byte[] Encrypt(byte[] rgb)
        {
            return Encrypt(rgb, 0, rgb.Length);
        }

        /// <inheritdoc/>
        public byte[] Encrypt(byte[] inputBuffer, int offset, int length)
        {
            InspectParameters();
            InspectEncryptionParameters();
            if (_encryptor == null)
            {
                _encryptor = GetCipher(true);
            }
            return _encryptor.ProcessBlock(inputBuffer, offset, length);
        }

        /// <inheritdoc/>
        public int GetLegalInputLength(bool forEncryption)
        {
            if (forEncryption)
            {
                switch (_keySize)
                {
                    case 192: return int.MaxValue - 81;
                    case 256: return int.MaxValue - 97;
                    default: throw new CryptographicException("Unknow elliptic curve.");
                }
            }
            else
            {
                if (_initialized)
                {
                    if (_privateKey == null)
                    {
                        return 0;
                    }
                }
                return int.MaxValue;
            }
        }

        #endregion Encryption

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
        public byte[] SignFinal(byte[] inputBuffer, int offset, int length)
        {
            SignUpdate(inputBuffer, offset, length);
            return SignFinal();
        }

        /// <inheritdoc/>
        public void SignUpdate(byte[] rgb)
        {
            SignUpdate(rgb, 0, rgb.Length);
        }

        /// <inheritdoc/>
        public void SignUpdate(byte[] inputBuffer, int offset, int length)
        {
            InspectParameters();
            InspectSigner(true);
            _signer.BlockUpdate(inputBuffer, offset, length);
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
        public bool VerifyFinal(byte[] inputBuffer, int offset, int length, byte[] signature)
        {
            VerifyUpdate(inputBuffer, offset, length);
            return VerifyFinal(signature);
        }

        /// <inheritdoc/>
        public void VerifyUpdate(byte[] rgb)
        {
            VerifyUpdate(rgb, 0, rgb.Length);
        }

        /// <inheritdoc/>
        public void VerifyUpdate(byte[] inputBuffer, int offset, int length)
        {
            InspectParameters();
            InspectSigner(false);
            _verifier.BlockUpdate(inputBuffer, offset, length);
        }

        #endregion Signature

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static SM2 Create()
        {
            return new SM2();
        }

        internal static AsymmetricAlgorithmName GetAlgorithmName()
        {
            return new AsymmetricAlgorithmName(NAME, AsymmetricAlgorithmKind.Signature, () => { return new SM2(); });
        }

        internal static SignatureAlgorithmName GetSignatureAlgorithmName(HashAlgorithmName hashAlgorithm)
        {
            return new SignatureAlgorithmName(GetSignatureAlgorithmMechanism(hashAlgorithm),
                                              () => { return new SM2() { _hashAlgorithmName = hashAlgorithm }; });
        }

        private static DerObjectIdentifier GetNamedOid(SM2EllipticCurve ellipticCurve)
        {
            // GMNamedCurves.GetByOid(GMObjectIdentifiers.sm2p256v1);
            switch (ellipticCurve)
            {
                case SM2EllipticCurve.Sm2P256v1: return GMObjectIdentifiers.sm2p256v1;
                case SM2EllipticCurve.WapiP192v1: return GMObjectIdentifiers.wapip192v1;
                default: throw new CryptographicException("Unsupported elliptic curve.");
            }
        }

        private static string GetSignatureAlgorithmMechanism(HashAlgorithmName hashAlgorithm)
        {
            return $"{hashAlgorithm.Name}with{NAME}";
        }

        private void GenerateEncryptionParameters()
        {
            _publicEncryptionKey = new ParametersWithRandom(_publicKey, Common.SecureRandom.Value);
            _decryptor = null;
            _encryptor = null;
            _encryptionInitialized = true;
        }

        private SM2Engine GetCipher(bool forEncryption)
        {
            SM2Engine cipher = new SM2Engine();
            cipher.Init(forEncryption, forEncryption ? _publicEncryptionKey : _privateKey);
            return cipher;
        }

        private void InspectEncryptionParameters()
        {
            if (!_encryptionInitialized)
            {
                GenerateEncryptionParameters();
            }
        }

        private void InspectSigner(bool forSigning)
        {
            if (forSigning)
            {
                if (_signer == null)
                {
                    IDigest digest = _hashAlgorithmName.GetEngine();
                    _signer = new SM2Signer(digest);
                    _signer.Init(true, _privateKey);
                }
            }
            else
            {
                if (_verifier == null)
                {
                    IDigest digest = _hashAlgorithmName.GetEngine();
                    _verifier = new SM2Signer(digest);
                    _verifier.Init(false, _publicKey);
                }
            }
        }
    }
}