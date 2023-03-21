using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
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
    public sealed class GOST3410 : AsymmetricAlgorithm, IAsymmetricSignatureAlgorithm
    {
        #region Properties

        private const GOST3410CryptoPro DEFAULT_CRYPTO_PRO = GOST3410CryptoPro.GostR3410x94CryptoProA;
        private const string NAME = "GOST3410";
        private static readonly KeySizes[] LEGAL_KEY_SIZES = new KeySizes[] { new KeySizes(512, 1024, 512) };
        private HashAlgorithmName _hashAlgorithm = HashAlgorithmName.GOST3411;
        private bool _initialized = false;
        private AsymmetricKeyParameter _privateKey = null;
        private AsymmetricKeyParameter _publicKey = null;
        private ISigner _signer = null;
        private ISigner _verifier = null;

        /// <summary>
        /// Get or set hash algorithm for signature. Legal hash algorithm is hash size more than or equal to 256 bits.
        /// </summary>
        public HashAlgorithmName HashAlgorithm
        {
            get => _hashAlgorithm;
            set
            {
                if (value != _hashAlgorithm)
                {
                    if (value == null)
                    {
                        throw new CryptographicException("This hash algorithm can't be null.");
                    }
                    if (value.HashSize < 256)
                    {
                        throw new CryptographicException("Legal hash algorithm is hash size more than or equal to 256 bits.");
                    }
                    _signer = null;
                    _verifier = null;
                    _hashAlgorithm = value;
                }
            }
        }

        /// <inheritdoc/>
        public string SignatureAlgorithm => GetSignatureAlgorithmMechanism(_hashAlgorithm);

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the GOST3410 class.
        /// </summary>
        public GOST3410() : base(NAME, AsymmetricAlgorithmKind.Signature)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static GOST3410 Create()
        {
            return new GOST3410();
        }

        #region GenerateParameters

        /// <inheritdoc/>
        public void GenerateParameters()
        {
            GenerateParameters(DEFAULT_CRYPTO_PRO);
        }

        /// <summary>
        /// Renew private key and public key of the algorithm.
        /// </summary>
        /// <param name="cryptoPro">Elliptic curve to be uesd.</param>
        public void GenerateParameters(GOST3410CryptoPro cryptoPro = DEFAULT_CRYPTO_PRO)
        {
            //
            // Gost3410ParametersGenerator with key size created key pair con't be save to pkcs8.
            //
            //Gost3410ParametersGenerator parametersGenerator = new Gost3410ParametersGenerator();
            //parametersGenerator.Init(keySize, procedure, Common.SecureRandom);
            //Gost3410Parameters parameters = parametersGenerator.GenerateParameters();
            //Gost3410KeyGenerationParameters generationParameters = new Gost3410KeyGenerationParameters(Common.SecureRandom, parameters);

            var generationParameters = new Gost3410KeyGenerationParameters(Common.SecureRandom, GetCryptoPro(cryptoPro));
            Gost3410KeyPairGenerator keyPairGenerator = new Gost3410KeyPairGenerator();
            keyPairGenerator.Init(generationParameters);
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();
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
            Gost3410PrivateKeyParameters privateKey = null;
            Gost3410PublicKeyParameters publicKey = null;
            Asn1Object asn1 = Asn1Object.FromByteArray(keyInfo);
            try
            {
                PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.GetInstance(asn1);
                privateKey = (Gost3410PrivateKeyParameters)PrivateKeyFactory.CreateKey(privateKeyInfo);
                BigInteger y = privateKey.Parameters.A.ModPow(privateKey.X, privateKey.Parameters.P);
                publicKey = new Gost3410PublicKeyParameters(y, privateKey.Parameters);
            }
            catch
            {
                try
                {
                    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.GetInstance(asn1);
                    publicKey = (Gost3410PublicKeyParameters)PublicKeyFactory.CreateKey(publicKeyInfo);
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
            Gost3410PrivateKeyParameters privateKey = (Gost3410PrivateKeyParameters)PrivateKeyFactory.CreateKey(privateKeyInfo);
            BigInteger y = privateKey.Parameters.A.ModPow(privateKey.X, privateKey.Parameters.P);
            Gost3410PublicKeyParameters publicKey = new Gost3410PublicKeyParameters(y, privateKey.Parameters);
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
                Gost3410PrivateKeyParameters privateKey = null;
                Gost3410PublicKeyParameters publicKey;
                object obj = new PemReader(reader).ReadObject();
                if (obj.GetType() == typeof(Gost3410PrivateKeyParameters))
                {
                    privateKey = (Gost3410PrivateKeyParameters)obj;
                    BigInteger y = privateKey.Parameters.A.ModPow(privateKey.X, privateKey.Parameters.P);
                    publicKey = new Gost3410PublicKeyParameters(y, privateKey.Parameters);
                }
                else
                {
                    publicKey = (Gost3410PublicKeyParameters)obj;
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
                Gost3410PrivateKeyParameters privateKey = (Gost3410PrivateKeyParameters)obj;
                BigInteger y = privateKey.Parameters.A.ModPow(privateKey.X, privateKey.Parameters.P);
                Gost3410PublicKeyParameters publicKey = new Gost3410PublicKeyParameters(y, privateKey.Parameters);
                _privateKey = privateKey;
                _publicKey = publicKey;
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

        /// <summary>
        /// Determines whether the specified size is valid for the current algorithm.
        /// </summary>
        /// <param name="keySize">Legal key size is more than or equal to 24 bits (8 bits increments).</param>
        /// <returns></returns>
        public bool ValidKeySize(int keySize, out string exception)
        {
            if (DetectionUtilities.ValidSize(LEGAL_KEY_SIZES, keySize))
            {
                exception = string.Empty;
                return true;
            }
            else
            {
                exception = "Legal key size 512, 1024 bits.";
                return false;
            }
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
            return new AsymmetricAlgorithmName(NAME, AsymmetricAlgorithmKind.Signature, () => { return new GOST3410(); });
        }

        internal static SignatureAlgorithmName GetSignatureAlgorithmName(HashAlgorithmName hashAlgorithm)
        {
            return new SignatureAlgorithmName(GetSignatureAlgorithmMechanism(hashAlgorithm),
                                              () => { return new GOST3410() { HashAlgorithm = hashAlgorithm }; });
        }

        private static DerObjectIdentifier GetCryptoPro(GOST3410CryptoPro cryptoPro)
        {
            switch (cryptoPro)
            {
                case GOST3410CryptoPro.GostR3410x94CryptoProA: return CryptoProObjectIdentifiers.GostR3410x94CryptoProA;
                case GOST3410CryptoPro.GostR3410x94CryptoProB: return CryptoProObjectIdentifiers.GostR3410x94CryptoProB;
                case GOST3410CryptoPro.GostR3410x94CryptoProXchA: return CryptoProObjectIdentifiers.GostR3410x94CryptoProXchA;
                default: throw new CryptographicException("Unsupported crypto pro.");
            }
        }

        private static string GetSignatureAlgorithmMechanism(HashAlgorithmName hashAlgorithm)
        {
            return $"{hashAlgorithm.Name}with{NAME}";
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
                    _signer = new Gost3410DigestSigner(new Gost3410Signer(), digest);
                    _signer.Init(true, _privateKey);
                }
            }
            else
            {
                if (_verifier == null)
                {
                    IDigest digest = _hashAlgorithm.GetEngine();
                    _verifier = new Gost3410DigestSigner(new Gost3410Signer(), digest);
                    _verifier.Init(false, _publicKey);
                }
            }
        }
    }
}