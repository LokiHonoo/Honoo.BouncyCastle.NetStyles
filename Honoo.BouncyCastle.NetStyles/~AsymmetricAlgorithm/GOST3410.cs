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
using System.IO;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class GOST3410 : AsymmetricAlgorithm, ISignatureAlgorithm
    {
        #region Properties

        private const GOST3410Parameters DEFAULT_PARAMETERS = GOST3410Parameters.GostR3410x94CryptoProA;
        private const string NAME = "GOST3410";
        private HashAlgorithmName _hashAlgorithmName = HashAlgorithmName.GOST3411;
        private ISigner _signer = null;
        private ISigner _verifier = null;

        /// <summary>
        /// Get or set hash algorithm for signature. Legal hash algorithm is hash size more than or equal to 256 bits.
        /// </summary>
        public HashAlgorithmName HashAlgorithmName
        {
            get => _hashAlgorithmName;
            set
            {
                if (value != _hashAlgorithmName)
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
                    _hashAlgorithmName = value;
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
        /// Initializes a new instance of the GOST3410 class.
        /// </summary>
        public GOST3410() : base(NAME, AsymmetricAlgorithmKind.Signature)
        {
        }

        #endregion Construction

        #region GenerateParameters

        /// <inheritdoc/>
        public override void GenerateParameters()
        {
            GenerateParameters(DEFAULT_PARAMETERS);
        }

        /// <summary>
        /// Renew private key and public key of the algorithm.
        /// </summary>
        /// <param name="parameters">GOST3410 parameters.</param>
        public void GenerateParameters(GOST3410Parameters parameters = DEFAULT_PARAMETERS)
        {
            //// Gost3410ParametersGenerator with key size created key pair con't be save to pkcs8.
            //Gost3410ParametersGenerator parametersGenerator = new Gost3410ParametersGenerator();
            //parametersGenerator.Init(keySize, procedure, Common.SecureRandom);
            //Gost3410Parameters parameters = parametersGenerator.GenerateParameters();
            //Gost3410KeyGenerationParameters generationParameters = new Gost3410KeyGenerationParameters(Common.SecureRandom, parameters);
            var generationParameters = new Gost3410KeyGenerationParameters(Common.SecureRandom.Value, GetGOST3410Parameters(parameters));
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
        public override void ImportKeyInfo(byte[] keyInfo)
        {
            Gost3410PrivateKeyParameters privateKey = null;
            Gost3410PublicKeyParameters publicKey = null;
            Asn1Object asn1 = Asn1Object.FromByteArray(keyInfo);
            try
            {
                PrivateKeyInfo priInfo = PrivateKeyInfo.GetInstance(asn1);
                privateKey = (Gost3410PrivateKeyParameters)PrivateKeyFactory.CreateKey(priInfo);
                BigInteger y = privateKey.Parameters.A.ModPow(privateKey.X, privateKey.Parameters.P);
                publicKey = new Gost3410PublicKeyParameters(y, privateKey.Parameters);
            }
            catch
            {
                try
                {
                    SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.GetInstance(asn1);
                    publicKey = (Gost3410PublicKeyParameters)PublicKeyFactory.CreateKey(pubInfo);
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
            Gost3410PrivateKeyParameters privateKey = (Gost3410PrivateKeyParameters)PrivateKeyFactory.CreateKey(priInfo);
            BigInteger y = privateKey.Parameters.A.ModPow(privateKey.X, privateKey.Parameters.P);
            Gost3410PublicKeyParameters publicKey = new Gost3410PublicKeyParameters(y, privateKey.Parameters);
            _privateKey = privateKey;
            _publicKey = publicKey;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportParameters(AsymmetricKeyParameter asymmetricKey)
        {
            Gost3410PrivateKeyParameters privateKey = null;
            Gost3410PublicKeyParameters publicKey;
            if (asymmetricKey.IsPrivate)
            {
                privateKey = (Gost3410PrivateKeyParameters)asymmetricKey;
                BigInteger y = privateKey.Parameters.A.ModPow(privateKey.X, privateKey.Parameters.P);
                publicKey = new Gost3410PublicKeyParameters(y, privateKey.Parameters);
            }
            else
            {
                publicKey = (Gost3410PublicKeyParameters)asymmetricKey;
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
            _privateKey = (Gost3410PrivateKeyParameters)keyPair.Private;
            _publicKey = (Gost3410PublicKeyParameters)keyPair.Public;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportPem(string keyPem)
        {
            using (StringReader reader = new StringReader(keyPem))
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
        public override void ImportPem(string privateKeyPem, string password)
        {
            using (StringReader reader = new StringReader(privateKeyPem))
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
        public static GOST3410 Create()
        {
            return new GOST3410();
        }

        internal static AsymmetricAlgorithmName GetAlgorithmName()
        {
            return new AsymmetricAlgorithmName(NAME, AsymmetricAlgorithmKind.Signature, () => { return new GOST3410(); });
        }

        internal static SignatureAlgorithmName GetSignatureAlgorithmName(HashAlgorithmName hashAlgorithm)
        {
            return new SignatureAlgorithmName(GetSignatureAlgorithmMechanism(hashAlgorithm),
                                              () => { return new GOST3410() { _hashAlgorithmName = hashAlgorithm }; });
        }

        private static DerObjectIdentifier GetGOST3410Parameters(GOST3410Parameters parameters)
        {
            switch (parameters)
            {
                case GOST3410Parameters.GostR3410x94CryptoProA: return CryptoProObjectIdentifiers.GostR3410x94CryptoProA;
                case GOST3410Parameters.GostR3410x94CryptoProB: return CryptoProObjectIdentifiers.GostR3410x94CryptoProB;
                //case GOST3410Parameters.GostR3410x94CryptoProC: return CryptoProObjectIdentifiers.GostR3410x94CryptoProC;
                //case GOST3410Parameters.GostR3410x94CryptoProD: return CryptoProObjectIdentifiers.GostR3410x94CryptoProD;
                case GOST3410Parameters.GostR3410x94CryptoProXchA: return CryptoProObjectIdentifiers.GostR3410x94CryptoProXchA;
                //case GOST3410Parameters.GostR3410x94CryptoProXchB: return CryptoProObjectIdentifiers.GostR3410x94CryptoProXchB;
                //case GOST3410Parameters.GostR3410x94CryptoProXchC: return CryptoProObjectIdentifiers.GostR3410x94CryptoProXchC;
                default: throw new CryptographicException("Unsupported GOST3410 parameters.");
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
                    _signer = new Gost3410DigestSigner(new Gost3410Signer(), digest);
                    _signer.Init(true, _privateKey);
                }
            }
            else
            {
                if (_verifier == null)
                {
                    IDigest digest = _hashAlgorithmName.GetEngine();
                    _verifier = new Gost3410DigestSigner(new Gost3410Signer(), digest);
                    _verifier.Init(false, _publicKey);
                }
            }
        }
    }
}