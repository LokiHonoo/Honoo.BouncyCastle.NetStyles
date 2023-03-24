using Honoo.BouncyCastle.NetStyles.Utilities;
using Org.BouncyCastle.Asn1;
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
using System;
using System.IO;
using System.Security.Cryptography;
using System.Xml.Linq;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class DSA : AsymmetricAlgorithm, ISignatureAlgorithm
    {
        #region Properties

        private const int DEFAULT_CERTAINTY = 80;
        private const int DEFAULT_KEY_SIZE = 1024;
        private const string NAME = "DSA";
        private static readonly KeySizes[] LEGAL_KEY_SIZES = new KeySizes[] { new KeySizes(512, 1024, 64) };
        private HashAlgorithmName _hashAlgorithmName = HashAlgorithmName.SHA256;
        private int _keySize = DEFAULT_KEY_SIZE;
        private DSASignatureEncodingMode _signatureEncoding = DSASignatureEncodingMode.Standard;
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

        /// <summary>
        /// Gets key size bits.
        /// </summary>
        public int KeySize => _keySize;

        /// <summary>
        /// Gets legal key size bits. Legal key size 512-1024 bits (64 bits increments).
        /// </summary>
        public KeySizes[] LegalKeySizes => (KeySizes[])LEGAL_KEY_SIZES.Clone();

        /// <inheritdoc/>
        public SignatureAlgorithmName SignatureAlgorithmName
        {
            get
            {
                string mechanism = GetSignatureAlgorithmMechanism(_hashAlgorithmName, _signatureEncoding);
                SignatureAlgorithmName.TryGetAlgorithmName(mechanism, out SignatureAlgorithmName algorithmName);
                return algorithmName;
            }
        }

        /// <summary>
        /// Represents the signature encoding mode used in the symmetric algorithm.
        /// </summary>
        public DSASignatureEncodingMode SignatureEncoding
        {
            get => _signatureEncoding;
            set
            {
                if (value != _signatureEncoding)
                {
                    _signer = null;
                    _verifier = null;
                    _signatureEncoding = value;
                }
            }
        }

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the DSA class.
        /// </summary>
        public DSA() : base(NAME, AsymmetricAlgorithmKind.Signature)
        {
        }

        #endregion Construction

        #region GenerateParameters

        /// <inheritdoc/>
        public override void GenerateParameters()
        {
            GenerateParameters(DEFAULT_KEY_SIZE, DEFAULT_CERTAINTY);
        }

        /// <summary>
        /// Renew private key and public key of the algorithm.
        /// </summary>
        /// <param name="keySize">Legal key size 512-1024 bits (64 bits increments).</param>
        /// <param name="certainty">Legal certainty is more than 0.</param>
        public void GenerateParameters(int keySize = DEFAULT_KEY_SIZE, int certainty = DEFAULT_CERTAINTY)
        {
            if (!ValidKeySize(keySize, out string exception))
            {
                throw new CryptographicException(exception);
            }
            if (certainty <= 0)
            {
                throw new CryptographicException("Legal certainty is more than 0.");
            }
            DsaParametersGenerator parametersGenerator = new DsaParametersGenerator();
            parametersGenerator.Init(keySize, certainty, Common.SecureRandom.Value);
            DsaParameters parameters = parametersGenerator.GenerateParameters();
            DsaKeyGenerationParameters generationParameters = new DsaKeyGenerationParameters(Common.SecureRandom.Value, parameters);
            DsaKeyPairGenerator keyPairGenerator = new DsaKeyPairGenerator();
            keyPairGenerator.Init(generationParameters);
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();
            _privateKey = keyPair.Private;
            _publicKey = keyPair.Public;
            _keySize = keySize;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        #endregion GenerateParameters

        #region Export/Import Parameters

        /// <inheritdoc/>
        public override void ImportKeyInfo(byte[] keyInfo)
        {
            DsaPrivateKeyParameters privateKey = null;
            DsaPublicKeyParameters publicKey = null;
            Asn1Object asn1 = Asn1Object.FromByteArray(keyInfo);
            try
            {
                PrivateKeyInfo priInfo = PrivateKeyInfo.GetInstance(asn1);
                privateKey = (DsaPrivateKeyParameters)PrivateKeyFactory.CreateKey(priInfo);
                BigInteger y = privateKey.Parameters.G.ModPow(privateKey.X, privateKey.Parameters.P);
                publicKey = new DsaPublicKeyParameters(y, privateKey.Parameters);
            }
            catch
            {
                try
                {
                    SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.GetInstance(asn1);
                    publicKey = (DsaPublicKeyParameters)PublicKeyFactory.CreateKey(pubInfo);
                }
                catch
                {
                }
            }
            _privateKey = privateKey;
            _publicKey = publicKey;
            _keySize = publicKey.Parameters.P.BitLength;
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
            DsaPrivateKeyParameters privateKey = (DsaPrivateKeyParameters)PrivateKeyFactory.CreateKey(priInfo);
            BigInteger y = privateKey.Parameters.G.ModPow(privateKey.X, privateKey.Parameters.P);
            DsaPublicKeyParameters publicKey = new DsaPublicKeyParameters(y, privateKey.Parameters);
            _privateKey = privateKey;
            _publicKey = publicKey;
            _keySize = publicKey.Parameters.P.BitLength;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <summary>
        /// Imports a <see cref="DSAParameters"/> that represents asymmetric algorithm key information.
        /// </summary>
        /// <param name="parameters">A <see cref="DSAParameters"/> that represents an asymmetric algorithm key.</param>
        public void ImportNetParameters(DSAParameters parameters)
        {
            DsaPrivateKeyParameters privateKey = null;
            DsaPublicKeyParameters publicKey;
            if (parameters.X == null)
            {
                publicKey = DotNetUtilities.GetDsaPublicKey(parameters);
            }
            else
            {
                AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetDsaKeyPair(parameters);
                privateKey = (DsaPrivateKeyParameters)keyPair.Private;
                publicKey = (DsaPublicKeyParameters)keyPair.Public;
            }
            _privateKey = privateKey;
            _publicKey = publicKey;
            _keySize = publicKey.Parameters.P.BitLength;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportParameters(AsymmetricKeyParameter asymmetricKey)
        {
            DsaPrivateKeyParameters privateKey = null;
            DsaPublicKeyParameters publicKey;
            if (asymmetricKey.IsPrivate)
            {
                privateKey = (DsaPrivateKeyParameters)asymmetricKey;
                BigInteger y = privateKey.Parameters.G.ModPow(privateKey.X, privateKey.Parameters.P);
                publicKey = new DsaPublicKeyParameters(y, privateKey.Parameters);
            }
            else
            {
                publicKey = (DsaPublicKeyParameters)asymmetricKey;
            }
            _privateKey = privateKey;
            _publicKey = publicKey;
            _keySize = publicKey.Parameters.P.BitLength;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportParameters(AsymmetricCipherKeyPair keyPair)
        {
            DsaPrivateKeyParameters privateKey = (DsaPrivateKeyParameters)keyPair.Private;
            DsaPublicKeyParameters publicKey = (DsaPublicKeyParameters)keyPair.Public;
            _privateKey = privateKey;
            _publicKey = publicKey;
            _keySize = publicKey.Parameters.P.BitLength;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public override void ImportPem(string keyPem)
        {
            using (StringReader reader = new StringReader(keyPem))
            {
                DsaPrivateKeyParameters privateKey = null;
                DsaPublicKeyParameters publicKey;
                object obj = new PemReader(reader).ReadObject();
                if (obj.GetType() == typeof(AsymmetricCipherKeyPair))
                {
                    AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)obj;
                    privateKey = (DsaPrivateKeyParameters)keyPair.Private;
                    publicKey = (DsaPublicKeyParameters)keyPair.Public;
                }
                else
                {
                    publicKey = (DsaPublicKeyParameters)obj;
                }
                _privateKey = privateKey;
                _publicKey = publicKey;
                _keySize = publicKey.Parameters.P.BitLength;
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
                DsaPrivateKeyParameters privateKey = (DsaPrivateKeyParameters)keyPair.Private;
                DsaPublicKeyParameters publicKey = (DsaPublicKeyParameters)keyPair.Public;
                _privateKey = privateKey;
                _publicKey = publicKey;
                _keySize = publicKey.Parameters.P.BitLength;
                _signer = null;
                _verifier = null;
                _initialized = true;
            }
        }

        /// <summary>
        /// Imports a xml string that represents asymmetric algorithm key information.
        /// </summary>
        /// <param name="xmlString">A xml string that represents an key asymmetric algorithm key.</param>
        public void ImportXml(string xmlString)
        {
            DsaPrivateKeyParameters privateKey = null;
            DsaPublicKeyParameters publicKey;
            StringReader reader = new StringReader(xmlString);
            XElement root = XElement.Load(reader, LoadOptions.None);
            BigInteger p = new BigInteger(1, Convert.FromBase64String(root.Element("P").Value));
            BigInteger q = new BigInteger(1, Convert.FromBase64String(root.Element("Q").Value));
            BigInteger g = new BigInteger(1, Convert.FromBase64String(root.Element("G").Value));
            BigInteger y = new BigInteger(1, Convert.FromBase64String(root.Element("Y").Value));
            DsaValidationParameters validationParameters = null;
            if (root.Element("Seed") != null)
            {
                byte[] seed = Convert.FromBase64String(root.Element("Seed").Value);
                byte[] c = Convert.FromBase64String(root.Element("PgenCounter").Value);
                int counter = c[c.Length - 1];
                if (c.Length > 1) counter |= (c[c.Length - 1 - 1] & 0xFF) << 8;
                if (c.Length > 2) counter |= (c[c.Length - 1 - 2] & 0xFF) << 16;
                if (c.Length > 3) counter |= (c[c.Length - 1 - 3] & 0xFF) << 24;
                validationParameters = new DsaValidationParameters(seed, counter);
            }
            DsaParameters parameters = new DsaParameters(p, q, g, validationParameters);
            XElement element = root.Element("X");
            if (element != null)
            {
                BigInteger x = new BigInteger(1, Convert.FromBase64String(element.Value));
                privateKey = new DsaPrivateKeyParameters(x, parameters);
                publicKey = new DsaPublicKeyParameters(y, parameters);
            }
            else
            {
                publicKey = new DsaPublicKeyParameters(y, parameters);
            }
            _privateKey = privateKey;
            _publicKey = publicKey;
            _keySize = publicKey.Parameters.P.BitLength;
            _signer = null;
            _verifier = null;
            _initialized = true;
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
        public static DSA Create()
        {
            return new DSA();
        }

        /// <summary>
        /// Determines whether the specified size is valid for the current algorithm.
        /// </summary>
        /// <param name="keySize">Legal key size 512-1024 bits (64 bits increments).</param>
        /// <param name="exception">Exception message.</param>
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
                exception = "Legal key size 512-1024 bits (64 bits increments).";
                return false;
            }
        }

        internal static AsymmetricAlgorithmName GetAlgorithmName()
        {
            return new AsymmetricAlgorithmName(NAME, AsymmetricAlgorithmKind.Signature, () => { return new DSA(); });
        }

        internal static SignatureAlgorithmName GetSignatureAlgorithmName(HashAlgorithmName hashAlgorithm, DSASignatureEncodingMode signatureEncoding)
        {
            return new SignatureAlgorithmName(GetSignatureAlgorithmMechanism(hashAlgorithm, signatureEncoding),
                                              () => { return new DSA() { _hashAlgorithmName = hashAlgorithm, _signatureEncoding = signatureEncoding }; });
        }

        private static string GetSignatureAlgorithmMechanism(HashAlgorithmName hashAlgorithm, DSASignatureEncodingMode signatureEncoding)
        {
            //string suffix;
            switch (signatureEncoding)
            {
                case DSASignatureEncodingMode.Standard: break;
                case DSASignatureEncodingMode.Plain: break;
                default: throw new CryptographicException("Unsupported signature padding mode.");
            }
            return $"{hashAlgorithm.Name}with{NAME}";
        }

        private void InspectSigner(bool forSigning)
        {
            if (forSigning)
            {
                if (_signer == null)
                {
                    IDigest digest = _hashAlgorithmName.GetEngine();
                    switch (_signatureEncoding)
                    {
                        case DSASignatureEncodingMode.Standard: _signer = new DsaDigestSigner(new DsaSigner(), digest, StandardDsaEncoding.Instance); break;
                        case DSASignatureEncodingMode.Plain: _signer = new DsaDigestSigner(new DsaSigner(), digest, PlainDsaEncoding.Instance); break;
                        default: throw new CryptographicException("Unsupported signature encoding mode.");
                    }
                    _signer.Init(true, _privateKey);
                }
            }
            else
            {
                if (_verifier == null)
                {
                    IDigest digest = _hashAlgorithmName.GetEngine();
                    switch (_signatureEncoding)
                    {
                        case DSASignatureEncodingMode.Standard: _verifier = new DsaDigestSigner(new DsaSigner(), digest, StandardDsaEncoding.Instance); break;
                        case DSASignatureEncodingMode.Plain: _verifier = new DsaDigestSigner(new DsaSigner(), digest, PlainDsaEncoding.Instance); break;
                        default: throw new CryptographicException("Unsupported signature encoding mode.");
                    }
                    _verifier.Init(false, _publicKey);
                }
            }
        }
    }
}