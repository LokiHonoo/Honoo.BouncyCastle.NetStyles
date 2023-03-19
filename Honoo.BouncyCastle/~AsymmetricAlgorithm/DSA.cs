using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Xml.Linq;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class DSA : AsymmetricAlgorithm
    {
        #region Properties

        private const int DEFAULT_CERTAINTY = 80;
        private const int DEFAULT_KEY_SIZE = 1024;
        private static readonly KeySizes[] LEGAL_KEY_SIZES = new KeySizes[] { new KeySizes(512, 1024, 64) };
        private HashAlgorithmName _hashAlgorithm = HashAlgorithmName.SHA256;
        private bool _initialized = false;
        private int _keySize = DEFAULT_KEY_SIZE;
        private AsymmetricKeyParameter _privateKey = null;
        private AsymmetricKeyParameter _publicKey = null;
        private DSASignatureEncodingMode _signatureEncoding = DSASignatureEncodingMode.Standard;
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
        /// Gets key size bits.
        /// </summary>
        public int KeySize => _keySize;

        /// <summary>
        /// Gets legal key size bits. Legal key size 512-1024 bits (64 bits increments).
        /// </summary>
        public KeySizes[] LegalKeySizes => (KeySizes[])LEGAL_KEY_SIZES.Clone();

        /// <summary>
        /// Gets signature algorithm name.
        /// </summary>
        public string SignatureAlgorithm => $"{_hashAlgorithm.Name}withDSA";

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
        public DSA() : base("DSA", AsymmetricAlgorithmKind.Signature)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static DSA Create()
        {
            return new DSA();
        }

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
        /// Renew private key and public key of the algorithm by default.
        /// </summary>
        public void GenerateParameters()
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
            parametersGenerator.Init(keySize, certainty, Common.SecureRandom);
            DsaParameters parameters = parametersGenerator.GenerateParameters();
            DsaKeyGenerationParameters generationParameters = new DsaKeyGenerationParameters(Common.SecureRandom, parameters);
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

        /// <summary>
        /// Imports a <see cref="DSAParameters"/> that represents asymmetric algorithm key information.
        /// </summary>
        /// <param name="parameters">A <see cref="DSAParameters"/> that represents an asymmetric algorithm key.</param>
        public void ImportParameters(DSAParameters parameters)
        {
            if (parameters.X == null)
            {
                _privateKey = null;
                _publicKey = DotNetUtilities.GetDsaPublicKey(parameters);
            }
            else
            {
                AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetDsaKeyPair(parameters);
                _privateKey = keyPair.Private;
                _publicKey = keyPair.Public;
            }
            _keySize = ((DsaPublicKeyParameters)_publicKey).Parameters.P.BitLength;
            _signer = null;
            _verifier = null;
            _initialized = true;
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
                    _privateKey = keyPair.Private;
                    _publicKey = keyPair.Public;
                }
                else
                {
                    _privateKey = null;
                    _publicKey = (DsaPublicKeyParameters)obj;
                }
                _keySize = ((DsaPublicKeyParameters)_publicKey).Parameters.P.BitLength;
                _signer = null;
                _verifier = null;
                _initialized = true;
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
                _privateKey = keyPair.Private;
                _publicKey = keyPair.Public;
                _keySize = ((DsaPublicKeyParameters)_publicKey).Parameters.P.BitLength;
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
                _privateKey = new DsaPrivateKeyParameters(x, parameters);
                _publicKey = new DsaPublicKeyParameters(y, parameters);
            }
            else
            {
                _privateKey = null;
                _publicKey = new DsaPublicKeyParameters(y, parameters);
            }
            _keySize = ((DsaPublicKeyParameters)_publicKey).Parameters.P.BitLength;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public override void Reset()
        {
            _signer.Reset();
            _verifier.Reset();
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
        /// Determines whether the specified size is valid for the current algorithm.
        /// </summary>
        /// <param name="keySize">Legal key size 512-1024 bits (64 bits increments).</param>
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
            return new AsymmetricAlgorithmName("DSA", AsymmetricAlgorithmKind.Signature, () => { return new DSA(); });
        }

        private void InspectKey()
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
                    IDigest digest = _hashAlgorithm.GetDigest();
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
                    IDigest digest = _hashAlgorithm.GetDigest();
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