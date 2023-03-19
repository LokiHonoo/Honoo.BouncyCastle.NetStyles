using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class RSA : AsymmetricAlgorithm
    {
        #region Properties

        private static readonly KeySizes[] _legalKeySizes = new KeySizes[] { new KeySizes(24, Global.SizeMax, 8) };
        private IAsymmetricBlockCipher _decryptor = null;
        private IAsymmetricBlockCipher _encryptor = null;
        private HashAlgorithmName _hashAlgorithm = HashAlgorithmName.SHA256;
        private int _keySize = 0;
        private AsymmetricPaddingMode _padding = AsymmetricPaddingMode.PKCS1;
        private AsymmetricKeyParameter _privateKey = null;
        private AsymmetricKeyParameter _publicKey = null;
        private RSASignaturePaddingMode _signaturePadding = RSASignaturePaddingMode.PKCS1;
        private ISigner _signer = null;
        private ISigner _verifier = null;

        /// <summary>
        /// Gets legal input bytes length on decrypt.
        /// </summary>
        public int DecryptInputLength
        {
            get
            {
                if (_privateKey == null)
                {
                    return 0;
                }
                else if (_keySize > 0)
                {
                    return _keySize / 8;
                }
                else
                {
                    return 0;
                }
            }
        }

        /// <summary>
        /// Gets legal input bytes length on decrypt.
        /// </summary>
        public int DecryptOutputLength
        {
            get
            {
                if (_privateKey == null)
                {
                    return 0;
                }
                else if (_keySize > 0)
                {
                    int length = _keySize / 8;
                    switch (_padding)
                    {
                        case AsymmetricPaddingMode.NoPadding: return length - 1;
                        case AsymmetricPaddingMode.PKCS1: return length - 11;
                        case AsymmetricPaddingMode.OAEP: return length - 42;
                        case AsymmetricPaddingMode.ISO9796_1: return length / 2;
                        default: return 0;
                    }
                }
                else
                {
                    return 0;
                }
            }
        }

        /// <summary>
        /// Gets legal input bytes length on encrypt.
        /// </summary>
        public int EncryptInputLength
        {
            get
            {
                if (_publicKey == null)
                {
                    return 0;
                }
                else if (_keySize > 0)
                {
                    int length = _keySize / 8;
                    switch (_padding)
                    {
                        case AsymmetricPaddingMode.NoPadding: return length - 1;
                        case AsymmetricPaddingMode.PKCS1: return length - 11;
                        case AsymmetricPaddingMode.OAEP: return length - 42;
                        case AsymmetricPaddingMode.ISO9796_1: return length / 2;
                        default: return 0;
                    }
                }
                else
                {
                    return 0;
                }
            }
        }

        /// <summary>
        /// Gets legal input bytes length on encrypt.
        /// </summary>
        public int EncryptOutputLength
        {
            get
            {
                if (_publicKey == null)
                {
                    return 0;
                }
                else if (_keySize > 0)
                {
                    return _keySize / 8;
                }
                else
                {
                    return 0;
                }
            }
        }

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
        public int KeySize => _keySize == 0 ? 2048 : _keySize;

        /// <summary>
        /// Gets legal key size bits. Legal key size is more than or equal to 24 bits (8 bits increments).
        /// </summary>
        public KeySizes[] LegalKeySizes => (KeySizes[])_legalKeySizes.Clone();

        /// <summary>
        /// Represents the padding mode used in the symmetric algorithm.
        /// </summary>
        public AsymmetricPaddingMode Padding
        {
            get => _padding;
            set
            {
                if (value != _padding)
                {
                    _encryptor = null;
                    _decryptor = null;
                    _padding = value;
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
                switch (_signaturePadding)
                {
                    case RSASignaturePaddingMode.PKCS1: suffix = "RSA"; break;
                    case RSASignaturePaddingMode.MGF1: suffix = "RSAandMGF1"; break;
                    case RSASignaturePaddingMode.X931: suffix = "RSA/X9.31"; break;
                    case RSASignaturePaddingMode.ISO9796_2: suffix = "RSA/ISO9796-2"; break;
                    default: throw new CryptographicException("Unsupported signature padding mode.");
                }
                return $"{_hashAlgorithm.Name}with{suffix}";
            }
        }

        /// <summary>
        /// Represents the signature padding mode used in the symmetric algorithm.
        /// </summary>
        public RSASignaturePaddingMode SignaturePadding
        {
            get => _signaturePadding;
            set
            {
                if (value != _signaturePadding)
                {
                    _signer = null;
                    _verifier = null;
                    _signaturePadding = value;
                }
            }
        }

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the RSA class.
        /// </summary>
        public RSA() : base("RSA", AsymmetricAlgorithmKind.SignatureAndEncryption)
        {
        }

        #endregion Construction

        /// <summary>
        /// Decrypts data with the asymmetric algorithm.
        /// </summary>
        /// <param name="rgb">The encrypted data.</param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] rgb)
        {
            return Decrypt(rgb, 0, rgb.Length);
        }

        /// <summary>
        /// Decrypts data with the asymmetric algorithm.
        /// </summary>
        /// <param name="buffer">The encrypted data buffer.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] buffer, int offset, int length)
        {
            InspectKey();
            if (_decryptor == null)
            {
                _decryptor = GenerateCipher(false, null, null);
            }
            return _decryptor.ProcessBlock(buffer, offset, length);
        }

        /// <summary>
        /// Auto set <see cref="Padding"/> = <see cref="AsymmetricPaddingMode.OAEP"/>, Decrypts data with the asymmetric algorithm.
        /// </summary>
        /// <param name="buffer">The encrypted data buffer.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <param name="hashForOAEP">The hash algorithm name for OAEP padding.</param>
        /// <param name="mgf1ForOAEP">The mgf1 algorithm name for OAEP padding.</param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] buffer, int offset, int length, HashAlgorithmName hashForOAEP, HashAlgorithmName mgf1ForOAEP)
        {
            if (hashForOAEP is null)
            {
                throw new ArgumentNullException(nameof(hashForOAEP));
            }
            if (mgf1ForOAEP is null)
            {
                throw new ArgumentNullException(nameof(mgf1ForOAEP));
            }
            InspectKey();
            _padding = AsymmetricPaddingMode.OAEP;
            _decryptor = GenerateCipher(false, hashForOAEP, mgf1ForOAEP);
            return _decryptor.ProcessBlock(buffer, offset, length);
        }

        /// <summary>
        /// Encrypts data with the asymmetric algorithm.
        /// </summary>
        /// <param name="rgb">The data to be decrypted.</param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] rgb)
        {
            return Encrypt(rgb, 0, rgb.Length);
        }

        /// <summary>
        /// Encrypts data with the asymmetric algorithm.
        /// </summary>
        /// <param name="buffer">The data buffer to be decrypted.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] buffer, int offset, int length)
        {
            InspectKey();
            if (_encryptor == null)
            {
                _encryptor = GenerateCipher(true, null, null);
            }
            return _encryptor.ProcessBlock(buffer, offset, length);
        }

        /// <summary>
        /// Auto set <see cref="Padding"/> = <see cref="AsymmetricPaddingMode.OAEP"/>, Encrypts data with the asymmetric algorithm.
        /// </summary>
        /// <param name="buffer">The data buffer to be decrypted.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <param name="hashForOAEP">The hash algorithm name for OAEP padding.</param>
        /// <param name="mgf1ForOAEP">The mgf1 algorithm name for OAEP padding.</param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] buffer, int offset, int length, HashAlgorithmName hashForOAEP, HashAlgorithmName mgf1ForOAEP)
        {
            if (hashForOAEP is null)
            {
                throw new ArgumentNullException(nameof(hashForOAEP));
            }
            if (mgf1ForOAEP is null)
            {
                throw new ArgumentNullException(nameof(mgf1ForOAEP));
            }
            InspectKey();
            _padding = AsymmetricPaddingMode.OAEP;
            _encryptor = GenerateCipher(true, hashForOAEP, mgf1ForOAEP);
            return _encryptor.ProcessBlock(buffer, offset, length);
        }

        /// <summary>
        /// Exports <see cref="RSAParameters"/> containing the asymmetric algorithm key information associated.
        /// </summary>
        /// <param name="includePrivate">true to include the private key; otherwise, false.</param>
        /// <returns></returns>
        public RSAParameters ExportParameters(bool includePrivate)
        {
            InspectKey();
            if (includePrivate)
            {
                return DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)_privateKey);
            }
            else
            {
                return DotNetUtilities.ToRSAParameters((RsaKeyParameters)_publicKey);
            }
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
        /// Imports a xml string that represents asymmetric algorithm key information.
        /// </summary>
        /// <param name="xmlString">A xml string that represents an key asymmetric algorithm key.</param>
        public void FromXmlString(string xmlString)
        {
            StringReader reader = new StringReader(xmlString);
            XElement root = XElement.Load(reader, LoadOptions.None);
            BigInteger modulus = new BigInteger(1, Convert.FromBase64String(root.Element("Modulus").Value));
            BigInteger exponent = new BigInteger(1, Convert.FromBase64String(root.Element("Exponent").Value));
            BigInteger p = null;
            BigInteger q = null;
            BigInteger dp = null;
            BigInteger dq = null;
            BigInteger inverseQ = null;
            BigInteger d = null;
            XElement element = root.Element("P");
            bool isPrivate = element != null;
            if (isPrivate) p = new BigInteger(1, Convert.FromBase64String(element.Value));
            element = root.Element("Q");
            isPrivate = element != null;
            if (isPrivate) q = new BigInteger(1, Convert.FromBase64String(element.Value));
            element = root.Element("DP");
            isPrivate = element != null;
            if (isPrivate) dp = new BigInteger(1, Convert.FromBase64String(element.Value));
            element = root.Element("DQ");
            isPrivate = element != null;
            if (isPrivate) dq = new BigInteger(1, Convert.FromBase64String(element.Value));
            element = root.Element("InverseQ");
            isPrivate = element != null;
            if (isPrivate) inverseQ = new BigInteger(1, Convert.FromBase64String(element.Value));
            element = root.Element("D");
            isPrivate = element != null;
            if (isPrivate) d = new BigInteger(1, Convert.FromBase64String(element.Value));
            if (isPrivate)
            {
                _privateKey = new RsaPrivateCrtKeyParameters(modulus, exponent, d, p, q, dp, dq, inverseQ);
                _publicKey = new RsaKeyParameters(false, modulus, exponent);
            }
            else
            {
                _privateKey = null;
                _publicKey = new RsaKeyParameters(false, modulus, exponent); ;
            }
            _keySize = ((RsaKeyParameters)_publicKey).Modulus.BitLength;
            _encryptor = null;
            _decryptor = null;
            _signer = null;
            _verifier = null;
        }

        /// <summary>
        /// Renew private key and public key of the algorithm.
        /// </summary>
        /// <param name="keySize">Legal key size is more than or equal to 24 bits (8 bits increments).</param>
        /// <param name="certainty">Legal certainty is more than 0.</param>
        public void GenerateKeyPair(int keySize = 2048, int certainty = 25)
        {
            if (!DetectionUtilities.ValidSize(_legalKeySizes, keySize))
            {
                throw new CryptographicException("Legal key size is more than or equal to 24 bits (8 bits increments).");
            }
            if (certainty <= 0)
            {
                throw new CryptographicException("Legal certainty is more than 0.");
            }
            RsaKeyGenerationParameters parameters = new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), Common.SecureRandom, keySize, certainty);
            RsaKeyPairGenerator generator = new RsaKeyPairGenerator();
            generator.Init(parameters);
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
            _privateKey = keyPair.Private;
            _publicKey = keyPair.Public;
            _keySize = keySize;
            _encryptor = null;
            _decryptor = null;
            _signer = null;
            _verifier = null;
        }

        /// <summary>
        /// Imports a <see cref="RSAParameters"/> that represents asymmetric algorithm key information.
        /// </summary>
        /// <param name="parameters">A <see cref="RSAParameters"/> that represents an asymmetric algorithm key.</param>
        public void ImportParameters(RSAParameters parameters)
        {
            if (parameters.D == null)
            {
                _privateKey = null;
                _publicKey = DotNetUtilities.GetRsaPublicKey(parameters); ;
            }
            else
            {
                AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetRsaKeyPair(parameters);
                _privateKey = keyPair.Private;
                _publicKey = keyPair.Public;
            }
            _keySize = ((RsaKeyParameters)_publicKey).Modulus.BitLength;
            _encryptor = null;
            _decryptor = null;
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
                    _privateKey = keyPair.Private;
                    _publicKey = keyPair.Public;
                }
                else
                {
                    _privateKey = null;
                    _publicKey = (RsaKeyParameters)obj;
                }
                _keySize = ((RsaKeyParameters)_publicKey).Modulus.BitLength;
                _encryptor = null;
                _decryptor = null;
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
                _privateKey = keyPair.Private;
                _publicKey = keyPair.Public;
                _keySize = ((RsaKeyParameters)_publicKey).Modulus.BitLength;
                _encryptor = null;
                _decryptor = null;
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
        /// Exports a xml string containing the asymmetric algorithm key information associated.
        /// </summary>
        /// <param name="includePrivate">true to include the private key; otherwise, false.</param>
        /// <returns></returns>
        public string ToXmlString(bool includePrivate)
        {
            InspectKey();
            if (includePrivate)
            {
                RSAParameters parameters = ExportParameters(true);
                XElement root = new XElement("RSAKeyValue");
                root.Add(new XElement("Modulus", Convert.ToBase64String(parameters.Modulus)));
                root.Add(new XElement("Exponent", Convert.ToBase64String(parameters.Exponent)));
                root.Add(new XElement("P", Convert.ToBase64String(parameters.P)));
                root.Add(new XElement("Q", Convert.ToBase64String(parameters.Q)));
                root.Add(new XElement("DP", Convert.ToBase64String(parameters.DP)));
                root.Add(new XElement("DQ", Convert.ToBase64String(parameters.DQ)));
                root.Add(new XElement("InverseQ", Convert.ToBase64String(parameters.InverseQ)));
                root.Add(new XElement("D", Convert.ToBase64String(parameters.D)));
                StringBuilder builder = new StringBuilder();
                XmlWriterSettings settings = new XmlWriterSettings() { Indent = true, Encoding = new UTF8Encoding(false), OmitXmlDeclaration = true };
                using (XmlWriter writer = XmlWriter.Create(builder, settings))
                {
                    root.Save(writer);
                    writer.Flush();
                    return builder.ToString();
                }
            }
            else
            {
                RsaKeyParameters key = (RsaKeyParameters)_publicKey;
                XElement root = new XElement("RSAKeyValue");
                root.Add(new XElement("Modulus", Convert.ToBase64String(key.Modulus.ToByteArray())));
                root.Add(new XElement("Exponent", Convert.ToBase64String(key.Exponent.ToByteArray())));
                StringBuilder builder = new StringBuilder();
                XmlWriterSettings settings = new XmlWriterSettings() { Indent = true, Encoding = new UTF8Encoding(false), OmitXmlDeclaration = true };
                using (XmlWriter writer = XmlWriter.Create(builder, settings))
                {
                    root.Save(writer);
                    writer.Flush();
                    return builder.ToString();
                }
            }
        }

        /// <summary>
        /// Determines whether the specified key size is valid for the current algorithm.
        /// </summary>
        /// <param name="keySize">Key size bits.</param>
        /// <returns></returns>
        public bool ValidKeySize(int keySize)
        {
            return DetectionUtilities.ValidSize(_legalKeySizes, keySize);
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
            return new AsymmetricAlgorithmName("RSA", AsymmetricAlgorithmKind.SignatureAndEncryption, () => { return new RSA(); });
        }

        private IAsymmetricBlockCipher GenerateCipher(bool forEncryption, HashAlgorithmName hash, HashAlgorithmName mgf1)
        {
            IAsymmetricBlockCipher cipher = new RsaBlindedEngine();
            switch (_padding)
            {
                case AsymmetricPaddingMode.NoPadding: break;
                case AsymmetricPaddingMode.PKCS1: cipher = new Pkcs1Encoding(cipher); break;
                case AsymmetricPaddingMode.OAEP:
                    if (hash == null && mgf1 == null)
                    {
                        cipher = new OaepEncoding(cipher);
                    }
                    else if (hash == null)
                    {
                        cipher = new OaepEncoding(cipher, null, mgf1.GenerateDigest(), null);
                    }
                    else if (mgf1 == null)
                    {
                        cipher = new OaepEncoding(cipher, hash.GenerateDigest(), null, null);
                    }
                    else
                    {
                        cipher = new OaepEncoding(cipher, hash.GenerateDigest(), mgf1.GenerateDigest(), null);
                    }
                    break;

                case AsymmetricPaddingMode.ISO9796_1: cipher = new ISO9796d1Encoding(cipher); break;
                default: throw new CryptographicException("Unsupported padding mode.");
            }
            cipher.Init(forEncryption, forEncryption ? _publicKey : _privateKey);
            return cipher;
        }

        private void InspectKey()
        {
            if (_keySize == 0)
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
                    switch (_signaturePadding)
                    {
                        case RSASignaturePaddingMode.PKCS1: _signer = new RsaDigestSigner(digest); break;
                        case RSASignaturePaddingMode.MGF1: _signer = new PssSigner(new RsaBlindedEngine(), digest); break;
                        case RSASignaturePaddingMode.X931: _signer = new X931Signer(new RsaBlindedEngine(), digest); break;
                        case RSASignaturePaddingMode.ISO9796_2: _signer = new Iso9796d2Signer(new RsaBlindedEngine(), digest); break;
                        default: throw new CryptographicException("Unsupported signature padding mode.");
                    }
                    _signer.Init(forSigning, _privateKey);
                }
            }
            else
            {
                if (_verifier == null)
                {
                    IDigest digest = _hashAlgorithm.GenerateDigest();
                    switch (_signaturePadding)
                    {
                        case RSASignaturePaddingMode.PKCS1: _verifier = new RsaDigestSigner(digest); break;
                        case RSASignaturePaddingMode.MGF1: _verifier = new PssSigner(new RsaBlindedEngine(), digest); break;
                        case RSASignaturePaddingMode.X931: _verifier = new X931Signer(new RsaBlindedEngine(), digest); break;
                        case RSASignaturePaddingMode.ISO9796_2: _verifier = new Iso9796d2Signer(new RsaBlindedEngine(), digest); break;
                        default: throw new CryptographicException("Unsupported signature padding mode.");
                    }
                    _verifier.Init(false, _publicKey);
                }
            }
        }
    }
}