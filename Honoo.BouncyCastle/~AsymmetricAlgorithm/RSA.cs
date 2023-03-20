using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
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
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class RSA : AsymmetricAlgorithm, IAsymmetricEncryptionAlgorithm, IAsymmetricSignatureAlgorithm
    {
        #region Properties
        private const int DEFAULT_CERTAINTY = 25;
        private const int DEFAULT_KEY_SIZE = 2048;
        private const string NAME = "RSA";
        private static readonly KeySizes[] LEGAL_KEY_SIZES = new KeySizes[] { new KeySizes(24, Common.SizeMax, 8) };
        private IAsymmetricBlockCipher _decryptor = null;
        private IAsymmetricBlockCipher _encryptor = null;
        private HashAlgorithmName _hashAlgorithm = HashAlgorithmName.SHA256;
        private bool _initialized = false;
        private int _keySize = DEFAULT_KEY_SIZE;
        private AsymmetricEncryptionPaddingMode _padding = AsymmetricEncryptionPaddingMode.PKCS1;
        private AsymmetricKeyParameter _privateKey = null;
        private AsymmetricKeyParameter _publicKey = null;
        private RSASignaturePaddingMode _signaturePadding = RSASignaturePaddingMode.PKCS1;
        private ISigner _signer = null;
        private ISigner _verifier = null;

        /// <inheritdoc/>

        public int DecryptInputLength
        {
            get
            {
                if (_initialized)
                {
                    if (_privateKey == null)
                    {
                        return 0;
                    }
                    else
                    {
                        return _keySize / 8;
                    }
                }
                else
                {
                    return _keySize / 8;
                }
            }
        }

        /// <inheritdoc/>
        public int DecryptOutputLength
        {
            get
            {
                if (_initialized)
                {
                    if (_privateKey == null)
                    {
                        return 0;
                    }
                    else
                    {
                        return GetPaddedLength();
                    }
                }
                else
                {
                    return GetPaddedLength();
                }
            }
        }

        /// <inheritdoc/>
        public int EncryptInputLength => GetPaddedLength();

        /// <inheritdoc/>
        public int EncryptOutputLength => _keySize / 8;

        /// <inheritdoc/>
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
        /// Gets legal key size bits. Legal key size is more than or equal to 24 bits (8 bits increments).
        /// </summary>
        public KeySizes[] LegalKeySizes => (KeySizes[])LEGAL_KEY_SIZES.Clone();

        /// <inheritdoc/>
        public AsymmetricEncryptionPaddingMode Padding
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

        /// <inheritdoc/>
        public string SignatureAlgorithm => GetSignatureAlgorithmMechanism(_hashAlgorithm, _signaturePadding);

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
        public RSA() : base(NAME, AsymmetricAlgorithmKind.SignatureAndEncryption)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static RSA Create()
        {
            return new RSA();
        }

        #region GenerateParameters

        /// <inheritdoc/>
        public void GenerateParameters()
        {
            GenerateParameters(DEFAULT_KEY_SIZE, DEFAULT_CERTAINTY);
        }

        /// <summary>
        /// Renew private key and public key of the algorithm.
        /// </summary>
        /// <param name="keySize">Legal key size is more than or equal to 24 bits (8 bits increments).</param>
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

        /// <summary>
        /// Exports <see cref="RSAParameters"/> containing the asymmetric algorithm key information associated.
        /// </summary>
        /// <param name="includePrivate">true to include the private key; otherwise, false.</param>
        /// <returns></returns>
        public RSAParameters ExportParameters(bool includePrivate)
        {
            InspectParameters();
            if (includePrivate)
            {
                return DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)_privateKey);
            }
            else
            {
                return DotNetUtilities.ToRSAParameters((RsaKeyParameters)_publicKey);
            }
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

        /// <summary>
        /// Exports a xml string containing the asymmetric algorithm key information associated.
        /// </summary>
        /// <param name="includePrivate">true to include the private key; otherwise, false.</param>
        /// <returns></returns>
        public string ExportXml(bool includePrivate)
        {
            InspectParameters();
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

        /// <inheritdoc/>
        public void ImportKeyInfo(byte[] keyInfo)
        {
            RsaPrivateCrtKeyParameters privateKey = null;
            RsaKeyParameters publicKey = null;
            Asn1Object asn1 = Asn1Object.FromByteArray(keyInfo);
            try
            {
                PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.GetInstance(asn1);
                privateKey = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(privateKeyInfo);
                publicKey = new RsaKeyParameters(false, privateKey.Modulus, privateKey.PublicExponent);
            }
            catch
            {
                try
                {
                    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.GetInstance(asn1);
                    publicKey = (RsaKeyParameters)PublicKeyFactory.CreateKey(publicKeyInfo);
                }
                catch
                {
                }
            }
            _privateKey = privateKey;
            _publicKey = publicKey;
            _keySize = publicKey.Modulus.BitLength;
            _encryptor = null;
            _decryptor = null;
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
            RsaPrivateCrtKeyParameters privateKey = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(privateKeyInfo);
            RsaKeyParameters publicKey = new RsaKeyParameters(false, privateKey.Modulus, privateKey.PublicExponent);
            _privateKey = privateKey;
            _publicKey = publicKey;
            _keySize = publicKey.Modulus.BitLength;
            _encryptor = null;
            _decryptor = null;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <summary>
        /// Imports a <see cref="RSAParameters"/> that represents asymmetric algorithm key information.
        /// </summary>
        /// <param name="parameters">A <see cref="RSAParameters"/> that represents an asymmetric algorithm key.</param>
        public void ImportParameters(RSAParameters parameters)
        {
            RsaPrivateCrtKeyParameters privateKey = null;
            RsaKeyParameters publicKey;
            if (parameters.D == null)
            {
                publicKey = DotNetUtilities.GetRsaPublicKey(parameters);
            }
            else
            {
                AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetRsaKeyPair(parameters);
                privateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;
                publicKey = (RsaKeyParameters)keyPair.Public;
            }
            _privateKey = privateKey;
            _publicKey = publicKey;
            _keySize = publicKey.Modulus.BitLength;
            _encryptor = null;
            _decryptor = null;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        /// <inheritdoc/>
        public void ImportPem(string pem)
        {
            using (StringReader reader = new StringReader(pem))
            {
                RsaPrivateCrtKeyParameters privateKey = null;
                RsaKeyParameters publicKey;
                object obj = new PemReader(reader).ReadObject();
                if (obj.GetType() == typeof(AsymmetricCipherKeyPair))
                {
                    AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)obj;
                    privateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;
                    publicKey = (RsaKeyParameters)keyPair.Public;
                }
                else
                {
                    publicKey = (RsaKeyParameters)obj;
                }
                _privateKey = privateKey;
                _publicKey = publicKey;
                _keySize = publicKey.Modulus.BitLength;
                _encryptor = null;
                _decryptor = null;
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
                RsaPrivateCrtKeyParameters privateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;
                RsaKeyParameters publicKey = (RsaKeyParameters)keyPair.Public;
                _privateKey = privateKey;
                _publicKey = publicKey;
                _keySize = publicKey.Modulus.BitLength;
                _encryptor = null;
                _decryptor = null;
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
            RsaPrivateCrtKeyParameters privateKey = null;
            RsaKeyParameters publicKey;
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
                privateKey = new RsaPrivateCrtKeyParameters(modulus, exponent, d, p, q, dp, dq, inverseQ);
                publicKey = new RsaKeyParameters(false, modulus, exponent);
            }
            else
            {
                publicKey = new RsaKeyParameters(false, modulus, exponent); ;
            }
            _privateKey = privateKey;
            _publicKey = publicKey;
            _keySize = publicKey.Modulus.BitLength;
            _encryptor = null;
            _decryptor = null;
            _signer = null;
            _verifier = null;
            _initialized = true;
        }

        #endregion Export/Import Parameters

        /// <inheritdoc/>
        public byte[] Decrypt(byte[] rgb)
        {
            return Decrypt(rgb, 0, rgb.Length);
        }

        /// <inheritdoc/>
        public byte[] Decrypt(byte[] buffer, int offset, int length)
        {
            InspectParameters();
            if (_decryptor == null)
            {
                _decryptor = GetCipher(false, null, null);
            }
            return _decryptor.ProcessBlock(buffer, offset, length);
        }

        /// <inheritdoc/>
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
            InspectParameters();
            _padding = AsymmetricEncryptionPaddingMode.OAEP;
            _decryptor = GetCipher(false, hashForOAEP, mgf1ForOAEP);
            return _decryptor.ProcessBlock(buffer, offset, length);
        }

        /// <inheritdoc/>
        public byte[] Encrypt(byte[] rgb)
        {
            return Encrypt(rgb, 0, rgb.Length);
        }

        /// <inheritdoc/>
        public byte[] Encrypt(byte[] buffer, int offset, int length)
        {
            InspectParameters();
            if (_encryptor == null)
            {
                _encryptor = GetCipher(true, null, null);
            }
            return _encryptor.ProcessBlock(buffer, offset, length);
        }

        /// <inheritdoc/>
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
            InspectParameters();
            _padding = AsymmetricEncryptionPaddingMode.OAEP;
            _encryptor = GetCipher(true, hashForOAEP, mgf1ForOAEP);
            return _encryptor.ProcessBlock(buffer, offset, length);
        }

        /// <inheritdoc/>
        public override IAsymmetricEncryptionAlgorithm GetEncryptionInterface()
        {
            return this;
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
            _signer.Reset();
            _verifier.Reset();
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
                exception = "Legal key size is more than or equal to 24 bits (8 bits increments).";
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
            return new AsymmetricAlgorithmName(NAME, AsymmetricAlgorithmKind.SignatureAndEncryption, () => { return new RSA(); });
        }

        internal static SignatureAlgorithmName GetSignatureAlgorithmName(HashAlgorithmName hashAlgorithm, RSASignaturePaddingMode signaturePadding)
        {
            return new SignatureAlgorithmName(GetSignatureAlgorithmMechanism(hashAlgorithm, signaturePadding),
                                              () => { return new RSA() { HashAlgorithm = hashAlgorithm, SignaturePadding = signaturePadding }; });
        }

        private static string GetSignatureAlgorithmMechanism(HashAlgorithmName hashAlgorithm, RSASignaturePaddingMode signaturePadding)
        {
            string suffix;
            switch (signaturePadding)
            {
                case RSASignaturePaddingMode.PKCS1: suffix = "RSA"; break;
                case RSASignaturePaddingMode.MGF1: suffix = "RSAandMGF1"; break;
                case RSASignaturePaddingMode.X931: suffix = "RSA/X9.31"; break;
                case RSASignaturePaddingMode.ISO9796_2: suffix = "RSA/ISO9796-2"; break;
                default: throw new CryptographicException("Unsupported signature padding mode.");
            }
            return $"{hashAlgorithm.Name}with{suffix}";
        }

        private IAsymmetricBlockCipher GetCipher(bool forEncryption, HashAlgorithmName hash, HashAlgorithmName mgf1)
        {
            IAsymmetricBlockCipher cipher = new RsaBlindedEngine();
            switch (_padding)
            {
                case AsymmetricEncryptionPaddingMode.NoPadding: break;
                case AsymmetricEncryptionPaddingMode.PKCS1: cipher = new Pkcs1Encoding(cipher); break;
                case AsymmetricEncryptionPaddingMode.OAEP:
                    if (hash == null && mgf1 == null)
                    {
                        cipher = new OaepEncoding(cipher);
                    }
                    else if (hash == null)
                    {
                        cipher = new OaepEncoding(cipher, null, mgf1.GetDigest(), null);
                    }
                    else if (mgf1 == null)
                    {
                        cipher = new OaepEncoding(cipher, hash.GetDigest(), null, null);
                    }
                    else
                    {
                        cipher = new OaepEncoding(cipher, hash.GetDigest(), mgf1.GetDigest(), null);
                    }
                    break;

                case AsymmetricEncryptionPaddingMode.ISO9796_1: cipher = new ISO9796d1Encoding(cipher); break;
                default: throw new CryptographicException("Unsupported padding mode.");
            }
            cipher.Init(forEncryption, forEncryption ? _publicKey : _privateKey);
            return cipher;
        }

        private int GetPaddedLength()
        {
            int length = _keySize / 8;
            switch (_padding)
            {
                case AsymmetricEncryptionPaddingMode.NoPadding: return length - 1;
                case AsymmetricEncryptionPaddingMode.PKCS1: return length - 11;
                case AsymmetricEncryptionPaddingMode.OAEP: return length - 42;
                case AsymmetricEncryptionPaddingMode.ISO9796_1: return length / 2;
                default: throw new CryptographicException("Unsupported padding mode.");
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
                    IDigest digest = _hashAlgorithm.GetDigest();
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
                    IDigest digest = _hashAlgorithm.GetDigest();
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