using Honoo.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using System;
using System.IO;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class ElGamal : AsymmetricAlgorithm
    {
        #region Properties

        private const int DEFAULT_CERTAINTY = 20;
        private const int DEFAULT_KEY_SIZE = 768;
        private static readonly KeySizes[] LEGAL_KEY_SIZES = new KeySizes[] { new KeySizes(8, Common.SizeMax, 8) };
        private IAsymmetricBlockCipher _decryptor = null;
        private IAsymmetricBlockCipher _encryptor = null;
        private bool _initialized = false;
        private int _keySize = DEFAULT_KEY_SIZE;
        private AsymmetricPaddingMode _padding = AsymmetricPaddingMode.PKCS1;
        private AsymmetricKeyParameter _privateKey = null;
        private AsymmetricKeyParameter _publicKey = null;

        /// <summary>
        /// Gets legal input bytes length on decrypt.
        /// </summary>
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
                        return _padding == AsymmetricPaddingMode.ISO9796_1 ? 0 : _keySize / 4;
                    }
                }
                else
                {
                    return _padding == AsymmetricPaddingMode.ISO9796_1 ? 0 : _keySize / 4;
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

        /// <summary>
        /// Gets legal input bytes length on encrypt.
        /// </summary>
        public int EncryptInputLength => GetPaddedLength();

        /// <summary>
        /// Gets legal input bytes length on encrypt.
        /// </summary>
        public int EncryptOutputLength => _padding == AsymmetricPaddingMode.ISO9796_1 ? 0 : _keySize / 4;

        /// <summary>
        /// Get or set key size bits.
        /// </summary>
        public int KeySize => _keySize;

        /// <summary>
        /// Gets legal key size bits. Legal key size is more than or equal to 8 bits (8 bits increments).
        /// </summary>
        public KeySizes[] LegalKeySizes => (KeySizes[])LEGAL_KEY_SIZES.Clone();

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

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the ElGamal class.
        /// </summary>
        public ElGamal() : base("ElGamal", AsymmetricAlgorithmKind.Encryption)
        {
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static ElGamal Create()
        {
            return new ElGamal();
        }

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
                _decryptor = GetCipher(false, null, null);
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
            _decryptor = GetCipher(false, hashForOAEP, mgf1ForOAEP);
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
                _encryptor = GetCipher(true, null, null);
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
            _encryptor = GetCipher(true, hashForOAEP, mgf1ForOAEP);
            return _encryptor.ProcessBlock(buffer, offset, length);
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
        /// <param name="keySize">Legal key size is more than or equal to 8 bits (8 bits increments).</param>
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
            ElGamalParametersGenerator parametersGenerator = new ElGamalParametersGenerator();
            parametersGenerator.Init(keySize, certainty, Common.SecureRandom);
            ElGamalParameters parameters = parametersGenerator.GenerateParameters();
            ElGamalKeyGenerationParameters generationParameters = new ElGamalKeyGenerationParameters(Common.SecureRandom, parameters);
            ElGamalKeyPairGenerator keyPairGenerator = new ElGamalKeyPairGenerator();
            keyPairGenerator.Init(generationParameters);
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();
            _privateKey = keyPair.Private;
            _publicKey = keyPair.Public;
            _keySize = keySize;
            _encryptor = null;
            _decryptor = null;
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
                if (obj.GetType() == typeof(ElGamalPrivateKeyParameters))
                {
                    ElGamalPrivateKeyParameters privateKey = (ElGamalPrivateKeyParameters)obj;
                    _privateKey = privateKey;
                    BigInteger y = privateKey.Parameters.G.ModPow(privateKey.X, privateKey.Parameters.P);
                    _publicKey = new ElGamalPublicKeyParameters(y, privateKey.Parameters);
                }
                else
                {
                    _privateKey = null;
                    _publicKey = (ElGamalPublicKeyParameters)obj;
                }
                _keySize = ((ElGamalPublicKeyParameters)_publicKey).Parameters.P.BitLength;
                _encryptor = null;
                _decryptor = null;
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
                ElGamalPrivateKeyParameters privateKey = (ElGamalPrivateKeyParameters)obj;
                _privateKey = privateKey;
                BigInteger y = privateKey.Parameters.G.ModPow(privateKey.X, privateKey.Parameters.P);
                _publicKey = new ElGamalPublicKeyParameters(y, privateKey.Parameters);
                _keySize = ((ElGamalPublicKeyParameters)_publicKey).Parameters.P.BitLength;
                _encryptor = null;
                _decryptor = null;
                _initialized = true;
            }
        }
        /// <inheritdoc/>
        public override void Reset()
        {
        }
        /// <summary>
        /// Determines whether the specified size is valid for the current algorithm.
        /// </summary>
        /// <param name="keySize">Legal key size is more than or equal to 8 bits (8 bits increments).</param>
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
                exception = "Legal key size is more than or equal to 8 bits (8 bits increments).";
                return false;
            }
        }

        internal static AsymmetricAlgorithmName GetAlgorithmName()
        {
            return new AsymmetricAlgorithmName("ElGamal", AsymmetricAlgorithmKind.Encryption, () => { return new ElGamal(); });
        }

        private IAsymmetricBlockCipher GetCipher(bool encryption, HashAlgorithmName hash, HashAlgorithmName mgf1)
        {
            IAsymmetricBlockCipher cipher = new ElGamalEngine();
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

                case AsymmetricPaddingMode.ISO9796_1: throw new CryptographicException("ElGamal is unsupported ISO9796_1 padding mode.");
                default: throw new CryptographicException("Unsupported padding mode.");
            }
            cipher.Init(encryption, encryption ? _publicKey : _privateKey);
            return cipher;
        }

        private int GetPaddedLength()
        {
            int length = _keySize / 8;
            switch (_padding)
            {
                case AsymmetricPaddingMode.NoPadding: return length - 1;
                case AsymmetricPaddingMode.PKCS1: return length - 11;
                case AsymmetricPaddingMode.OAEP: return length - 42;
                case AsymmetricPaddingMode.ISO9796_1: return 0;
                default: throw new CryptographicException("Unsupported padding mode.");
            }
        }

        private void InspectKey()
        {
            if (!_initialized)
            {
                GenerateParameters();
            }
        }
    }
}