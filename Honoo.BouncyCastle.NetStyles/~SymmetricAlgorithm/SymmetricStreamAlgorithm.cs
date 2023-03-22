using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Represents the abstract base class from which all implementations of symmetric stream algorithms must inherit.
    /// </summary>
    public abstract class SymmetricStreamAlgorithm : SymmetricAlgorithm
    {
        #region Properties

        private readonly int _defaultIVSize;
        private readonly int _defaultKeySize;

        /// <summary>
        /// Gets or sets the mode for operation of the symmetric algorithm. Valid for block algorithm only.
        /// </summary>
        public override SymmetricCipherMode Mode { get => _mode; set => _mode = value; }

        /// <summary>
        /// Gets or sets the padding mode used in the symmetric algorithm. Valid for block algorithm only.
        /// </summary>
        public override SymmetricPaddingMode Padding { get => _padding; set => _padding = value; }

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the SymmetricStreamAlgorithm class.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="defaultKeySize"></param>
        /// <param name="defaultIVSize"></param>
        protected SymmetricStreamAlgorithm(string name, int defaultKeySize, int defaultIVSize)
            : base(name, SymmetricAlgorithmKind.Stream, 0, defaultKeySize, defaultIVSize)
        {
            _defaultKeySize = defaultKeySize;
            _defaultIVSize = defaultIVSize;
        }

        #endregion Construction

        /// <summary>
        /// Renew parameters of the algorithm by default key size and iv size.
        /// </summary>
        public override void GenerateParameters()
        {
            GenerateParameters(_defaultKeySize, _defaultIVSize);
        }

        /// <inheritdoc/>
        public override void ImportParameters(ICipherParameters parameters)
        {
            int keySize;
            int ivSize;
            ICipherParameters parameters1;
            if (parameters.GetType() == typeof(AeadParameters))
            {
                throw new CryptographicException("AeadParameters not supported of symmetric stream algorithm.");
            }
            else if (parameters.GetType() == typeof(ParametersWithIV))
            {
                ParametersWithIV parameters2 = (ParametersWithIV)parameters;
                byte[] iv = parameters2.GetIV();
                ivSize = iv == null ? 0 : iv.Length * 8;
                if (!ValidIVSize(ivSize, out string exception))
                {
                    throw new CryptographicException(exception);
                }
                byte[] key = ((KeyParameter)parameters2.Parameters).GetKey();
                keySize = key.Length * 8;
                if (!ValidKeySize(keySize, out exception))
                {
                    throw new CryptographicException(exception);
                }
                parameters1 = GetKeyParameter(key);
                if (ivSize > 0)
                {
                    parameters1 = new ParametersWithIV(parameters1, iv);
                }
            }
            else
            {
                KeyParameter parameter = (KeyParameter)parameters;
                ivSize = 0;
                if (!ValidIVSize(ivSize, out string exception))
                {
                    throw new CryptographicException(exception);
                }
                byte[] key = parameter.GetKey();
                keySize = key.Length * 8;
                if (!ValidKeySize(keySize, out exception))
                {
                    throw new CryptographicException(exception);
                }
                parameters1 = GetKeyParameter(key);
            }
            _parameters = parameters1;
            _keySize = keySize;
            _ivSize = ivSize;
            _encryptor = null;
            _decryptor = null;
            _initialized = true;
        }

        /// <summary>
        ///
        /// </summary>
        /// <returns></returns>
        internal abstract IStreamCipher GetEngine();

        /// <summary>
        ///
        /// </summary>
        /// <param name="forEncryption"></param>
        /// <returns></returns>
        protected override IBufferedCipher GetCipher(bool forEncryption)
        {
            IStreamCipher engine = GetEngine();
            IBufferedCipher cipher = new BufferedStreamCipher(engine);
            cipher.Init(forEncryption, _parameters);
            return cipher;
        }
    }
}