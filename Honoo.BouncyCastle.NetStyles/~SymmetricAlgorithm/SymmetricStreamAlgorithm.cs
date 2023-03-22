using Org.BouncyCastle.Crypto;

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