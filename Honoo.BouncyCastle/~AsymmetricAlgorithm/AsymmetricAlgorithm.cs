using System;

namespace Honoo.BouncyCastle
{
    /// <summary>
    /// Represents the abstract base class from which all implementations of asymmetric algorithms must inherit.
    /// </summary>
    public abstract class AsymmetricAlgorithm : IAsymmetricAlgorithm
    {
        #region Properties

        private readonly AsymmetricAlgorithmKind _kind;
        private readonly string _name;

        /// <summary>
        /// Gets the asymmetric algorithm kind of the algorithm.
        /// </summary>
        public AsymmetricAlgorithmKind Kind => _kind;

        /// <summary>
        /// Gets the asymmetric algorithm name of the algorithm.
        /// </summary>
        public string Name => _name;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the AsymmetricAlgorithm class.
        /// </summary>
        /// <param name="name"></param>
        /// <param name="kind"></param>
        protected AsymmetricAlgorithm(string name, AsymmetricAlgorithmKind kind)
        {
            _name = name;
            _kind = kind;
        }

        #endregion Construction

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">Asymmetric algorithm name.</param>
        /// <returns></returns>
        public static AsymmetricAlgorithm Create(AsymmetricAlgorithmName algorithmName)
        {
            return algorithmName.GetAlgorithm();
        }

        /// <summary>
        /// Creates an instance of the algorithm by algorithm name.
        /// </summary>
        /// <param name="algorithmName">Signature algorithm name.</param>
        /// <returns></returns>
        public static AsymmetricAlgorithm Create(SignatureAlgorithmName algorithmName)
        {
            return algorithmName.GetAlgorithm();
        }

        /// <summary>
        /// Gets encryption algorithm interface.
        /// Throw <see cref="NotImplementedException"/> if this algorithm is not a encryption algorithm.
        /// </summary>
        /// <returns></returns>
        public abstract IAsymmetricEncryptionAlgorithm GetEncryptionInterface();

        /// <summary>
        /// Gets key exchange algorithm party A's interface.
        /// Throw <see cref="NotImplementedException"/> if this algorithm is not a key exchange algorithm.
        /// </summary>
        /// <returns></returns>
        public abstract IKeyExchangeA GetKeyExchangeAInterface();

        /// <summary>
        /// Gets key exchange algorithm party B's interface.
        /// Throw <see cref="NotImplementedException"/> if this algorithm is not a key exchange algorithm.
        /// </summary>
        /// <returns></returns>
        public abstract IKeyExchangeB GetKeyExchangeBInterface();

        /// <summary>
        /// Gets signature algorithm interface.
        /// Throw <see cref="NotImplementedException"/> if this algorithm is not a signature algorithm.
        /// </summary>
        /// <returns></returns>
        public abstract IAsymmetricSignatureAlgorithm GetSignatureInterface();
    }
}