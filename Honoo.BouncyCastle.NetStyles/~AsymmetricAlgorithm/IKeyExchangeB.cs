namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Key exchange algorithm party B's interface.
    /// </summary>
    public interface IKeyExchangeB
    {
        /// <summary>
        /// Gets the asymmetric algorithm kind of the algorithm.
        /// </summary>
        AsymmetricAlgorithmKind Kind { get; }

        /// <summary>
        /// Gets the asymmetric algorithm name of the algorithm.
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Sand this value to party A.
        /// </summary>
        byte[] PublicKeyB { get; }

        /// <summary>
        /// Derive key material.
        /// </summary>
        /// <param name="unsigned">Output unsigned bytes.</param>
        /// <returns></returns>
        byte[] DeriveKeyMaterial(bool unsigned);

        /// <summary>
        /// Renew key exchange parameters of the algorithm.
        /// </summary>
        /// <param name="p">The party A's P value.</param>
        /// <param name="g">The party A's G value.</param>
        /// <param name="publicKeyA">The party A's public key blob.</param>
        void GenerateParameters(byte[] p, byte[] g, byte[] publicKeyA);
    }
}