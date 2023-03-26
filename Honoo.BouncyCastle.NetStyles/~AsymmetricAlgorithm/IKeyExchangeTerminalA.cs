using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Key exchange algorithm terminal A's interface.
    /// </summary>
    public interface IKeyExchangeTerminalA
    {
        /// <summary>
        /// Sand this value to terminal B.
        /// </summary>
        byte[] G { get; }

        /// <summary>
        /// Gets key size bits.
        /// </summary>
        int KeySize { get; }

        /// <summary>
        /// Gets the asymmetric algorithm kind of the algorithm.
        /// </summary>
        AsymmetricAlgorithmKind Kind { get; }

        /// <summary>
        /// Gets legal key size bits. Legal key size 192, 224, 239, 256, 384, 521..
        /// </summary>
        KeySizes[] LegalKeySizes { get; }

        /// <summary>
        /// Gets the asymmetric algorithm name of the algorithm.
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Sand this value to terminal B.
        /// </summary>
        byte[] P { get; }

        /// <summary>
        /// Sand this value to terminal B.
        /// </summary>
        byte[] PublicKeyA { get; }

        /// <summary>
        /// Derive key material from the terminal B's exchange.
        /// </summary>
        /// <param name="publicKeyB">The terminal B's public key blob.</param>
        /// <param name="unsigned">Output unsigned bytes.</param>
        /// <returns></returns>
        byte[] DeriveKeyMaterial(byte[] publicKeyB, bool unsigned);

        /// <summary>
        /// Generate new parameters of algorithm terminal A.
        /// </summary>
        void GenerateParameters();

        /// <summary>
        /// Generate new parameters of algorithm terminal A.
        /// </summary>
        /// <param name="keySize">Legal key size Prime192v1, SecP224r1, Prime239v1, Prime256v1, SecP384r1, SecP521r1.</param>
        /// <param name="certainty">Legal certainty is more than 0.</param>
        void GenerateParameters(int keySize = 521, int certainty = 20);

        /// <summary>
        /// Determines whether the specified size is valid for the current algorithm.
        /// </summary>
        /// <param name="keySize">Legal key size 192, 224, 239, 256, 384, 521.</param>
        /// <param name="exception">Exception message.</param>
        /// <returns></returns>
        bool ValidKeySize(int keySize, out string exception);
    }
}