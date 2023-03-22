namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Asymmetric signature algorithm interface.
    /// </summary>
    public interface IAsymmetricSignatureAlgorithm : IAsymmetricParameters
    {
        /// <summary>
        /// Get or set Hash algorithm for signature.
        /// </summary>
        HashAlgorithmName HashAlgorithm { get; set; }

        /// <summary>
        /// Gets signature algorithm name.
        /// </summary>
        string SignatureAlgorithm { get; }

        /// <summary>
        /// Reset signer/verifier calculator of the algorithm.
        /// </summary>
        void Reset();

        /// <summary>
        /// Signs the specified input bytes using the specified hash algorithm.
        /// </summary>
        /// <returns></returns>
        byte[] SignFinal();

        /// <summary>
        /// Signs the specified input bytes using the specified hash algorithm.
        /// </summary>
        /// <param name="rgb">The input data for which to sign.</param>
        byte[] SignFinal(byte[] rgb);

        /// <summary>
        /// Signs the specified input bytes using the specified hash algorithm.
        /// </summary>
        /// <param name="buffer">The input data of buffer for which to sign.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        byte[] SignFinal(byte[] buffer, int offset, int length);

        /// <summary>
        /// Signs the specified input bytes using the specified hash algorithm.
        /// </summary>
        /// <param name="rgb">The input data for which to sign.</param>
        void SignUpdate(byte[] rgb);

        /// <summary>
        /// Signs the specified input bytes using the specified hash algorithm.
        /// </summary>
        /// <param name="buffer">The data buffer.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        void SignUpdate(byte[] buffer, int offset, int length);

        /// <summary>
        /// Verifies that a digital signature of the specified input bytes using the specified hash algorithm.
        /// </summary>
        /// <param name="signature">The signature data to be verified.</param>
        /// <returns></returns>
        bool VerifyFinal(byte[] signature);

        /// <summary>
        /// Verifies that a digital signature of the specified input bytes using the specified hash algorithm.
        /// </summary>
        /// <param name="rgb">The input data for which to compute the hash.</param>
        /// <param name="signature">The signature data to be verified.</param>
        bool VerifyFinal(byte[] rgb, byte[] signature);

        /// <summary>
        /// Verifies that a digital signature of the specified input bytes using the specified hash algorithm.
        /// </summary>
        /// <param name="buffer">The input data buffer for which to compute the hash.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <param name="signature">The signature data to be verified.</param>
        bool VerifyFinal(byte[] buffer, int offset, int length, byte[] signature);

        /// <summary>
        /// Verifies that a digital signature of the specified input bytes using the specified hash algorithm.
        /// </summary>
        /// <param name="rgb">The input data for which to compute the hash.</param>
        void VerifyUpdate(byte[] rgb);

        /// <summary>
        /// Verifies that a digital signature of the specified input bytes using the specified hash algorithm.
        /// </summary>
        /// <param name="buffer">The data buffer.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        void VerifyUpdate(byte[] buffer, int offset, int length);
    }
}