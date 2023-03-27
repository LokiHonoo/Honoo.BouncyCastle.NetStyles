namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Asymmetric encryption algorithm interface.
    /// </summary>
    public interface IAsymmetricEncryptionAlgorithm : IAsymmetricAlgorithm
    {
        /// <summary>
        /// Decrypts data with the asymmetric algorithm.
        /// </summary>
        /// <param name="rgb">The encrypted data.</param>
        /// <returns></returns>
        byte[] Decrypt(byte[] rgb);

        /// <summary>
        /// Decrypts data with the asymmetric algorithm.
        /// </summary>
        /// <param name="inputBuffer">The encrypted data buffer.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        byte[] Decrypt(byte[] inputBuffer, int offset, int length);

        /// <summary>
        /// Encrypts data with the asymmetric algorithm.
        /// </summary>
        /// <param name="rgb">The data to be encrypted.</param>
        /// <returns></returns>
        byte[] Encrypt(byte[] rgb);

        /// <summary>
        /// Encrypts data with the asymmetric algorithm.
        /// </summary>
        /// <param name="inputBuffer">The data buffer to be encrypted.</param>
        /// <param name="offset">The starting offset to read.</param>
        /// <param name="length">The length to read.</param>
        /// <returns></returns>
        byte[] Encrypt(byte[] inputBuffer, int offset, int length);

        /// <summary>
        /// Gets legal input bytes length.
        /// </summary>
        /// <param name="forEncryption">Specifies whether it is used for encryption or decryption.</param>
        int GetLegalInputLength(bool forEncryption);
    }
}