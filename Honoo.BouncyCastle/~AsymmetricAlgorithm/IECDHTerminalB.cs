namespace Honoo.BouncyCastle
{
    public interface IECDHTerminalB
    {
        /// <summary>
        /// Sand this value to terminal A.
        /// </summary>
        byte[] PublicKeyB { get; }

        /// <summary>
        /// Derive key material.
        /// </summary>
        /// <param name="unsigned">Output unsigned bytes.</param>
        /// <returns></returns>
        byte[] DeriveKeyMaterial(bool unsigned);

        /// <summary>
        /// Renew ecdh parameters of the algorithm.
        /// </summary>
        /// <param name="p">Terminal A's P value.</param>
        /// <param name="g">Terminal A's G value.</param>
        /// <param name="publicKeyA">Terminal A's public key blob.</param>
        void GenerateParameters(byte[] p, byte[] g, byte[] publicKeyA);
    }
}