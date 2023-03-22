﻿using System;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Asymmetric algorithm name.
    /// </summary>
    public sealed class AsymmetricAlgorithmName : IEquatable<AsymmetricAlgorithmName>
    {
        #region Delegate

        internal delegate AsymmetricAlgorithm GetAlgorithmCallback();

        #endregion Delegate

        #region AlgorithmNames

        /// <summary>
        /// Asymmetric signature algorithm. Legal key size 512-1024 bits (64 bits increments).
        /// </summary>
        public static AsymmetricAlgorithmName DSA { get; } = Honoo.BouncyCastle.NetStyles.DSA.GetAlgorithmName();

        /// <summary>
        /// Asymmetric key exchange algorithm.
        /// </summary>
        public static AsymmetricAlgorithmName ECDH { get; } = Honoo.BouncyCastle.NetStyles.ECDH.GetAlgorithmName();

        /// <summary>
        /// Asymmetric signature algorithm.
        /// </summary>
        public static AsymmetricAlgorithmName ECDSA { get; } = Honoo.BouncyCastle.NetStyles.ECDSA.GetAlgorithmName();

        /// <summary>
        /// Asymmetric signature algorithm.
        /// </summary>
        public static AsymmetricAlgorithmName ECGOST3410 { get; } = Honoo.BouncyCastle.NetStyles.ECGOST3410.GetAlgorithmName();

        /// <summary>
        /// Asymmetric signature algorithm.
        /// </summary>
        public static AsymmetricAlgorithmName Ed25519 { get; } = Honoo.BouncyCastle.NetStyles.Ed25519.GetAlgorithmName();

        /// <summary>
        /// Asymmetric signature algorithm.
        /// </summary>
        public static AsymmetricAlgorithmName Ed448 { get; } = Honoo.BouncyCastle.NetStyles.Ed448.GetAlgorithmName();

        /// <summary>
        /// Asymmetric signature and encryption algorithm. Legal key size is more than or equal to 8 bits (8 bits increments).
        /// </summary>
        public static AsymmetricAlgorithmName ElGamal { get; } = Honoo.BouncyCastle.NetStyles.ElGamal.GetAlgorithmName();

        /// <summary>
        /// Asymmetric signature algorithm.
        /// </summary>
        public static AsymmetricAlgorithmName GOST3410 { get; } = Honoo.BouncyCastle.NetStyles.GOST3410.GetAlgorithmName();

        /// <summary>
        /// Asymmetric signature and encryption algorithm. Legal key size is more than or equal to 24 bits (8 bits increments).
        /// </summary>
        public static AsymmetricAlgorithmName RSA { get; } = Honoo.BouncyCastle.NetStyles.RSA.GetAlgorithmName();

        /// <summary>
        /// Asymmetric signature algorithm.
        /// </summary>
        public static AsymmetricAlgorithmName SM2 { get; } = Honoo.BouncyCastle.NetStyles.SM2.GetAlgorithmName();

        #endregion AlgorithmNames

        #region Properties

        private readonly GetAlgorithmCallback _getAlgorithm;
        private readonly AsymmetricAlgorithmKind _kind;
        private readonly string _name;

        /// <summary>
        /// Gets algorithm kind of the algorithm.
        /// </summary>
        public AsymmetricAlgorithmKind Kind => _kind;

        /// <summary>
        /// Gets this algorithm's name.
        /// </summary>
        public string Name => _name;

        internal GetAlgorithmCallback GetAlgorithm => _getAlgorithm;

        #endregion Properties

        #region Construction

        internal AsymmetricAlgorithmName(string name, AsymmetricAlgorithmKind kind, GetAlgorithmCallback getAlgorithm)
        {
            _name = name;
            _kind = kind;
            _getAlgorithm = getAlgorithm;
        }

        #endregion Construction

        /// <summary>
        /// Gets all algorithm names of the storage.
        /// </summary>
        /// <returns></returns>
        public static AsymmetricAlgorithmName[] GetNames()
        {
            return new AsymmetricAlgorithmName[] { DSA, ECDH, ECDSA, ECGOST3410, Ed25519, Ed448, ElGamal, GOST3410, RSA, SM2, };
        }

        /// <summary>
        /// Gets algorithm names of the storage of the specified kind.
        /// </summary>
        /// <param name="kind">Algorithm kind.</param>
        /// <returns></returns>
        public static AsymmetricAlgorithmName[] GetNames(AsymmetricAlgorithmKind kind)
        {
            switch (kind)
            {
                case AsymmetricAlgorithmKind.Signature: return new AsymmetricAlgorithmName[] { DSA, ECDSA, ECGOST3410, Ed25519, Ed448, GOST3410, RSA, SM2, };
                case AsymmetricAlgorithmKind.Encryption: return new AsymmetricAlgorithmName[] { ElGamal, RSA, };
                case AsymmetricAlgorithmKind.SignatureAndEncryption: return new AsymmetricAlgorithmName[] { RSA, };
                case AsymmetricAlgorithmKind.KeyExchange: return new AsymmetricAlgorithmName[] { ECDH, };
                default: return GetNames();
            }
        }

        /// <summary>
        /// Try get algorithm name from mechanism.
        /// </summary>
        /// <param name="mechanism">Algorithm mechanism.</param>
        /// <param name="algorithmName">Algorithm name.</param>
        /// <returns></returns>
        public static bool TryGetAlgorithmName(string mechanism, out AsymmetricAlgorithmName algorithmName)
        {
            if (string.IsNullOrWhiteSpace(mechanism))
            {
                algorithmName = null;
                return false;
            }
            mechanism = mechanism.Trim().Replace('_', '-').Replace('/', '-').ToUpperInvariant();
            switch (mechanism)
            {
                case "1.2.840.10040.4.1": case "DSA": algorithmName = DSA; return true;
                case "0.4.0.127.0.7.2.2.3.2": case "ECDH": algorithmName = ECDH; return true;
                case "0.4.0.127.0.7.2.2.2.2": case "ECDSA": algorithmName = ECDSA; return true;
                case "1.2.643.2.2.19": case "ECGOST3410": case "ECGOST3410-2001": algorithmName = ECGOST3410; return true;
                case "1.3.101.112": case "ED25519": algorithmName = Ed25519; return true;
                case "1.3.101.113": case "ED448": algorithmName = Ed448; return true;
                case "1.3.14.7.2.1.1": case "ELGAMAL": algorithmName = ElGamal; return true;
                case "1.2.643.2.2.20": case "GOST3410": case "GOST3410-94": algorithmName = GOST3410; return true;
                case "1.2.840.113549.1.1.1": case "RSA": algorithmName = RSA; return true;
                case "1.2.156.10197.1.301.1": case "SM2": algorithmName = SM2; return true;
                default: algorithmName = null; return false;
            }
        }

        /// <summary>
        /// Determines whether the specified object is equal to the current object.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(AsymmetricAlgorithmName other)
        {
            return other._name.Equals(_name);
        }

        /// <summary>
        /// Return algorithm name.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return _name;
        }
    }
}