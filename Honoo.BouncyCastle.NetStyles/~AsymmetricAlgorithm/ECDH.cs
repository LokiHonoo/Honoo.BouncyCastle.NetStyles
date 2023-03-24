﻿using Honoo.BouncyCastle.NetStyles.Utilities;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles
{
    /// <summary>
    /// Using the BouncyCastle implementation of the algorithm.
    /// </summary>
    public sealed class ECDH : AsymmetricAlgorithm, IKeyExchangeA, IKeyExchangeB
    {
        #region Properties

        private const int DEFAULT_CERTAINTY = 20;
        private const int DEFAULT_KEY_SIZE = 521;
        private const string NAME = "ECDH";

        private static readonly KeySizes[] LEGAL_KEY_SIZES = new KeySizes[]
        {
            new KeySizes(192, 224, 32),
            new KeySizes(239, 239, 0),
            new KeySizes(256, 384, 128),
            new KeySizes(521, 521, 0)
        };

        private ECDHBasicAgreement _agreementA = null;
        private ECDHBasicAgreement _agreementB = null;
        private byte[] _g = null;
        private byte[] _p = null;
        private BigInteger _pmsB = null;

        private byte[] _publicKeyA = null;
        private byte[] _publicKeyB = null;

        /// <inheritdoc/>
        public byte[] G
        {
            get
            {
                InspectParameters();
                return (byte[])_g.Clone();
            }
        }

        /// <inheritdoc/>
        public byte[] P
        {
            get
            {
                InspectParameters();
                return (byte[])_p.Clone();
            }
        }

        /// <inheritdoc/>
        public byte[] PublicKeyA
        {
            get
            {
                InspectParameters();
                return (byte[])_publicKeyA.Clone();
            }
        }

        /// <inheritdoc/>
        public byte[] PublicKeyB => _publicKeyB;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the ECDH class.
        /// </summary>
        public ECDH() : base(NAME, AsymmetricAlgorithmKind.KeyExchange)
        {
        }

        #endregion Construction

        #region Interfaces

        /// <inheritdoc/>
        public override IAsymmetricEncryptionAlgorithm GetEncryptionInterface()
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public override IKeyExchangeA GetKeyExchangeAInterface()
        {
            return this;
        }

        /// <inheritdoc/>
        public override IKeyExchangeB GetKeyExchangeBInterface()
        {
            return this;
        }

        /// <inheritdoc/>
        public override IAsymmetricSignatureAlgorithm GetSignatureInterface()
        {
            throw new NotImplementedException();
        }

        #endregion Interfaces

        #region GenerateParameters

        /// <inheritdoc/>
        public override void GenerateParameters()
        {
            GenerateParameters(DEFAULT_KEY_SIZE, DEFAULT_CERTAINTY);
        }

        /// <inheritdoc/>
        public void GenerateParameters(int keySize = 521, int certainty = 20)
        {
            if (!ValidKeySize(keySize, out string exception))
            {
                throw new CryptographicException(exception);
            }
            if (certainty <= 0)
            {
                throw new CryptographicException("Legal certainty is more than 0.");
            }
            DHParametersGenerator parametersGenerator = new DHParametersGenerator();
            parametersGenerator.Init(keySize, certainty, Common.SecureRandom.Value);
            DHParameters parameters = parametersGenerator.GenerateParameters();
            ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator("ECDH");
            DHKeyGenerationParameters generationParameters = new DHKeyGenerationParameters(Common.SecureRandom.Value, parameters);
            keyPairGenerator.Init(generationParameters);
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();
            _agreementA = new ECDHBasicAgreement();
            _agreementA.Init(keyPair.Private);
            _p = parameters.P.ToByteArray();
            _g = parameters.G.ToByteArray();
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            _publicKeyA = publicKeyInfo.GetEncoded();
            //
            _agreementB = null;
            _pmsB = null;
            _publicKeyB = null;
            //
            _initialized = true;
        }

        /// <inheritdoc/>
        public void GenerateParameters(byte[] p, byte[] g, byte[] publicKeyA)
        {
            AsymmetricKeyParameter publicKeyAlice = PublicKeyFactory.CreateKey(publicKeyA);
            DHParameters parameters = new DHParameters(new BigInteger(p), new BigInteger(g));
            ECKeyPairGenerator generator = new ECKeyPairGenerator("ECDH");
            DHKeyGenerationParameters generationParameters = new DHKeyGenerationParameters(Common.SecureRandom.Value, parameters);
            generator.Init(generationParameters);
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();
            _agreementB = new ECDHBasicAgreement();
            _agreementB.Init(keyPair.Private);
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            _publicKeyB = publicKeyInfo.GetEncoded();
            _pmsB = _agreementB.CalculateAgreement(publicKeyAlice);
            //
            _agreementA = null;
            _p = null;
            _g = null;
            _publicKeyA = null;
            //
            _initialized = true;
        }

        #endregion GenerateParameters

        #region Derive

        /// <inheritdoc/>
        public byte[] DeriveKeyMaterial(bool unsigned)
        {
            return unsigned ? _pmsB.ToByteArrayUnsigned() : _pmsB.ToByteArray();
        }

        /// <inheritdoc/>
        public byte[] DeriveKeyMaterial(byte[] publicKeyB, bool unsigned)
        {
            AsymmetricKeyParameter publicKeyBob = PublicKeyFactory.CreateKey(publicKeyB);
            BigInteger pmsA = _agreementA.CalculateAgreement(publicKeyBob);
            return unsigned ? pmsA.ToByteArrayUnsigned() : pmsA.ToByteArray();
        }

        #endregion Derive

        #region Export/Import Parameters

        /// <summary>
        /// Imports a byte array that represents asymmetric algorithm key information. Always throw <see cref="NotImplementedException"/>.
        /// </summary>
        /// <param name="keyInfo">A byte buffer that represents an asymmetric algorithm key.</param>
        public override void ImportKeyInfo(byte[] keyInfo)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Imports a byte array that represents asymmetric algorithm key information. Always throw <see cref="NotImplementedException"/>.
        /// </summary>
        /// <param name="privateKeyInfo">A byte buffer that represents an asymmetric algorithm private key.</param>
        /// <param name="password">Using decrypt private key.</param>
        public override void ImportKeyInfo(byte[] privateKeyInfo, string password)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Imports a <see cref="AsymmetricKeyParameter"/> that represents asymmetric algorithm key information. Always throw <see cref="NotImplementedException"/>.
        /// </summary>
        /// <param name="asymmetricKey">A <see cref="AsymmetricKeyParameter"/> that represents an asymmetric algorithm key.</param>
        public override void ImportParameters(AsymmetricKeyParameter asymmetricKey)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Imports a <see cref="AsymmetricCipherKeyPair"/> that represents asymmetric algorithm key pair information. Always throw <see cref="NotImplementedException"/>.
        /// </summary>
        /// <param name="keyPair">A <see cref="AsymmetricCipherKeyPair"/> that represents an asymmetric algorithm key pair.</param>
        public override void ImportParameters(AsymmetricCipherKeyPair keyPair)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Imports a pem string that represents asymmetric algorithm private key information. Always throw <see cref="NotImplementedException"/>.
        /// </summary>
        /// <param name="keyPem">A pem string that represents an asymmetric algorithm private key.</param>
        public override void ImportPem(string keyPem)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Imports a pem string that represents asymmetric algorithm private key information. Always throw <see cref="NotImplementedException"/>.
        /// </summary>
        /// <param name="privateKeyPem">A pem string that represents an asymmetric algorithm private private key.</param>
        /// <param name="password">Using decrypt private key.</param>
        public override void ImportPem(string privateKeyPem, string password)
        {
            throw new NotImplementedException();
        }

        #endregion Export/Import Parameters

        /// <summary>
        /// Creates an instance of the algorithm.
        /// </summary>
        /// <returns></returns>
        public static ECDH Create()
        {
            return new ECDH();
        }

        /// <summary>
        /// Determines whether the specified size is valid for the current algorithm.
        /// </summary>
        /// <param name="keySize">Legal key size 192, 224, 239, 256, 384, 521.</param>
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
                exception = "Legal key size 192, 224, 239, 256, 384, 521.";
                return false;
            }
        }

        internal static AsymmetricAlgorithmName GetAlgorithmName()
        {
            return new AsymmetricAlgorithmName(NAME, AsymmetricAlgorithmKind.KeyExchange, () => { return new ECDH(); });
        }
    }
}