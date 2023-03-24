using Honoo.BouncyCastle.NetStyles.X509.Utilities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using System;
using System.IO;

namespace Honoo.BouncyCastle.NetStyles.X509
{
    /// <summary>
    /// Represents a generator over the certification revocation list.
    /// </summary>
    public class X509CertificateRevocationListGenerator
    {
        #region Properties

        private readonly string _asn1Algorithm;
        private readonly X509ExtensionCollection _extensions = new X509ExtensionCollection();
        private readonly X509NameCollection _issuerDN = new X509NameCollection();
        private readonly AsymmetricKeyParameter _privateKey;
        private readonly X509CertificateRevocationCollection _revocations = new X509CertificateRevocationCollection();

        /// <summary>
        /// Gets X509 extension collection.
        /// </summary>
        public X509ExtensionCollection Extensions => _extensions;

        /// <summary>
        /// Gets issuer X509 distinct name collection.
        /// </summary>
        public X509NameCollection IssuerDN => _issuerDN;

        /// <summary>
        /// Gets X509 certificate revocation collection.
        /// </summary>
        public X509CertificateRevocationCollection Revocations => _revocations;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the X509CertificateRevocationListGenerator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="issuerPrivateKey">Issuer(CA) private key.</param>
        public X509CertificateRevocationListGenerator(SignatureAlgorithmName algorithmName, AsymmetricKeyParameter issuerPrivateKey)
        {
            _asn1Algorithm = algorithmName.Asn1Identifier;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportParameters(issuerPrivateKey);
            _privateKey = algorithm.ExportParameters(true);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateRevocationListGenerator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="issuerPrivateKeyPem">Issuer(CA) private key pem string.</param>
        public X509CertificateRevocationListGenerator(SignatureAlgorithmName algorithmName, string issuerPrivateKeyPem)
        {
            _asn1Algorithm = algorithmName.Asn1Identifier;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportPem(issuerPrivateKeyPem);
            _privateKey = algorithm.ExportParameters(true);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateRevocationListGenerator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="issuerPrivateKeyPem">Issuer(CA) private key pem string.</param>
        /// <param name="password">Using decrypt private key.</param>
        public X509CertificateRevocationListGenerator(SignatureAlgorithmName algorithmName, string issuerPrivateKeyPem, string password)
        {
            _asn1Algorithm = algorithmName.Asn1Identifier;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportPem(issuerPrivateKeyPem, password);
            _privateKey = algorithm.ExportParameters(true);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateRevocationListGenerator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="issuerPrivateKeyInfo">Issuer(CA) private key info.</param>
        public X509CertificateRevocationListGenerator(SignatureAlgorithmName algorithmName, byte[] issuerPrivateKeyInfo)
        {
            _asn1Algorithm = algorithmName.Asn1Identifier;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportKeyInfo(issuerPrivateKeyInfo);
            _privateKey = algorithm.ExportParameters(true);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateRevocationListGenerator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="issuerPrivateKeyInfo">Issuer(CA) private key info.</param>
        /// <param name="password">Using decrypt private key.</param>
        public X509CertificateRevocationListGenerator(SignatureAlgorithmName algorithmName, byte[] issuerPrivateKeyInfo, string password)
        {
            _asn1Algorithm = algorithmName.Asn1Identifier;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportKeyInfo(issuerPrivateKeyInfo, password);
            _privateKey = algorithm.ExportParameters(true);
        }

        #endregion Construction

        /// <summary>
        /// Generate certification revocation list.
        /// </summary>
        /// <param name="thisUpdate">The time of this update.</param>
        /// <param name="nextUpdate">The time of anticipated next update.</param>
        /// <param name="others">The other certification revocation list.</param>
        public X509Crl Generate(DateTime thisUpdate, DateTime nextUpdate, X509Crl[] others)
        {
            return GenerateCore(thisUpdate, nextUpdate, others);
        }

        /// <summary>
        /// Generate certification revocation list, And save to a byte array of DER encoding.
        /// </summary>
        /// <param name="thisUpdate">The time of this update.</param>
        /// <param name="nextUpdate">The time of anticipated next update.</param>
        /// <param name="others">The other certification revocation list.</param>
        public byte[] GenerateDer(DateTime thisUpdate, DateTime nextUpdate, X509Crl[] others)
        {
            X509Crl crl = GenerateCore(thisUpdate, nextUpdate, others);
            return crl.GetEncoded();
        }

        /// <summary>
        /// Generate certification revocation list, And save to a pem string.
        /// </summary>
        /// <param name="thisUpdate">The time of this update.</param>
        /// <param name="nextUpdate">The time of anticipated next update.</param>
        /// <param name="others">The other certification revocation list.</param>
        public string GeneratePem(DateTime thisUpdate, DateTime nextUpdate, X509Crl[] others)
        {
            X509Crl crl = GenerateCore(thisUpdate, nextUpdate, others);
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(crl);
                return writer.ToString();
            }
        }

        private X509Crl GenerateCore(DateTime thisUpdate, DateTime nextUpdate, X509Crl[] others)
        {
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(_asn1Algorithm, _privateKey, Common.SecureRandom.Value);
            X509V2CrlGenerator generator = new X509V2CrlGenerator();
            generator.SetIssuerDN(X509Utilities.GetX509Name(_issuerDN));
            if (_extensions.Count > 0)
            {
                foreach (X509ExtensionEntity entity in _extensions)
                {
                    generator.AddExtension(entity.Oid, entity.IsCritical, entity.Value);
                }
            }
            if (others != null)
            {
                foreach (X509Crl other in others)
                {
                    generator.AddCrl(other);
                }
            }
            if (_revocations.Count > 0)
            {
                foreach (var revocation in _revocations)
                {
                    BigInteger serialNumber = new BigInteger(revocation.SerialNumber, 16);
                    generator.AddCrlEntry(serialNumber, revocation.RevocationDate, X509Utilities.GetX509Extensions(revocation.Extensions));
                }
            }
            generator.SetThisUpdate(thisUpdate);
            generator.SetNextUpdate(nextUpdate);
            return generator.Generate(signatureFactory);
        }
    }
}