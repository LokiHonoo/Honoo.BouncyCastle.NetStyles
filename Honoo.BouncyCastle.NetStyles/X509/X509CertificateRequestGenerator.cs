using Honoo.BouncyCastle.NetStyles.X509.Utilities;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using System.Collections.Generic;
using System.IO;

namespace Honoo.BouncyCastle.NetStyles.X509
{
    /// <summary>
    /// Represents a generator over the certification request.
    /// </summary>
    public sealed class X509CertificateRequestGenerator
    {
        #region Properties

        private readonly string _asn1Algorithm;
        private readonly IDictionary<X509ExtensionLabel, X509Extension> _extensions = new SortedDictionary<X509ExtensionLabel, X509Extension>();
        private readonly AsymmetricKeyParameter _privateKey;
        private readonly AsymmetricKeyParameter _publicKey;
        private readonly IDictionary<X509NameLabel, string> _subjectDN = new SortedDictionary<X509NameLabel, string>();

        /// <summary>
        /// Gets X509 extension collection.
        /// </summary>
        public IDictionary<X509ExtensionLabel, X509Extension> Extensions => _extensions;

        /// <summary>
        /// Gets X509 subject distinct name collection.
        /// </summary>
        public IDictionary<X509NameLabel, string> SubjectDN => _subjectDN;

        internal AsymmetricKeyParameter PublicKey => _publicKey;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the X509CertificateRequestGenerator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="subjectPrivateKey">Subject private key.</param>
        public X509CertificateRequestGenerator(SignatureAlgorithmName algorithmName, AsymmetricCipherKeyPair subjectPrivateKeyPair)
        {
            _asn1Algorithm = algorithmName.Asn1Algorithm;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportParameters(subjectPrivateKeyPair);
            _privateKey = algorithm.ExportParameters(true);
            _publicKey = algorithm.ExportParameters(false);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateRequestGenerator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="subjectPrivateKey">Subject private key.</param>
        public X509CertificateRequestGenerator(SignatureAlgorithmName algorithmName, AsymmetricKeyParameter subjectPrivateKey)
        {
            _asn1Algorithm = algorithmName.Asn1Algorithm;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportParameters(subjectPrivateKey);
            _privateKey = algorithm.ExportParameters(true);
            _publicKey = algorithm.ExportParameters(false);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateRequestGenerator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="subjectPrivateKeyPem">Subject private key pem string.</param>
        public X509CertificateRequestGenerator(SignatureAlgorithmName algorithmName, string subjectPrivateKeyPem)
        {
            _asn1Algorithm = algorithmName.Asn1Algorithm;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportPem(subjectPrivateKeyPem);
            _privateKey = algorithm.ExportParameters(true);
            _publicKey = algorithm.ExportParameters(false);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateRequestGenerator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="subjectPrivateKeyPem">Subject private key pem string.</param>
        /// <param name="password">Using decrypt private key.</param>
        public X509CertificateRequestGenerator(SignatureAlgorithmName algorithmName, string subjectPrivateKeyPem, string password)
        {
            _asn1Algorithm = algorithmName.Asn1Algorithm;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportPem(subjectPrivateKeyPem, password);
            _privateKey = algorithm.ExportParameters(true);
            _publicKey = algorithm.ExportParameters(false);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateRequestGenerator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="subjectPrivateKeyInfo">ubject private key PKCS#8 info.</param>
        public X509CertificateRequestGenerator(SignatureAlgorithmName algorithmName, byte[] subjectPrivateKeyInfo)
        {
            _asn1Algorithm = algorithmName.Asn1Algorithm;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportKeyInfo(subjectPrivateKeyInfo);
            _privateKey = algorithm.ExportParameters(true);
            _publicKey = algorithm.ExportParameters(false);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateRequestGenerator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="subjectPrivateKeyInfo">ubject private key PKCS#8 info.</param>
        /// <param name="password">Using decrypt private key.</param>
        public X509CertificateRequestGenerator(SignatureAlgorithmName algorithmName, byte[] subjectPrivateKeyInfo, string password)
        {
            _asn1Algorithm = algorithmName.Asn1Algorithm;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportKeyInfo(subjectPrivateKeyInfo, password);
            _privateKey = algorithm.ExportParameters(true);
            _publicKey = algorithm.ExportParameters(false);
        }

        #endregion Construction

        /// <summary>
        /// Generates a <see cref="Pkcs10CertificationRequest"/> containing the certification request associated.
        /// </summary>
        /// <returns></returns>
        public Pkcs10CertificationRequest Generate()
        {
            return GenerateCore();
        }

        /// <summary>
        /// Generates a byte array containing the certification request associated.
        /// </summary>
        /// <returns></returns>
        public byte[] GenerateDer()
        {
            Pkcs10CertificationRequest csr = GenerateCore();
            return csr.GetDerEncoded();
        }

        /// <summary>
        /// Generates a pem string containing the certification request associated.
        /// </summary>
        /// <returns></returns>
        public string GeneratePem()
        {
            Pkcs10CertificationRequest csr = GenerateCore();
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(csr);
                return writer.ToString();
            }
        }

        private Pkcs10CertificationRequest GenerateCore()
        {
            Asn1SignatureFactory signatureFactory = new Asn1SignatureFactory(_asn1Algorithm, _privateKey, Common.SecureRandom.Value);
            X509Name name = X509Utilities.GetX509Name(_subjectDN);
            DerSet attribute = null;
            if (_extensions.Count > 0)
            {
                X509Extensions extensions = X509Utilities.GetX509Extensions(_extensions);
                DerSet extensionsDerSet = new DerSet(extensions);
                AttributePkcs pkcs = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, extensionsDerSet);
                attribute = new DerSet(pkcs);
            }
            return new Pkcs10CertificationRequest(signatureFactory, name, _publicKey, attribute);
        }
    }
}