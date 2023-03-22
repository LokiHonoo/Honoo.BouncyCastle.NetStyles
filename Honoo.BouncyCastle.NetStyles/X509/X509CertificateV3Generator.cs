using Honoo.BouncyCastle.NetStyles.X509.Utilities;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;

namespace Honoo.BouncyCastle.NetStyles.X509
{
    /// <summary>
    /// Represents a generator over the X.509 v.3 certificate.
    /// </summary>
    public class X509CertificateV3Generator
    {
        #region Properties

        private readonly string _asn1Algorithm;
        private readonly IDictionary<X509ExtensionLabel, X509Extension> _extensions = new SortedDictionary<X509ExtensionLabel, X509Extension>();
        private readonly IDictionary<X509NameLabel, string> _issuerDN = new SortedDictionary<X509NameLabel, string>();
        private readonly AsymmetricKeyParameter _privateKey;
        private X509CertificateRequestTiled _certificateRequestTiled;

        /// <summary>
        /// Gets certificate request tiled to modify information.
        /// </summary>
        public X509CertificateRequestTiled CertificateRequest => _certificateRequestTiled;

        /// <summary>
        /// Gets X509 extension collection.
        /// </summary>
        public IDictionary<X509ExtensionLabel, X509Extension> Extensions => _extensions;

        /// <summary>
        /// Gets issuer X509 distinct name collection.
        /// </summary>
        public IDictionary<X509NameLabel, string> IssuerDN => _issuerDN;

        #endregion Properties

        #region Construction

        /// <summary>
        /// Initializes a new instance of the X509CertificateV3Generator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="issuerPrivateKey">Issuer(CA) private key .</param>
        public X509CertificateV3Generator(SignatureAlgorithmName algorithmName, AsymmetricKeyParameter issuerPrivateKey)
        {
            _asn1Algorithm = algorithmName.Asn1Algorithm;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportParameters(issuerPrivateKey);
            _privateKey = algorithm.ExportParameters(true);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateV3Generator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="issuerPrivateKeyPem">Issuer(CA) private key pem string.</param>
        public X509CertificateV3Generator(SignatureAlgorithmName algorithmName, string issuerPrivateKeyPem)
        {
            _asn1Algorithm = algorithmName.Asn1Algorithm;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportPem(issuerPrivateKeyPem);
            _privateKey = algorithm.ExportParameters(true);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateV3Generator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="issuerPrivateKeyPem">Issuer(CA) private key pem string.</param>
        /// <param name="password">Using decrypt private key.</param>
        public X509CertificateV3Generator(SignatureAlgorithmName algorithmName, string issuerPrivateKeyPem, string password)
        {
            _asn1Algorithm = algorithmName.Asn1Algorithm;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportPem(issuerPrivateKeyPem, password);
            _privateKey = algorithm.ExportParameters(true);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateV3Generator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="issuerPrivateKeyInfo">Issuer(CA) private key info.</param>
        public X509CertificateV3Generator(SignatureAlgorithmName algorithmName, byte[] issuerPrivateKeyInfo)
        {
            _asn1Algorithm = algorithmName.Asn1Algorithm;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportKeyInfo(issuerPrivateKeyInfo);
            _privateKey = algorithm.ExportParameters(true);
        }

        /// <summary>
        /// Initializes a new instance of the X509CertificateV3Generator class.
        /// </summary>
        /// <param name="algorithmName">Specifies the signature algorithm used.</param>
        /// <param name="issuerPrivateKeyInfo">Issuer(CA) private key info.</param>
        /// <param name="password">Using decrypt private key.</param>
        public X509CertificateV3Generator(SignatureAlgorithmName algorithmName, byte[] issuerPrivateKeyInfo, string password)
        {
            _asn1Algorithm = algorithmName.Asn1Algorithm;
            AsymmetricAlgorithm algorithm = algorithmName.GetAlgorithm();
            algorithm.ImportKeyInfo(issuerPrivateKeyInfo, password);
            _privateKey = algorithm.ExportParameters(true);
        }

        #endregion Construction

        /// <summary>
        /// Generate X.509 v.3 certificates from certification request.
        /// </summary>
        /// <param name="start">The start time of the validity period.</param>
        /// <param name="end">The end time of the validity period.</param>
        public X509Certificate Generate(DateTime start, DateTime end)
        {
            return GenerateCore(start, end);
        }

        /// <summary>
        /// Generate X.509 v.3 certificates from certification request, And save to DER encoding.
        /// </summary>
        /// <param name="start">The start time of the validity period.</param>
        /// <param name="end">The end time of the validity period.</param>
        public byte[] GenerateDer(DateTime start, DateTime end)
        {
            X509Certificate cer = GenerateCore(start, end);
            return cer.GetEncoded();
        }

        /// <summary>
        /// Generate X.509 v.3 certificates from certification request, And save to pem string.
        /// </summary>
        /// <param name="start">The start time of the validity period.</param>
        /// <param name="end">The end time of the validity period.</param>
        public string GeneratePem(DateTime start, DateTime end)
        {
            X509Certificate cer = GenerateCore(start, end);
            using (StringWriter writer = new StringWriter())
            {
                PemWriter pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(cer);
                return writer.ToString();
            }
        }

        /// <summary>
        /// Sets certificate request, for create the certificate later.
        /// </summary>
        public void SetCertificateRequest(Pkcs10CertificationRequest certificationRequest)
        {
            _certificateRequestTiled = new X509CertificateRequestTiled(certificationRequest);
        }

        /// <summary>
        /// Sets certificate request, for create the certificate later.
        /// </summary>
        public void SetCertificateRequest(string certificationRequestPem)
        {
            using (StringReader reader = new StringReader(certificationRequestPem))
            {
                object obj = new PemReader(reader).ReadObject();
                Pkcs10CertificationRequest csr = (Pkcs10CertificationRequest)obj;
                _certificateRequestTiled = new X509CertificateRequestTiled(csr);
            }
        }

        /// <summary>
        /// Sets certificate request, for create the certificate later.
        /// </summary>
        public void SetCertificateRequest(byte[] certificationRequestDerEncoded)
        {
            Pkcs10CertificationRequest csr = new Pkcs10CertificationRequest(certificationRequestDerEncoded);
            _certificateRequestTiled = new X509CertificateRequestTiled(csr);
        }
        /// <summary>
        /// Remove certificate request.
        /// </summary>
        public void RemoveCertificateRequest()
        {
            _certificateRequestTiled = null;
        }
        private X509Certificate GenerateCore(DateTime start, DateTime end)
        {
            if (end < start)
            {
                throw new Exception("The end time is earlier than the start time.");
            }
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(_asn1Algorithm, _privateKey, Common.SecureRandom.Value);
            BigInteger sn = new BigInteger(128, Common.SecureRandom.Value);
            X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
            generator.SetSerialNumber(sn);
            generator.SetIssuerDN(X509Utilities.GetX509Name(_issuerDN));
            generator.SetPublicKey(_certificateRequestTiled.PublicKey);
            generator.SetSubjectDN(X509Utilities.GetX509Name(_certificateRequestTiled.SubjectDN));
            if (_extensions.Count > 0)
            {
                foreach (KeyValuePair<X509ExtensionLabel, X509Extension> entity in _extensions)
                {
                    generator.AddExtension(X509Utilities.GetX509ExtensionOid(entity.Key), entity.Value.IsCritical, entity.Value.GetParsedValue());
                }
            }
            if (_certificateRequestTiled.Extensions.Count > 0)
            {
                foreach (KeyValuePair<X509ExtensionLabel, X509Extension> entity in _certificateRequestTiled.Extensions)
                {
                    generator.AddExtension(X509Utilities.GetX509ExtensionOid(entity.Key), entity.Value.IsCritical, entity.Value.GetParsedValue());
                }
            }
            generator.SetNotBefore(start);
            generator.SetNotAfter(end);
            return generator.Generate(signatureFactory);
        }
    }
}