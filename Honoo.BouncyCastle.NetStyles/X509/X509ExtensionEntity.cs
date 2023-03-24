using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles.X509
{
    /// <summary>
    /// X509 extension entity.
    /// </summary>
    public sealed class X509ExtensionEntity
    {
        #region Properties

        private readonly bool _isCritical;
        private readonly X509ExtensionLabel _label;
        private readonly DerObjectIdentifier _oid;
        private readonly Asn1Encodable _value;

        /// <summary>
        /// X509 extension critical.
        /// </summary>
        public bool IsCritical => _isCritical;

        /// <summary>
        /// X509 extension label.
        /// </summary>
        public X509ExtensionLabel Label => _label;

        /// <summary>
        /// X509 extension oid.
        /// </summary>
        public DerObjectIdentifier Oid => _oid;

        /// <summary>
        /// X509 extension value.
        /// </summary>
        public Asn1Encodable Value => _value;

        #endregion Properties

        /// <summary>
        /// Initializes a new instance of the X509ExtensionEntity class.
        /// </summary>
        /// <param name="label">X509 extension label.</param>
        /// <param name="isCritical">X509 extension critical.</param>
        /// <param name="value">X509 extension value.</param>
        public X509ExtensionEntity(X509ExtensionLabel label, bool isCritical, Asn1Encodable value)
        {
            _label = label;
            _isCritical = isCritical;
            _value = value;
            _oid = GetOid(label);
        }

        /// <summary>
        /// Initializes a new instance of the X509ExtensionEntity class.
        /// </summary>
        /// <param name="oid">X509 extension oid.</param>
        /// <param name="isCritical">X509 extension critical.</param>
        /// <param name="value">X509 extension value.</param>
        internal X509ExtensionEntity(DerObjectIdentifier oid, bool isCritical, Asn1Encodable value)
        {
            _label = GetLabel(oid);
            _isCritical = isCritical;
            _value = value;
            _oid = oid;
        }

        private static X509ExtensionLabel GetLabel(DerObjectIdentifier oid)
        {
            switch (oid.Id)
            {
                case "2.5.29.9": return X509ExtensionLabel.SubjectDirectoryAttributes;
                case "2.5.29.14": return X509ExtensionLabel.SubjectKeyIdentifier;
                case "2.5.29.15": return X509ExtensionLabel.KeyUsage;
                case "2.5.29.16": return X509ExtensionLabel.PrivateKeyUsagePeriod;
                case "2.5.29.17": return X509ExtensionLabel.SubjectAlternativeName;
                case "2.5.29.18": return X509ExtensionLabel.IssuerAlternativeName;
                case "2.5.29.19": return X509ExtensionLabel.BasicConstraints;
                case "2.5.29.20": return X509ExtensionLabel.CrlNumber;
                case "2.5.29.21": return X509ExtensionLabel.ReasonCode;
                case "2.5.29.23": return X509ExtensionLabel.InstructionCode;
                case "2.5.29.24": return X509ExtensionLabel.InvalidityDate;
                case "2.5.29.27": return X509ExtensionLabel.DeltaCrlIndicator;
                case "2.5.29.28": return X509ExtensionLabel.IssuingDistributionPoint;
                case "2.5.29.29": return X509ExtensionLabel.CertificateIssuer;
                case "2.5.29.30": return X509ExtensionLabel.NameConstraints;
                case "2.5.29.31": return X509ExtensionLabel.CrlDistributionPoints;
                case "2.5.29.32": return X509ExtensionLabel.CertificatePolicies;
                case "2.5.29.33": return X509ExtensionLabel.PolicyMappings;
                case "2.5.29.35": return X509ExtensionLabel.AuthorityKeyIdentifier;
                case "2.5.29.36": return X509ExtensionLabel.PolicyConstraints;
                case "2.5.29.37": return X509ExtensionLabel.ExtendedKeyUsage;
                case "2.5.29.46": return X509ExtensionLabel.FreshestCrl;
                case "2.5.29.54": return X509ExtensionLabel.InhibitAnyPolicy;
                case "1.3.6.1.5.5.7.1.1": return X509ExtensionLabel.AuthorityInfoAccess;
                case "1.3.6.1.5.5.7.1.11": return X509ExtensionLabel.SubjectInfoAccess;
                case "1.3.6.1.5.5.7.1.12": return X509ExtensionLabel.LogoType;
                case "1.3.6.1.5.5.7.1.2": return X509ExtensionLabel.BiometricInfo;
                case "1.3.6.1.5.5.7.1.3": return X509ExtensionLabel.QCStatements;
                case "1.3.6.1.5.5.7.1.4": return X509ExtensionLabel.AuditIdentity;
                case "2.5.29.56": return X509ExtensionLabel.NoRevAvail;
                case "2.5.29.55": return X509ExtensionLabel.TargetInformation;
                case "2.5.29.60": return X509ExtensionLabel.ExpiredCertsOnCrl;
                default: throw new CryptographicException("Unsupported X509Extension.");
            }
        }

        private static DerObjectIdentifier GetOid(X509ExtensionLabel label)
        {
            switch (label)
            {
                case X509ExtensionLabel.AuditIdentity: return X509Extensions.AuditIdentity;
                case X509ExtensionLabel.AuthorityInfoAccess: return X509Extensions.AuthorityInfoAccess;
                case X509ExtensionLabel.AuthorityKeyIdentifier: return X509Extensions.AuthorityKeyIdentifier;
                case X509ExtensionLabel.BasicConstraints: return X509Extensions.BasicConstraints;
                case X509ExtensionLabel.BiometricInfo: return X509Extensions.BiometricInfo;
                case X509ExtensionLabel.CertificateIssuer: return X509Extensions.CertificateIssuer;
                case X509ExtensionLabel.CertificatePolicies: return X509Extensions.CertificatePolicies;
                case X509ExtensionLabel.CrlDistributionPoints: return X509Extensions.CrlDistributionPoints;
                case X509ExtensionLabel.CrlNumber: return X509Extensions.CrlNumber;
                case X509ExtensionLabel.DeltaCrlIndicator: return X509Extensions.DeltaCrlIndicator;
                case X509ExtensionLabel.ExpiredCertsOnCrl: return X509Extensions.ExpiredCertsOnCrl;
                case X509ExtensionLabel.ExtendedKeyUsage: return X509Extensions.ExtendedKeyUsage;
                case X509ExtensionLabel.FreshestCrl: return X509Extensions.FreshestCrl;
                case X509ExtensionLabel.InhibitAnyPolicy: return X509Extensions.InhibitAnyPolicy;
                case X509ExtensionLabel.InstructionCode: return X509Extensions.InstructionCode;
                case X509ExtensionLabel.InvalidityDate: return X509Extensions.InvalidityDate;
                case X509ExtensionLabel.IssuerAlternativeName: return X509Extensions.IssuerAlternativeName;
                case X509ExtensionLabel.IssuingDistributionPoint: return X509Extensions.IssuingDistributionPoint;
                case X509ExtensionLabel.KeyUsage: return X509Extensions.KeyUsage;
                case X509ExtensionLabel.LogoType: return X509Extensions.LogoType;
                case X509ExtensionLabel.NameConstraints: return X509Extensions.NameConstraints;
                case X509ExtensionLabel.NoRevAvail: return X509Extensions.NoRevAvail;
                case X509ExtensionLabel.PolicyConstraints: return X509Extensions.PolicyConstraints;
                case X509ExtensionLabel.PolicyMappings: return X509Extensions.PolicyMappings;
                case X509ExtensionLabel.PrivateKeyUsagePeriod: return X509Extensions.PrivateKeyUsagePeriod;
                case X509ExtensionLabel.QCStatements: return X509Extensions.QCStatements;
                case X509ExtensionLabel.ReasonCode: return X509Extensions.ReasonCode;
                case X509ExtensionLabel.SubjectAlternativeName: return X509Extensions.SubjectAlternativeName;
                case X509ExtensionLabel.SubjectDirectoryAttributes: return X509Extensions.SubjectDirectoryAttributes;
                case X509ExtensionLabel.SubjectInfoAccess: return X509Extensions.SubjectInfoAccess;
                case X509ExtensionLabel.SubjectKeyIdentifier: return X509Extensions.SubjectKeyIdentifier;
                case X509ExtensionLabel.TargetInformation: return X509Extensions.TargetInformation;
                default: throw new CryptographicException("Unsupported X509Extension.");
            }
        }
    }
}