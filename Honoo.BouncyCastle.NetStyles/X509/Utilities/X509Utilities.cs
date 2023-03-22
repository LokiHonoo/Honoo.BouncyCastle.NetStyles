using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles.X509.Utilities
{
    internal static class X509Utilities
    {
        internal static X509ExtensionLabel GetX509ExtensionLabel(DerObjectIdentifier oid)
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

        internal static DerObjectIdentifier GetX509ExtensionOid(X509ExtensionLabel label)
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

        internal static X509Extensions GetX509Extensions(IDictionary<X509ExtensionLabel, X509Extension> entities)
        {
            List<DerObjectIdentifier> ordering = new List<DerObjectIdentifier>();
            List<X509Extension> attributes = new List<X509Extension>();
            foreach (KeyValuePair<X509ExtensionLabel, X509Extension> entity in entities)
            {
                ordering.Add(GetX509ExtensionOid(entity.Key));
                attributes.Add(entity.Value);
            }
            return new X509Extensions(ordering, attributes);
        }

        internal static X509Name GetX509Name(IDictionary<X509NameLabel, string> entities)
        {
            List<DerObjectIdentifier> ordering = new List<DerObjectIdentifier>();
            List<string> attributes = new List<string>();
            foreach (KeyValuePair<X509NameLabel, string> entity in entities)
            {
                ordering.Add(GetX509NameOid(entity.Key));
                attributes.Add(entity.Value);
            }
            return new X509Name(ordering, attributes);
        }

        internal static X509NameLabel GetX509NameLabel(DerObjectIdentifier oid)
        {
            switch (oid.Id)
            {
                case "2.5.4.6": return X509NameLabel.C;
                case "2.5.4.10": return X509NameLabel.O;
                case "2.5.4.11": return X509NameLabel.OU;
                case "2.5.4.12": return X509NameLabel.T;
                case "2.5.4.3": return X509NameLabel.CN;
                case "2.5.4.9": return X509NameLabel.Street;
                case "2.5.4.5": return X509NameLabel.SerialNumber;
                case "2.5.4.7": return X509NameLabel.L;
                case "2.5.4.8": return X509NameLabel.ST;
                case "2.5.4.4": return X509NameLabel.Surname;
                case "2.5.4.20": return X509NameLabel.TelephoneNumber;
                case "2.5.4.41": return X509NameLabel.Name;
                case "2.5.4.42": return X509NameLabel.GivenName;
                case "2.5.4.43": return X509NameLabel.Initials;
                case "2.5.4.44": return X509NameLabel.Generation;
                case "2.5.4.45": return X509NameLabel.UniqueIdentifier;
                case "2.5.4.15": return X509NameLabel.BusinessCategory;
                case "2.5.4.16": return X509NameLabel.PostalAddress;
                case "2.5.4.17": return X509NameLabel.PostalCode;
                case "2.5.4.46": return X509NameLabel.DnQualifier;
                case "2.5.4.54": return X509NameLabel.DmdName;
                case "2.5.4.65": return X509NameLabel.Pseudonym;
                case "2.5.4.97": return X509NameLabel.OrganizationIdentifier;
                case "1.3.6.1.5.5.7.9.1": return X509NameLabel.DateOfBirth;
                case "1.3.6.1.5.5.7.9.2": return X509NameLabel.PlaceOfBirth;
                case "1.3.6.1.5.5.7.9.3": return X509NameLabel.Gender;
                case "1.3.6.1.5.5.7.9.4": return X509NameLabel.CountryOfCitizenship;
                case "1.3.6.1.5.5.7.9.5": return X509NameLabel.CountryOfResidence;
                case "1.3.36.8.3.14": return X509NameLabel.NameAtBirth;
                case "1.2.840.113549.1.9.1": return X509NameLabel.EmailAddress;
                // case "1.2.840.113549.1.9.1": return X509NameLabel.E;
                case "1.2.840.113549.1.9.2": return X509NameLabel.UnstructuredName;
                case "1.2.840.113549.1.9.8": return X509NameLabel.UnstructuredAddress;
                case "0.9.2342.19200300.100.1.25": return X509NameLabel.DC;
                case "0.9.2342.19200300.100.1.1": return X509NameLabel.UID;
                default: throw new CryptographicException("Unsupported X509Name.");
            }
        }

        internal static DerObjectIdentifier GetX509NameOid(X509NameLabel label)
        {
            switch (label)
            {
                case X509NameLabel.BusinessCategory: return X509Name.BusinessCategory;
                case X509NameLabel.C: return X509Name.C;
                case X509NameLabel.CN: return X509Name.CN;
                case X509NameLabel.CountryOfCitizenship: return X509Name.CountryOfCitizenship;
                case X509NameLabel.CountryOfResidence: return X509Name.CountryOfResidence;
                case X509NameLabel.DateOfBirth: return X509Name.DateOfBirth;
                case X509NameLabel.DC: return X509Name.DC;
                case X509NameLabel.DmdName: return X509Name.DmdName;
                case X509NameLabel.DnQualifier: return X509Name.DnQualifier;
                case X509NameLabel.E: return X509Name.E;
                case X509NameLabel.EmailAddress: return X509Name.EmailAddress;
                case X509NameLabel.Gender: return X509Name.Gender;
                case X509NameLabel.Generation: return X509Name.Generation;
                case X509NameLabel.GivenName: return X509Name.GivenName;
                case X509NameLabel.Initials: return X509Name.Initials;
                case X509NameLabel.L: return X509Name.L;
                case X509NameLabel.Name: return X509Name.Name;
                case X509NameLabel.NameAtBirth: return X509Name.NameAtBirth;
                case X509NameLabel.O: return X509Name.O;
                case X509NameLabel.OrganizationIdentifier: return X509Name.OrganizationIdentifier;
                case X509NameLabel.OU: return X509Name.OU;
                case X509NameLabel.PlaceOfBirth: return X509Name.PlaceOfBirth;
                case X509NameLabel.PostalAddress: return X509Name.PostalAddress;
                case X509NameLabel.PostalCode: return X509Name.PostalCode;
                case X509NameLabel.Pseudonym: return X509Name.Pseudonym;
                case X509NameLabel.SerialNumber: return X509Name.SerialNumber;
                case X509NameLabel.ST: return X509Name.ST;
                case X509NameLabel.Street: return X509Name.Street;
                case X509NameLabel.Surname: return X509Name.Surname;
                case X509NameLabel.T: return X509Name.T;
                case X509NameLabel.TelephoneNumber: return X509Name.TelephoneNumber;
                case X509NameLabel.UID: return X509Name.UID;
                case X509NameLabel.UniqueIdentifier: return X509Name.UniqueIdentifier;
                case X509NameLabel.UnstructuredAddress: return X509Name.UnstructuredAddress;
                case X509NameLabel.UnstructuredName: return X509Name.UnstructuredName;
                default: throw new CryptographicException("Unsupported X509Name.");
            }
        }
    }
}