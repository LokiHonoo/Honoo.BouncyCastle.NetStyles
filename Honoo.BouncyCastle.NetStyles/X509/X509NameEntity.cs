using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using System.Security.Cryptography;

namespace Honoo.BouncyCastle.NetStyles.X509
{
    /// <summary>
    /// X509 distinct name entity.
    /// </summary>
    public sealed class X509NameEntity
    {
        #region Properties

        private readonly X509NameLabel _label;
        private readonly DerObjectIdentifier _oid;
        private readonly string _value;

        /// <summary>
        /// X509 distinct name label.
        /// </summary>
        public X509NameLabel Label => _label;

        /// <summary>
        /// X509 distinct name oid.
        /// </summary>
        public DerObjectIdentifier Oid => _oid;

        /// <summary>
        /// X509 distinct name value.
        /// </summary>
        public string Value => _value;

        #endregion Properties

        /// <summary>
        /// Initializes a new instance of the X509NameEntity class.
        /// </summary>
        /// <param name="label">X509 distinct name label.</param>
        /// <param name="value">X509 distinct name value.</param>
        public X509NameEntity(X509NameLabel label, string value)
        {
            _label = label;
            _value = value;
            _oid = GetOid(label);
        }

        /// <summary>
        /// Initializes a new instance of the X509NameEntity class.
        /// </summary>
        /// <param name="oid">X509 distinct name oid.</param>
        /// <param name="value">X509 distinct name value.</param>
        internal X509NameEntity(DerObjectIdentifier oid, string value)
        {
            _label = GetLabel(oid);
            _value = value;
            _oid = oid;
        }

        private static X509NameLabel GetLabel(DerObjectIdentifier oid)
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

        private static DerObjectIdentifier GetOid(X509NameLabel label)
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