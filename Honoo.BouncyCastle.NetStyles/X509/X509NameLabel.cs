namespace Honoo.BouncyCastle.NetStyles.X509
{
    /// <summary>
    /// X509 distinct name label.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("CodeQuality", "IDE0079:请删除不必要的忽略", Justification = "<挂起>")]
    public enum X509NameLabel
    {
#pragma warning disable CS1591 // 缺少对公共可见类型或成员的 XML 注释

        BusinessCategory = 1,
        C, CN, CountryOfCitizenship, CountryOfResidence,
        DateOfBirth, DC, DmdName, DnQualifier,
        E, EmailAddress,
        Gender, Generation, GivenName,
        Initials,
        L,
        Name, NameAtBirth,
        O, OrganizationIdentifier, OU,
        PlaceOfBirth, PostalAddress, PostalCode, Pseudonym,
        SerialNumber, ST, Street, Surname,
        T, TelephoneNumber,
        UID, UniqueIdentifier, UnstructuredAddress, UnstructuredName,

#pragma warning restore CS1591 // 缺少对公共可见类型或成员的 XML 注释
    }
}