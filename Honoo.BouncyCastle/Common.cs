using Org.BouncyCastle.Security;

namespace Honoo.BouncyCastle
{
    internal static class Common
    {
        internal static SecureRandom SecureRandom { get; } = new SecureRandom();

    }
}