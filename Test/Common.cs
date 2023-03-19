using Org.BouncyCastle.Security;

namespace Test
{
    internal static class Common
    {
        internal static SecureRandom SecureRandom { get; } = new SecureRandom();
    }
}