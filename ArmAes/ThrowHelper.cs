using System.Diagnostics.CodeAnalysis;

namespace ArmAes
{
    internal static class ThrowHelper
    {
        [DoesNotReturn]
        public static void ThrowPlatformNotSupportedException()
            => throw new PlatformNotSupportedException();

        [DoesNotReturn]
        public static void ThrowArgumentNullException(string argument)
            => throw new ArgumentNullException(argument);

        [DoesNotReturn]
        public static T ThrowUnknownKeySizeException<T>(string argument, int keyLength)
            => throw new ArgumentOutOfRangeException(argument, $"Key size not supported: ${keyLength}");
    }
}