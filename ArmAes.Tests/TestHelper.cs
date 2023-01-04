using System;

namespace ArmAes.Tests;

internal static class TestHelper
{
    public static byte[] ToByteArray(this string hex)
    {
        if (hex.Length % 2 != 0) hex = "0" + hex;
        return Convert.FromHexString(hex);
    }
}