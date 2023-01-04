namespace ArmAes;

internal static partial class KeygenUtil
{
    private const nuint BytesPerRoundKey = 16;

    #region 128

    public static void EncKeygen128(ReadOnlySpan<byte> key, ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported &&
            System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.EncKeygen128(key, ref keySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.EncKeygen128(key, ref keySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    public static void EncDecKeygen128(ReadOnlySpan<byte> key, ref byte encKeySchedule, ref byte decKeySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported &&
            System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.EncDecKeygen128(key, ref encKeySchedule, ref decKeySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.EncDecKeygen128(key, ref encKeySchedule, ref decKeySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    public static void DecKeygen128(ReadOnlySpan<byte> key, ref byte decKeySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported &&
            System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.DecKeygen128(key, ref decKeySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.DecKeygen128(key, ref decKeySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    #endregion

    #region 192

    public static void EncKeygen192(ReadOnlySpan<byte> key, ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported &&
            System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.EncKeygen192(key, ref keySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.EncKeygen192(key, ref keySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    public static void EncDecKeygen192(ReadOnlySpan<byte> key, ref byte encKeySchedule, ref byte decKeySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported &&
            System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.EncDecKeygen192(key, ref encKeySchedule, ref decKeySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.EncDecKeygen192(key, ref encKeySchedule, ref decKeySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    public static void DecKeygen192(ReadOnlySpan<byte> key, ref byte decKeySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported &&
            System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.DecKeygen192(key, ref decKeySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.DecKeygen192(key, ref decKeySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    #endregion

    #region 256

    public static void EncKeygen256(ReadOnlySpan<byte> key, ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported &&
            System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.EncKeygen256(key, ref keySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.EncKeygen256(key, ref keySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    public static void EncDecKeygen256(ReadOnlySpan<byte> key, ref byte encKeySchedule, ref byte decKeySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported &&
            System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.EncDecKeygen256(key, ref encKeySchedule, ref decKeySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.EncDecKeygen256(key, ref encKeySchedule, ref decKeySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    public static void DecKeygen256(ReadOnlySpan<byte> key, ref byte decKeySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported &&
            System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.DecKeygen256(key, ref decKeySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.DecKeygen256(key, ref decKeySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    #endregion
}