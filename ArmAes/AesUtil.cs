using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

namespace ArmAes;

internal static partial class AesUtil
{
    private const nuint BytesPerRoundKey = 16;

    #region 128

    #region KeyGen

    public static void EncKeygen128(ReadOnlySpan<byte> key, ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.Arm64.IsSupported &&
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
        if (System.Runtime.Intrinsics.Arm.AdvSimd.Arm64.IsSupported &&
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
        if (System.Runtime.Intrinsics.Arm.AdvSimd.Arm64.IsSupported &&
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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Encrypt128(
        ref Vector128<byte> ta0,
        ref Vector128<byte> ta1,
        ref Vector128<byte> ta2,
        ref Vector128<byte> ta3,
        ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.Encrypt128(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.Encrypt128(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> Encrypt128(ref byte keySchedule, Vector128<byte> input)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            return Arm.Encrypt128(ref keySchedule, input);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            return X86.Encrypt128(ref keySchedule, input);
        }

        ThrowHelper.ThrowPlatformNotSupportedException();
        return default;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Decrypt128(
        ref Vector128<byte> ta0,
        ref Vector128<byte> ta1,
        ref Vector128<byte> ta2,
        ref Vector128<byte> ta3,
        ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.Decrypt128(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.Decrypt128(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    #endregion

    #region 192

    #region KeyGen

    public static void EncKeygen192(ReadOnlySpan<byte> key, ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.Arm64.IsSupported &&
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
        if (System.Runtime.Intrinsics.Arm.AdvSimd.Arm64.IsSupported &&
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
        if (System.Runtime.Intrinsics.Arm.AdvSimd.Arm64.IsSupported &&
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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Encrypt192(
        ref Vector128<byte> ta0,
        ref Vector128<byte> ta1,
        ref Vector128<byte> ta2,
        ref Vector128<byte> ta3,
        ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.Encrypt192(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.Encrypt192(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> Encrypt192(ref byte keySchedule, Vector128<byte> input)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            return Arm.Encrypt192(ref keySchedule, input);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            return X86.Encrypt192(ref keySchedule, input);
        }

        ThrowHelper.ThrowPlatformNotSupportedException();
        return default;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Decrypt192(
        ref Vector128<byte> ta0,
        ref Vector128<byte> ta1,
        ref Vector128<byte> ta2,
        ref Vector128<byte> ta3,
        ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.Decrypt192(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.Decrypt192(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    #endregion

    #region 256

    #region KeyGen

    public static void EncKeygen256(ReadOnlySpan<byte> key, ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.Arm64.IsSupported &&
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
        if (System.Runtime.Intrinsics.Arm.AdvSimd.Arm64.IsSupported &&
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
        if (System.Runtime.Intrinsics.Arm.AdvSimd.Arm64.IsSupported &&
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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Encrypt256(
        ref Vector128<byte> ta0,
        ref Vector128<byte> ta1,
        ref Vector128<byte> ta2,
        ref Vector128<byte> ta3,
        ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.Encrypt256(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.Encrypt256(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> Encrypt256(ref byte keySchedule, Vector128<byte> input)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            return Arm.Encrypt256(ref keySchedule, input);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            return X86.Encrypt256(ref keySchedule, input);
        }

        ThrowHelper.ThrowPlatformNotSupportedException();
        return default;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Decrypt256(
        ref Vector128<byte> ta0,
        ref Vector128<byte> ta1,
        ref Vector128<byte> ta2,
        ref Vector128<byte> ta3,
        ref byte keySchedule)
    {
        if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            Arm.Decrypt256(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else if (System.Runtime.Intrinsics.X86.Aes.IsSupported)
        {
            X86.Decrypt256(ref ta0, ref ta1, ref ta2, ref ta3, ref keySchedule);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    #endregion
}