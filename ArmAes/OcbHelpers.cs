using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

namespace ArmAes;

internal static partial class OcbHelpers
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> Double(Vector128<byte> b)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported)
        {
            return Arm.Double(b);
        }
        else if (System.Runtime.Intrinsics.X86.Sse2.IsSupported)
        {
            return X86.Double(b);
        }

        ThrowHelper.ThrowPlatformNotSupportedException();
        return default;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> GenOffsetFromNonce128(ref byte nonce, ref byte keySchedule, nuint tagLen)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported)
        {
            return Arm.GenOffsetFromNonce128(ref nonce, ref keySchedule, tagLen);
        }
        else if (System.Runtime.Intrinsics.X86.Sse2.IsSupported)
        {
            return X86.GenOffsetFromNonce128(ref nonce, ref keySchedule, tagLen);
        }

        ThrowHelper.ThrowPlatformNotSupportedException();
        return default;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> GenOffsetFromNonce192(ref byte nonce, ref byte keySchedule, nuint tagLen)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported)
        {
            return Arm.GenOffsetFromNonce192(ref nonce, ref keySchedule, tagLen);
        }
        else if (System.Runtime.Intrinsics.X86.Sse2.IsSupported)
        {
            return X86.GenOffsetFromNonce192(ref nonce, ref keySchedule, tagLen);
        }

        ThrowHelper.ThrowPlatformNotSupportedException();
        return default;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> GenOffsetFromNonce256(ref byte nonce, ref byte keySchedule, nuint tagLen)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported)
        {
            return Arm.GenOffsetFromNonce256(ref nonce, ref keySchedule, tagLen);
        }
        else if (System.Runtime.Intrinsics.X86.Sse2.IsSupported)
        {
            return X86.GenOffsetFromNonce256(ref nonce, ref keySchedule, tagLen);
        }

        ThrowHelper.ThrowPlatformNotSupportedException();
        return default;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static Vector128<byte> SwapIfLe(Vector128<byte> block)
    {
        if (System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported)
        {
            return Arm.SwapIfLe(block);
        }
        else if (System.Runtime.Intrinsics.X86.Sse2.IsSupported)
        {
            return X86.SwapIfLe(block);
        }

        ThrowHelper.ThrowPlatformNotSupportedException();
        return default;
    }
}