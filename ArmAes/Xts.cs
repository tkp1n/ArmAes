using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

namespace ArmAes;

public static partial class Xts
{
    private const nuint BytesPerBlock = 16;
    private const nuint ParallelTweaks = 16;
    private const nuint DataUnit = 512;

    internal static void EncryptXts(
        ReadOnlySpan<byte> input,
        Span<byte> output,
        long dataUnitSeqNumber,
        in XtsKey keys,
        nuint dataUnitLen = DataUnit)
    {
        Span<byte> iv = stackalloc byte[16];
        ref var ivRef = ref MemoryMarshal.GetReference(iv);

        Unsafe.As<byte, long>(ref ivRef) = dataUnitSeqNumber;

        EncryptXts(input, output, iv, keys, dataUnitLen);
    }

    internal static void EncryptXts(
        ReadOnlySpan<byte> input,
        Span<byte> output,
        ReadOnlySpan<byte> iv,
        in XtsKey keys,
        nuint dataUnitLen = DataUnit)
    {
        if (keys.Length == 64)
        {
            EncryptXts256(input, output, iv, keys, dataUnitLen);
        }
        else if (keys.Length == 32)
        {
            EncryptXts128(input, output, iv, keys, dataUnitLen);
        }
        else
        {
            ThrowHelper.ThrowPlatformNotSupportedException();
        }
    }

    private static void EncryptXts256(
        ReadOnlySpan<byte> input,
        Span<byte> output,
        ReadOnlySpan<byte> iv,
        in XtsKey keys,
        nuint dataUnitLen)
    {
        Span<byte> tweaks = stackalloc byte[(int)(ParallelTweaks * BytesPerBlock)];
        ref var tweakRef = ref MemoryMarshal.GetReference(tweaks);
        var ivVec = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(iv));

        var ptLen = (nuint)input.Length;
        var (dataUnits, remainder) = Math.DivRem(ptLen, dataUnitLen);
        var tweakRounds = dataUnits;
        if (remainder != 0) tweakRounds++;
        if (tweakRounds > ParallelTweaks) ThrowHelper.ThrowArgumentOutOfRangeException(nameof(input));

        nuint tweakBytes = 0;
        while (tweakRounds-- > 0)
        {
            ivVec.StoreUnsafe(ref tweakRef, tweakBytes);
            ivVec = XtsUtil.AddOne(ivVec);
            tweakBytes += BytesPerBlock;
        }

        Ecb.EncryptEcb256(keys.Key2, ref tweakRef, tweakBytes, ref tweakRef);

        ref var pt = ref MemoryMarshal.GetReference(input);
        ref var ct = ref MemoryMarshal.GetReference(output);

        while (dataUnits-- > 0)
        {
            EncryptDataUnit256(
                keys.Key1,
                ref tweakRef,
                ref pt, dataUnitLen,
                ref ct);

            tweakRef = ref Unsafe.AddByteOffset(ref tweakRef, BytesPerBlock);
            pt = ref Unsafe.AddByteOffset(ref pt, dataUnitLen);
            ct = ref Unsafe.AddByteOffset(ref ct, dataUnitLen);
        }

        if (remainder > 0)
        {
            EncryptDataUnit256(
                keys.Key1,
                ref tweakRef,
                ref pt, remainder,
                ref ct);
        }
    }

    private static void EncryptXts128(
        ReadOnlySpan<byte> input,
        Span<byte> output,
        ReadOnlySpan<byte> iv,
        in XtsKey keys,
        nuint dataUnitLen)
    {
        Span<byte> tweaks = stackalloc byte[(int)(ParallelTweaks * BytesPerBlock)];
        ref var tweakRef = ref MemoryMarshal.GetReference(tweaks);
        var ivVec = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(iv));

        var ptLen = (nuint)input.Length;
        var (dataUnits, remainder) = Math.DivRem(ptLen, dataUnitLen);
        var tweakRounds = dataUnits;
        if (remainder != 0) tweakRounds++;
        if (tweakRounds > ParallelTweaks) ThrowHelper.ThrowArgumentOutOfRangeException(nameof(input));

        nuint tweakBytes = 0;
        while (tweakRounds-- > 0)
        {
            ivVec.StoreUnsafe(ref tweakRef, tweakBytes);
            ivVec = XtsUtil.AddOne(ivVec);
            tweakBytes += BytesPerBlock;
        }

        Ecb.EncryptEcb128(keys.Key2, ref tweakRef, tweakBytes, ref tweakRef);

        ref var pt = ref MemoryMarshal.GetReference(input);
        ref var ct = ref MemoryMarshal.GetReference(output);

        while (dataUnits-- > 0)
        {
            EncryptDataUnit128(
                keys.Key1,
                ref tweakRef,
                ref pt, dataUnitLen,
                ref ct);

            tweakRef = ref Unsafe.AddByteOffset(ref tweakRef, BytesPerBlock);
            pt = ref Unsafe.AddByteOffset(ref pt, dataUnitLen);
            ct = ref Unsafe.AddByteOffset(ref ct, dataUnitLen);
        }

        if (remainder > 0)
        {
            EncryptDataUnit128(
                keys.Key1,
                ref tweakRef,
                ref pt, remainder,
                ref ct);
        }
    }

    internal static void DecryptXts(
        ReadOnlySpan<byte> input,
        Span<byte> output,
        long dataUnitSeqNumber,
        in XtsKey keys,
        nuint dataUnitLen = DataUnit)
    {
        Span<byte> iv = stackalloc byte[16];
        ref var ivRef = ref MemoryMarshal.GetReference(iv);

        Unsafe.As<byte, long>(ref ivRef) = dataUnitSeqNumber;

        DecryptXts(input, output, iv, keys, dataUnitLen);
    }

    internal static void DecryptXts(
        ReadOnlySpan<byte> input,
        Span<byte> output,
        ReadOnlySpan<byte> iv,
        in XtsKey keys,
        nuint dataUnitLen = DataUnit)
    {
        if (keys.Length == 64)
        {
            DecryptXts256(input, output, iv, keys, dataUnitLen);
        }
        else if (keys.Length == 32)
        {
            DecryptXts128(input, output, iv, keys, dataUnitLen);
        }
        else
        {
            ThrowHelper.ThrowUnknownKeySizeException<bool>(nameof(keys), keys.Length);
        }
    }

    private static void DecryptXts256(
        ReadOnlySpan<byte> input,
        Span<byte> output,
        ReadOnlySpan<byte> iv,
        in XtsKey keys,
        nuint dataUnitLen)
    {
        Span<byte> tweaks = stackalloc byte[(int)(ParallelTweaks * BytesPerBlock)];
        ref var tweakRef = ref MemoryMarshal.GetReference(tweaks);
        var ivVec = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(iv));

        var ctLen = (nuint)input.Length;
        var (dataUnits, remainder) = Math.DivRem(ctLen, dataUnitLen);
        var tweakRounds = dataUnits;
        if (remainder != 0) tweakRounds++;
        if (tweakRounds > ParallelTweaks) ThrowHelper.ThrowArgumentOutOfRangeException(nameof(input));

        nuint tweakBytes = 0;
        while (tweakRounds-- > 0)
        {
            ivVec.StoreUnsafe(ref tweakRef, tweakBytes);
            ivVec = XtsUtil.AddOne(ivVec);
            tweakBytes += BytesPerBlock;
        }

        Ecb.EncryptEcb256(keys.Key2, ref tweakRef, tweakBytes, ref tweakRef);

        ref var ct = ref MemoryMarshal.GetReference(input);
        ref var pt = ref MemoryMarshal.GetReference(output);

        while (dataUnits-- > 0)
        {
            DecryptDataUnit256(
                keys.Key1,
                ref tweakRef,
                ref ct, dataUnitLen,
                ref pt);

            tweakRef = ref Unsafe.AddByteOffset(ref tweakRef, BytesPerBlock);
            ct = ref Unsafe.AddByteOffset(ref ct, dataUnitLen);
            pt = ref Unsafe.AddByteOffset(ref pt, dataUnitLen);
        }

        if (remainder > 0)
        {
            DecryptDataUnit256(
                keys.Key1,
                ref tweakRef,
                ref ct, remainder,
                ref pt);
        }
    }

    private static void DecryptXts128(
        ReadOnlySpan<byte> input,
        Span<byte> output,
        ReadOnlySpan<byte> iv,
        in XtsKey keys,
        nuint dataUnitLen)
    {
        Span<byte> tweaks = stackalloc byte[(int)(ParallelTweaks * BytesPerBlock)];
        ref var tweakRef = ref MemoryMarshal.GetReference(tweaks);
        var ivVec = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(iv));

        var ctLen = (nuint)input.Length;
        var (dataUnits, remainder) = Math.DivRem(ctLen, dataUnitLen);
        var tweakRounds = dataUnits;
        if (remainder != 0) tweakRounds++;
        if (tweakRounds > ParallelTweaks) ThrowHelper.ThrowArgumentOutOfRangeException(nameof(input));

        nuint tweakBytes = 0;
        while (tweakRounds-- > 0)
        {
            ivVec.StoreUnsafe(ref tweakRef, tweakBytes);
            ivVec = XtsUtil.AddOne(ivVec);
            tweakBytes += BytesPerBlock;
        }

        Ecb.EncryptEcb128(keys.Key2, ref tweakRef, tweakBytes, ref tweakRef);

        ref var ct = ref MemoryMarshal.GetReference(input);
        ref var pt = ref MemoryMarshal.GetReference(output);

        while (dataUnits-- > 0)
        {
            DecryptDataUnit128(
                keys.Key1,
                ref tweakRef,
                ref ct, dataUnitLen,
                ref pt);

            tweakRef = ref Unsafe.AddByteOffset(ref tweakRef, BytesPerBlock);
            ct = ref Unsafe.AddByteOffset(ref ct, dataUnitLen);
            pt = ref Unsafe.AddByteOffset(ref pt, dataUnitLen);
        }

        if (remainder > 0)
        {
            DecryptDataUnit128(
                keys.Key1,
                ref tweakRef,
                ref ct, remainder,
                ref pt);
        }
    }
}