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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static nuint PrepareTweaks(ReadOnlySpan<byte> iv, nuint dataUnits, nuint remainder, Span<byte> tweaks)
    {
        ref var ivRef = ref MemoryMarshal.GetReference(iv);
        ref var tweakRef = ref MemoryMarshal.GetReference(tweaks);

        var tweakRounds = dataUnits;
        if (remainder != 0) tweakRounds++;
        if (tweakRounds * BytesPerBlock > (nuint)tweaks.Length)
            ThrowHelper.ThrowArgumentOutOfRangeException(nameof(dataUnits));

        nuint tweakBytes = 0;
        var a = Unsafe.AddByteOffset(ref Unsafe.As<byte, long>(ref ivRef), 0);
        var b = Unsafe.AddByteOffset(ref Unsafe.As<byte, long>(ref ivRef), 8);

        while (tweakRounds-- > 0)
        {
            Unsafe.AddByteOffset(ref Unsafe.As<byte, long>(ref tweakRef), 0) = a;
            Unsafe.AddByteOffset(ref Unsafe.As<byte, long>(ref tweakRef), 8) = b;

            var aInc = a + 1;
            if (aInc < a) b++;
            a = aInc;

            tweakBytes += BytesPerBlock;
        }

        return tweakBytes;
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

        var ptLen = (nuint)input.Length;
        var (dataUnits, remainder) = Math.DivRem(ptLen, dataUnitLen);

        var tweakBytes = PrepareTweaks(iv, dataUnits, remainder, tweaks);

        Ecb.EncryptEcb256(keys.Key2, tweaks[..(int)tweakBytes], tweaks);

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

        var ptLen = (nuint)input.Length;
        var (dataUnits, remainder) = Math.DivRem(ptLen, dataUnitLen);

        var tweakBytes = PrepareTweaks(iv, dataUnits, remainder, tweaks);

        Ecb.EncryptEcb128(keys.Key2, tweaks[..(int)tweakBytes], tweaks);

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

        var ctLen = (nuint)input.Length;
        var (dataUnits, remainder) = Math.DivRem(ctLen, dataUnitLen);

        var tweakBytes = PrepareTweaks(iv, dataUnits, remainder, tweaks);

        Ecb.EncryptEcb256(keys.Key2, tweaks[..(int)tweakBytes], tweaks);

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

        var ptLen = (nuint)input.Length;
        var (dataUnits, remainder) = Math.DivRem(ptLen, dataUnitLen);

        var tweakBytes = PrepareTweaks(iv, dataUnits, remainder, tweaks);

        Ecb.EncryptEcb128(keys.Key2, tweaks[..(int)tweakBytes], tweaks);

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