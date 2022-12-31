using System.Runtime.InteropServices;

namespace ArmAes;

public static partial class Ocb
{
    private const nuint Bpi = 4;
    private const nuint BytesPerBlock = 16;

    internal static void EncryptOcb(
        ReadOnlySpan<byte> input,
        Span<byte> output,
        ReadOnlySpan<byte> addt,
        ReadOnlySpan<byte> iv,
        Span<byte> tag,
        in AesKey key)
    {
        var ctx = new OcbContext(key, input.Length, addt.Length);

        if (key.Length == 16)
        {
            AeEncrypt128(
                ctx,
                key,
                ref MemoryMarshal.GetReference(input), (nuint)input.Length,
                ref MemoryMarshal.GetReference(iv),
                ref MemoryMarshal.GetReference(addt), (nuint)addt.Length,
                ref MemoryMarshal.GetReference(output),
                ref MemoryMarshal.GetReference(tag), (nuint)tag.Length
            );
        }
        else if (key.Length == 24)
        {
            AeEncrypt192(
                ctx,
                key,
                ref MemoryMarshal.GetReference(input), (nuint)input.Length,
                ref MemoryMarshal.GetReference(iv),
                ref MemoryMarshal.GetReference(addt), (nuint)addt.Length,
                ref MemoryMarshal.GetReference(output),
                ref MemoryMarshal.GetReference(tag), (nuint)tag.Length
            );
        }
        else if (key.Length == 32)
        {
            AeEncrypt256(
                ctx,
                key,
                ref MemoryMarshal.GetReference(input), (nuint)input.Length,
                ref MemoryMarshal.GetReference(iv),
                ref MemoryMarshal.GetReference(addt), (nuint)addt.Length,
                ref MemoryMarshal.GetReference(output),
                ref MemoryMarshal.GetReference(tag), (nuint)tag.Length
            );
        }
        else
        {
            ThrowHelper.ThrowUnknownKeySizeException<int>(nameof(key), key.Length);
        }
    }

    internal static bool DecryptOcb(
        ReadOnlySpan<byte> input,
        Span<byte> output,
        ReadOnlySpan<byte> addt,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> tag,
        in AesKey key)
    {
        var ctx = new OcbContext(key, input.Length, addt.Length);

        if (key.Length == 16)
        {
            return AeDecrypt128(
                ctx,
                key,
                ref MemoryMarshal.GetReference(input), (nuint)input.Length,
                ref MemoryMarshal.GetReference(iv),
                ref MemoryMarshal.GetReference(addt), (nuint)addt.Length,
                ref MemoryMarshal.GetReference(output),
                ref MemoryMarshal.GetReference(tag), (nuint)tag.Length
            );
        }
        else if (key.Length == 24)
        {
            return AeDecrypt192(
                ctx,
                key,
                ref MemoryMarshal.GetReference(input), (nuint)input.Length,
                ref MemoryMarshal.GetReference(iv),
                ref MemoryMarshal.GetReference(addt), (nuint)addt.Length,
                ref MemoryMarshal.GetReference(output),
                ref MemoryMarshal.GetReference(tag), (nuint)tag.Length
            );
        }
        else if (key.Length == 32)
        {
            return AeDecrypt256(
                ctx,
                key,
                ref MemoryMarshal.GetReference(input), (nuint)input.Length,
                ref MemoryMarshal.GetReference(iv),
                ref MemoryMarshal.GetReference(addt), (nuint)addt.Length,
                ref MemoryMarshal.GetReference(output),
                ref MemoryMarshal.GetReference(tag), (nuint)tag.Length
            );
        }
        else
        {
            return ThrowHelper.ThrowUnknownKeySizeException<bool>(nameof(key), key.Length);
        }
    }
}