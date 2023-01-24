using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;

namespace ArmAes;

public static partial class Gcm
{
    private const nuint BytesPerBlock = 16;

    private static readonly Vector128<byte> One = Vector128.Create(0, 0, 1, 0).AsByte();
    private static readonly Vector128<byte> Four = Vector128.Create(0, 0, 4, 0).AsByte();

    internal static void EncryptGcm(
        ReadOnlySpan<byte> input,
        Span<byte> output,
        ReadOnlySpan<byte> addt,
        ReadOnlySpan<byte> iv,
        Span<byte> tag,
        in AesKey key)
    {
        if (key.Length == 16)
        {
            AeEncrypt128(
                key,
                ref MemoryMarshal.GetReference(input), (nuint)input.Length,
                ref MemoryMarshal.GetReference(iv), (nuint)iv.Length,
                ref MemoryMarshal.GetReference(addt), (nuint)addt.Length,
                ref MemoryMarshal.GetReference(output),
                ref MemoryMarshal.GetReference(tag), (nuint)tag.Length
            );
        }
        else if (key.Length == 24)
        {
            AeEncrypt192(
                key,
                ref MemoryMarshal.GetReference(input), (nuint)input.Length,
                ref MemoryMarshal.GetReference(iv), (nuint)iv.Length,
                ref MemoryMarshal.GetReference(addt), (nuint)addt.Length,
                ref MemoryMarshal.GetReference(output),
                ref MemoryMarshal.GetReference(tag), (nuint)tag.Length
            );
        }
        else if (key.Length == 32)
        {
            AeEncrypt256(
                key,
                ref MemoryMarshal.GetReference(input), (nuint)input.Length,
                ref MemoryMarshal.GetReference(iv), (nuint)iv.Length,
                ref MemoryMarshal.GetReference(addt), (nuint)addt.Length,
                ref MemoryMarshal.GetReference(output),
                ref MemoryMarshal.GetReference(tag), (nuint)tag.Length
            );
        }
        else
        {
            ThrowHelper.ThrowUnknownKeySizeException<bool>(nameof(key), key.Length);
        }
    }

    internal static bool DecryptGcm(
        ReadOnlySpan<byte> input,
        Span<byte> output,
        ReadOnlySpan<byte> addt,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> tag,
        in AesKey key)
    {
        if (tag.Length > 16)
        {
            ThrowHelper.ThrowArgumentOutOfRangeException(nameof(tag));
        }

        Span<byte> refTag = stackalloc byte[16];

        if (key.Length == 16)
        {
            AeDecrypt128(
                key,
                ref MemoryMarshal.GetReference(input), (nuint)input.Length,
                ref MemoryMarshal.GetReference(iv),(nuint)iv.Length,
                ref MemoryMarshal.GetReference(addt), (nuint)addt.Length,
                ref MemoryMarshal.GetReference(output),
                ref MemoryMarshal.GetReference(refTag), (nuint)tag.Length
            );
        }
        else if (key.Length == 24)
        {
            AeDecrypt192(
                key,
                ref MemoryMarshal.GetReference(input), (nuint)input.Length,
                ref MemoryMarshal.GetReference(iv),(nuint)iv.Length,
                ref MemoryMarshal.GetReference(addt), (nuint)addt.Length,
                ref MemoryMarshal.GetReference(output),
                ref MemoryMarshal.GetReference(refTag), (nuint)tag.Length
            );
        }
        else if (key.Length == 32)
        {
            AeDecrypt256(
                key,
                ref MemoryMarshal.GetReference(input), (nuint)input.Length,
                ref MemoryMarshal.GetReference(iv),(nuint)iv.Length,
                ref MemoryMarshal.GetReference(addt), (nuint)addt.Length,
                ref MemoryMarshal.GetReference(output),
                ref MemoryMarshal.GetReference(refTag), (nuint)tag.Length
            );
        }
        else
        {
            return ThrowHelper.ThrowUnknownKeySizeException<bool>(nameof(key), key.Length);
        }

        return CryptographicOperations.FixedTimeEquals(refTag[..tag.Length], tag);
    }
}