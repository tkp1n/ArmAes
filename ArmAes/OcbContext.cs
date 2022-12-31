using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using static ArmAes.OcbHelpers;

namespace ArmAes;

internal readonly ref struct OcbContext
{
    private const nuint BytesPerBlock = 16;

    private readonly Span<byte> _lstar;
    private readonly Span<byte> _ldollar;
    private readonly Span<byte> _l;

    internal OcbContext(AesKey key, int inputLen, int addtLen)
    {
        var maxLen = Math.Max(inputLen, addtLen);
        var lCount = 0;
        if (maxLen != 0)
            lCount =  31 - int.LeadingZeroCount(maxLen);

        _lstar = GC.AllocateUninitializedArray<byte>(16);
        _ldollar = GC.AllocateUninitializedArray<byte>(16);
        _l = GC.AllocateUninitializedArray<byte>(16 * lCount);

        var tmp = key.Length switch
        {
            16 => AesUtil.Encrypt128(ref key.EncryptKeySchedule, Vector128<byte>.Zero),
            24 => AesUtil.Encrypt192(ref key.EncryptKeySchedule, Vector128<byte>.Zero),
            32 => AesUtil.Encrypt256(ref key.EncryptKeySchedule, Vector128<byte>.Zero),
            _ => ThrowHelper.ThrowUnknownKeySizeException<Vector128<byte>>(nameof(key), key.Length)
        };
        Lstar = tmp;
        tmp = SwapIfLe(tmp);
        tmp = Double(tmp);
        Ldollar = SwapIfLe(tmp);

        for (nuint i = 0; i < (nuint)lCount; i++)
        {
            tmp = Double(tmp);
            SwapIfLe(tmp).StoreUnsafe(ref MemoryMarshal.GetReference(_l), BytesPerBlock * i);
        }
    }

    public Vector128<byte> Lstar
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(_lstar));
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        set => value.StoreUnsafe(ref MemoryMarshal.GetReference(_lstar));
    }

    public Vector128<byte> Ldollar
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(_ldollar));
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        set => value.StoreUnsafe(ref MemoryMarshal.GetReference(_ldollar));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public Vector128<byte> L(nuint offset)
        => Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(_l), offset * BytesPerBlock);
}