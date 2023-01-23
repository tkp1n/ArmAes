namespace ArmAes;

public readonly ref struct XtsKey
{
    public readonly AesKey Key1;
    public readonly AesKey Key2;

    public XtsKey(ReadOnlySpan<byte> key)
        : this(key[..(key.Length / 2)], key[(key.Length / 2)..])
    {
        if (key.Length % 2 != 0)
        {
            ThrowHelper.ThrowArgumentOutOfRangeException(nameof(key));
        }
    }

    public XtsKey(ReadOnlySpan<byte> key1, ReadOnlySpan<byte> key2)
    {
        if (key1.Length != key2.Length /* || key1.SequenceEqual(key2) */)
        {
            ThrowHelper.ThrowArgumentOutOfRangeException(nameof(key2));
        }

        Key1 = new AesKey(key1);
        Key2 = new AesKey(key2);
    }

    public int Length => Key1.Length + Key2.Length;
}