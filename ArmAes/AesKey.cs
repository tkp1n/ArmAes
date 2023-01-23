using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace ArmAes
{
    [Flags]
    public enum KeyMode
    {
        Encrypt = 1,
        Decrypt = 2
    }

    public readonly ref struct AesKey
    {
        private const int BytesPerRoundKey = 16;

        private readonly KeyMode _mode;
        private readonly int _keyLen;
        private readonly Span<byte> _enc;
        private readonly Span<byte> _dec;

        public AesKey(ReadOnlySpan<byte> key, KeyMode mode = KeyMode.Encrypt | KeyMode.Decrypt)
        {
            _mode = mode;
            _keyLen = key.Length;
            if (mode.HasFlag(KeyMode.Encrypt))
                _enc = GC.AllocateUninitializedArray<byte>((1 + Rounds(key.Length)) * BytesPerRoundKey);
            else
                _enc = Span<byte>.Empty;

            if (mode.HasFlag(KeyMode.Decrypt))
                _dec = GC.AllocateUninitializedArray<byte>((1 + Rounds(key.Length)) * BytesPerRoundKey);
            else
                _dec = Span<byte>.Empty;

            ExpandKey(key);
        }

        internal KeyMode Mode => _mode;
        internal int Length => _keyLen;

        internal ref byte EncryptKeySchedule
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get
            {
                Debug.Assert(_mode.HasFlag(KeyMode.Encrypt));
                return ref MemoryMarshal.GetReference(_enc);
            }
        }

        internal ref byte DecryptKeySchedule
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get
            {
                Debug.Assert(_mode.HasFlag(KeyMode.Decrypt));
                return ref MemoryMarshal.GetReference(_dec);
            }
        }

        private static int Rounds(int keyLen) => keyLen switch
        {
            16 => 10,
            24 => 12,
            32 => 14,
            _ => ThrowHelper.ThrowUnknownKeySizeException<int>(nameof(keyLen), keyLen)
        };

        private void ExpandKey(ReadOnlySpan<byte> key)
        {
            if (key.Length != _keyLen)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(key));
            }

            if (_keyLen == 16)
            {
                if (_mode.HasFlag(KeyMode.Encrypt) && _mode.HasFlag(KeyMode.Decrypt))
                {
                    KeygenUtil.EncDecKeygen128(key, ref EncryptKeySchedule, ref DecryptKeySchedule);
                }
                else if (_mode.HasFlag(KeyMode.Encrypt))
                {
                    KeygenUtil.EncKeygen128(key, ref EncryptKeySchedule);
                }
                else if (_mode.HasFlag(KeyMode.Decrypt))
                {
                    KeygenUtil.DecKeygen128(key, ref DecryptKeySchedule);
                }
            }
            else if (_keyLen == 24)
            {
                if (_mode.HasFlag(KeyMode.Encrypt) && _mode.HasFlag(KeyMode.Decrypt))
                {
                    KeygenUtil.EncDecKeygen192(key, ref EncryptKeySchedule, ref DecryptKeySchedule);
                }
                else if (_mode.HasFlag(KeyMode.Encrypt))
                {
                    KeygenUtil.EncKeygen192(key, ref EncryptKeySchedule);
                }
                else if (_mode.HasFlag(KeyMode.Decrypt))
                {
                    KeygenUtil.DecKeygen192(key, ref DecryptKeySchedule);
                }
            }
            else if (_keyLen == 32)
            {
                if (_mode.HasFlag(KeyMode.Encrypt) && _mode.HasFlag(KeyMode.Decrypt))
                {
                    KeygenUtil.EncDecKeygen256(key, ref EncryptKeySchedule, ref DecryptKeySchedule);
                }
                else if (_mode.HasFlag(KeyMode.Encrypt))
                {
                    KeygenUtil.EncKeygen256(key, ref EncryptKeySchedule);
                }
                else if (_mode.HasFlag(KeyMode.Decrypt))
                {
                    KeygenUtil.DecKeygen256(key, ref DecryptKeySchedule);
                }
            }
        }
    }
}