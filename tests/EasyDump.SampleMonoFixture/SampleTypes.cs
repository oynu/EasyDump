using System.Runtime.InteropServices;

namespace SampleGame.Gameplay;

[StructLayout(LayoutKind.Explicit)]
public struct PlayerStatsPacket
{
    [FieldOffset(0x00)]
    public int Health;

    [FieldOffset(0x08)]
    public float Speed;

    [FieldOffset(0x10)]
    public long Experience;
}

public abstract class EntityBase
{
    public const int MaxEntities = 256;
    public int Id;
    private string _name = string.Empty;

    public abstract void Tick(float deltaTime);

    public int GetId() => Id;
}

public sealed class PlayerController : EntityBase
{
    public static int ActiveCount;
    public float MoveSpeed;

    public override void Tick(float deltaTime)
    {
        MoveSpeed += deltaTime * 0.1f;
    }

    public void ApplyDamage(int amount, bool bypassArmor)
    {
        if (bypassArmor && amount > 0)
            MoveSpeed = 0f;
    }

    public sealed class InventorySlot
    {
        public int ItemId;
    }
}
