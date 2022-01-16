package ghidrasync;

import java.util.HashMap;
import java.util.UUID;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.util.ObjectStorage;
import ghidra.util.Saveable;
import ghidra.util.UniversalID;
import ghidra.util.datastruct.LongArrayList;

public class TypeMapper {
    public static class UUIDMap implements Saveable {
        private HashMap<Long, UUID> map;

        public UUIDMap() {
            map = new HashMap<Long, UUID>();
        }

        public final Class<?>[] getObjectStorageFields() {
            return new Class<?>[]{long[].class, long[].class, long[].class};
        }

        public final int getSchemaVersion() {
            return 1;
        }
    
        public final boolean isPrivate() {
            return true;
        }

        public final boolean isUpgradeable(int version) {
            return false;
        }

        public final void restore(ObjectStorage objStorage) {
            long[] keys = objStorage.getLongs();
            long[] lo = objStorage.getLongs();
            long[] hi = objStorage.getLongs();

            map.clear();
            for (int i = 0; i < keys.length; ++i) {
                long k = keys[i];
                UUID v = new UUID(hi[i], lo[i]);
                map.put(k, v);
            }
        }

        public final void save(ObjectStorage objStorage) {
            LongArrayList keys = new LongArrayList();
            LongArrayList lo = new LongArrayList();
            LongArrayList hi = new LongArrayList();

            for (var entry : map.entrySet()) {
                keys.add(entry.getKey());
                lo.add(entry.getValue().getLeastSignificantBits());
                hi.add(entry.getValue().getMostSignificantBits());
            }

            objStorage.putLongs(keys.toLongArray());
            objStorage.putLongs(lo.toLongArray());
            objStorage.putLongs(hi.toLongArray());
        }

        public final boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion, ObjectStorage currentObjStorage) {
            return false;
        }

        public UUID get(long key) {
            return map.get(key);
        }

        public void set(long key, UUID value) {
            map.put(key, value);
        }
    }

    private Program             program;
    private ObjectPropertyMap   propMap;
    private Address             mapAddr;
    private UUIDMap             map;

    TypeMapper(Program aProgram) {
        program = aProgram;
        propMap = program.getProgramUserData().getObjectProperty("GhidraSyncPlugin", "UUIDMap", UUIDMap.class, true);
        mapAddr = propMap.getFirstPropertyAddress();
        if (mapAddr != null) {
            map = (UUIDMap)propMap.getObject(mapAddr);
        } else {
            mapAddr = program.getImageBase();
            map = new UUIDMap();
        }
    }

    public UUID getTypeUUID(DataType type) {
        UniversalID id = type.getUniversalID();
        if (id == null) {
            return new UUID(0, 0);
        }
        long key = id.getValue();
        UUID uuid = map.get(key);
        if (uuid == null) {
            uuid = UUID.randomUUID();
            map.set(key, uuid);
        }
        return uuid;
    }

    public void setTypeUUID(DataType type, UUID uuid) {
        UniversalID id = type.getUniversalID();
        if (id == null)
            return;
        long key = id.getValue();
        map.set(key, uuid);
    }

    public void save() {
        propMap.add(mapAddr, map);
    }
}
