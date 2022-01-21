package ghidrasync;

import java.util.HashMap;
import java.util.UUID;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.util.ObjectStorage;
import ghidra.util.Saveable;
import ghidra.util.datastruct.LongArrayList;

public class TypeMapper {
    public static class UUIDMap implements Saveable {
        private HashMap<Long, UUID> map;
        private HashMap<UUID, Long> mapReverse;

        public UUIDMap() {
            map = new HashMap<>();
            mapReverse = new HashMap<>();
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
                mapReverse.put(v, k);
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

        public UUID getUUID(long key) {
            return map.get(key);
        }

        public Long getTypeID(UUID uuid) {
            return mapReverse.get(uuid);
        }

        public void set(long key, UUID value) {
            map.put(key, value);
            mapReverse.put(value, key);
        }
    }

    private Program                     program;
    private ProgramBasedDataTypeManager typeManager;
    private ObjectPropertyMap           propMap;
    private Address                     mapAddr;
    private UUIDMap                     map;

    TypeMapper(Program aProgram) {
        program = aProgram;
        typeManager = program.getDataTypeManager();
        propMap = program.getProgramUserData().getObjectProperty("GhidraSyncPlugin", "UUIDMap", UUIDMap.class, true);
        mapAddr = propMap.getFirstPropertyAddress();
        if (mapAddr != null) {
            map = (UUIDMap)propMap.getObject(mapAddr);
        } else {
            mapAddr = program.getImageBase();
            map = new UUIDMap();
        }
    }

    public UUID getUUID(DataType type) {
        long key = typeManager.getID(type);
        UUID uuid = map.getUUID(key);
        if (uuid == null) {
            uuid = UUID.randomUUID();
            map.set(key, uuid);
        }
        return uuid;
    }

    public DataType getType(UUID uuid) {
        Long key = map.getTypeID(uuid);
        if (key == null)
            return null;
        return typeManager.getDataType(key);
    }

    public void update(DataType type, UUID uuid) {
        long key = typeManager.getID(type);
        map.set(key, uuid);
    }

    public void save() {
        propMap.add(mapAddr, map);
    }
}
