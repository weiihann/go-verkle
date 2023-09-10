package verkle

type StateEpoch uint16

// EpochExpired check pre epoch if expired compared to current epoch
func EpochExpired(pre StateEpoch, cur StateEpoch) bool {
	return cur >= 2 && pre < cur-1
}

func EpochToBytes(epoch StateEpoch) []byte {
	return []byte{byte(epoch >> 8), byte(epoch)}
}
