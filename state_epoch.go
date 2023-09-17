package verkle

type StateEpoch uint16

const (
	StateEpoch0 = StateEpoch(0)
	StateEpoch1 = StateEpoch(1)
)

// EpochExpired check pre epoch if expired compared to current epoch
func EpochExpired(pre StateEpoch, cur StateEpoch) bool {
	return cur >= 2 && pre < cur-1
}

func EpochToBytes(epoch StateEpoch) []byte {
	return []byte{byte(epoch >> 8), byte(epoch)}
}

func BytesToEpoch(b []byte) StateEpoch {
	return StateEpoch(b[0])<<8 | StateEpoch(b[1])
}
