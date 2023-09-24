// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <https://unlicense.org>

package verkle

import (
	"errors"
	"fmt"

	"github.com/crate-crypto/go-ipa/banderwagon"
)

type HashedNode struct{}

type ExpiryHashedNode struct {
	stem       []byte
	commitment *Point
	epoch      StateEpoch
}

func (HashedNode) Insert([]byte, []byte, NodeResolverFn) error {
	return errInsertIntoHash
}

func (HashedNode) Delete([]byte, NodeResolverFn) (bool, error) {
	return false, errors.New("cant delete a hashed node in-place")
}

func (HashedNode) Get([]byte, NodeResolverFn) ([]byte, error) {
	return nil, errors.New("can not read from a hash node")
}

func (HashedNode) Commit() *Point {
	panic("cannot commit a hashed node")
}

func (HashedNode) Commitment() *Point {
	return nil
}

func (HashedNode) GetProofItems(keylist, NodeResolverFn) (*ProofElements, []byte, [][]byte, error) {
	return nil, nil, nil, errors.New("can not get the full path, and there is no proof of absence")
}

func (HashedNode) GetProofItemsWithEpoch(keys keylist, resolver NodeResolverFn, epoch StateEpoch) (*ProofElements, []byte, [][]byte, error) {
	return nil, nil, nil, errors.New("trying to produce a commitment for an empty subtree")
}

func (HashedNode) Serialize() ([]byte, error) {
	return nil, errSerializeHashedNode
}

func (HashedNode) Copy() VerkleNode {
	return HashedNode{}
}

func (HashedNode) toDot(parent, path string) string {
	return fmt.Sprintf("hash%s [label=\"unresolved\"]\n%s -> hash%s\n", path, parent, path)
}

func (HashedNode) setDepth(_ byte) {
	// do nothing
}

func (HashedNode) Hash() *Fr {
	panic("can not hash a hashed node")
}

func (HashedNode) Revive([]byte, [][]byte, NodeResolverFn) error {
	return errExpiredNodeNotFound
}

func (n *ExpiryHashedNode) Insert([]byte, []byte, NodeResolverFn) error {
	return errInsertIntoHash
}

func (n *ExpiryHashedNode) Delete([]byte, NodeResolverFn) (bool, error) {
	return false, errors.New("cant delete a hashed node in-place")
}

func (n *ExpiryHashedNode) Get([]byte, NodeResolverFn) ([]byte, error) {
	return nil, errors.New("can not read from a hash node")
}

func (n *ExpiryHashedNode) Commit() *Point {
	return n.commitment
}

func (n *ExpiryHashedNode) Commitment() *Point {
	return n.commitment
}

func (n *ExpiryHashedNode) GetProofItems(keylist, NodeResolverFn) (*ProofElements, []byte, [][]byte, error) {
	return nil, nil, nil, nil
}

func (n *ExpiryHashedNode) GetProofItemsWithEpoch(keys keylist, resolver NodeResolverFn, epoch StateEpoch) (*ProofElements, []byte, [][]byte, error) {
	return nil, nil, nil, nil
}

func (n *ExpiryHashedNode) GetEpoch() StateEpoch {
	return n.epoch
}

func (n *ExpiryHashedNode) UpdateEpoch(epoch StateEpoch) {
	n.epoch = epoch
}

func (n *ExpiryHashedNode) Revive([]byte, [][]byte, NodeResolverFn) error {
	return errExpiredNodeNotFound
}

// The format is: <nodeType><stem><commitment><epoch>
func (n *ExpiryHashedNode) Serialize() ([]byte, error) {

	var emptyEpoch [EpochSize]byte

	ret := make([]byte, StemSize+nodeTypeSize+EpochSize+banderwagon.UncompressedSize)
	ret[nodeTypeOffset] = hashedRLPType

	// copy the stem
	copy(ret[hashStemOffset:], n.stem)

	// copy the commitment
	cBytes := banderwagon.BatchToBytesUncompressed(n.commitment)
	copy(ret[hashCommitmentOffset:], cBytes[0][:])

	epoch := EpochToBytes(n.GetEpoch())
	if padding := emptyEpoch[:EpochSize-len(epoch)]; len(padding) != 0 {
		epoch = append(epoch, padding...)
	}
	copy(ret[hashEpochOffset:], epoch)

	return ret, nil
}

func (n *ExpiryHashedNode) Copy() VerkleNode {
	return &ExpiryHashedNode{
		stem:       n.stem,
		commitment: n.commitment,
		epoch:      n.epoch,
	}
}

func (n *ExpiryHashedNode) toDot(parent, path string) string {
	return fmt.Sprintf("hash%s [label=\"unresolved\"]\n%s -> hash%s\n", path, parent, path)
}

func (n *ExpiryHashedNode) setDepth(_ byte) {
	// do nothing
}

func (n *ExpiryHashedNode) Hash() *Fr {
	panic("can not hash a hashed node")
}

func (n *ExpiryHashedNode) EnableExpiry() bool {
	if n.epoch != 0 && n.commitment != nil {
		return true
	}
	return false
}
