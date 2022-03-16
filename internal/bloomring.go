package internal

import (
	"bytes"
	"encoding/gob"
	"github.com/riobard/go-bloom"
	"hash/fnv"
	"log"
	"os"
	"sync"
)

// simply use Double FNV here as our Bloom Filter hash
func doubleFNV(b []byte) (uint64, uint64) {
	hx := fnv.New64()
	_, _ = hx.Write(b)
	x := hx.Sum64()
	hy := fnv.New64a()
	_, _ = hy.Write(b)
	y := hy.Sum64()
	return x, y
}

type BloomRing struct {
	slotCapacity int
	slotPosition int
	slotCount    int
	entryCounter int
	slots        []bloom.Filter
	mutex        sync.RWMutex
}

func NewBloomRing(slot int, capacity int, falsePositiveRate float64) *BloomRing {
	// Calculate entries for each slot
	r := &BloomRing{
		slotCapacity: capacity / slot,
		slotCount:    slot,
		slots:        make([]bloom.Filter, slot),
	}
	for i := 0; i < slot; i++ {
		r.slots[i] = bloom.New(r.slotCapacity, falsePositiveRate, doubleFNV)
	}
	return r
}

func LoadBloomRing(filePath string) (*BloomRing, error) {

	data, readError := os.ReadFile(filePath)
	if readError != nil {
		return nil, readError
	}

	buffer := bytes.NewBuffer(data)

	// Create a decoder and receive a value.
	decoder := gob.NewDecoder(buffer)
	var ring *BloomRing
	decodeError := decoder.Decode(ring)
	if decodeError != nil {
		log.Fatal("decode:", decodeError)
		return nil, decodeError
	}

	return ring, nil
}

func LoadOrCreateBloomRing(filePath string, slot int, capacity int, falsePositiveRate float64) *BloomRing {
	ring, loadError := LoadBloomRing(filePath)
	if loadError != nil {
		return NewBloomRing(slot, capacity, falsePositiveRate)
	} else {
		return ring
	}
}

func (r *BloomRing) Save(filePath string) error {

	var buffer bytes.Buffer

	enc := gob.NewEncoder(&buffer)
	encodeError := enc.Encode(r)
	if encodeError != nil {
		log.Fatal("encode:", encodeError)
		return encodeError
	}

	data := buffer.Bytes()
	writeError := os.WriteFile(filePath, data, 0666)
	if writeError != nil {
		return writeError
	}

	return nil
}

func (r *BloomRing) Add(b []byte) {
	if r == nil {
		return
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.add(b)
}

func (r *BloomRing) add(b []byte) {
	slot := r.slots[r.slotPosition]
	if r.entryCounter > r.slotCapacity {
		// Move to next slot and reset
		r.slotPosition = (r.slotPosition + 1) % r.slotCount
		slot = r.slots[r.slotPosition]
		slot.Reset()
		r.entryCounter = 0
	}
	r.entryCounter++
	slot.Add(b)
}

func (r *BloomRing) Test(b []byte) bool {
	if r == nil {
		return false
	}
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	test := r.test(b)
	return test
}

func (r *BloomRing) test(b []byte) bool {
	for _, s := range r.slots {
		if s.Test(b) {
			return true
		}
	}
	return false
}

func (r *BloomRing) Check(b []byte) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.Test(b) {
		return true
	}
	r.Add(b)
	return false
}
