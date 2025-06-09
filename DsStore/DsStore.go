package DsStore

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"unicode/utf16"
	"unsafe"
)

const (
	headerMinLength = 32
	magicNumber1    = 1
	magicNumber2    = 0x42756431
)

const (
	TypeBool = "bool"
	TypeLong = "long"
	TypeShor = "shor"
	TypeComp = "comp"
	TypeDutc = "dutc"
	TypeBlob = "blob"
	TypeUstr = "ustr"
)

type Block struct {
	Allocator *Allocator
	Offset    uint32
	Size      uint32
	Data      []byte
	Pos       uint32
}

type Allocator struct {
	Data     []byte
	Pos      uint32
	Root     *Block
	Offsets  []uint32
	Toc      map[string]uint32
	FreeList map[uint32][]uint32
}

func NewAllocator(data []byte) (*Allocator, error) {
	a := &Allocator{
		Data:     data,
		Toc:      make(map[string]uint32),
		FreeList: make(map[uint32][]uint32),
	}

	if err := a.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize allocator: %w", err)
	}

	return a, nil
}

func (a *Allocator) initialize() error {
	offset, size, err := a.readHeader()
	if err != nil {
		return err
	}

	a.Root, err = NewBlock(a, offset, size)
	if err != nil {
		return err
	}

	for _, operation := range []func() error{
		a.readOffsets,
		a.readToc,
		a.readFreeList,
	} {
		if err := operation(); err != nil {
			return err
		}
	}

	return nil
}

func NewBlock(a *Allocator, pos, size uint32) (*Block, error) {
	if len(a.Data) < int(pos+0x4+size) {
		return nil, fmt.Errorf("insufficient data for block: pos=%d, size=%d, data length=%d", pos, size, len(a.Data))
	}
	block := &Block{
		Size:      size,
		Allocator: a,
		Data:      a.Data[pos+0x4 : pos+0x4+size],
	}
	return block, nil
}

func (b *Block) readUint32() (uint32, error) {
	if b.Size-b.Pos < 4 {
		return 0, fmt.Errorf("Not enough bytes to read")
	}

	var value uint32
	if err := binary.Read(bytes.NewReader(b.Data[b.Pos:]), binary.BigEndian, &value); err != nil {
		return 0, err
	}

	b.Pos += 4
	return value, nil
}

func (b *Block) readByte() (byte, error) {
	if b.Size-b.Pos < 1 {
		return 0, fmt.Errorf("Not enough bytes to read")
	}

	value := b.Data[b.Pos]
	b.Pos++
	return value, nil
}

func (b *Block) readBuf(length int) ([]byte, error) {
	if int(b.Size)-int(b.Pos) < length {
		return nil, fmt.Errorf("Not enough bytes to read")
	}

	buf := make([]byte, length)
	copy(buf, b.Data[b.Pos:b.Pos+uint32(length)])
	b.Pos += uint32(length)
	return buf, nil
}

func (b *Block) readFileName() (string, error) {
	length, err := b.readUint32()
	if err != nil {
		return "", err
	}

	buf, err := b.readBuf(int(2 * length))
	if err != nil {
		return "", err
	}

	b.skip(4)

	stype, err := b.readBuf(4)
	if err != nil {
		return "", err
	}

	bytesToSkip, err := b.calculateBytesToSkip(string(stype))
	if err != nil {
		return "", err
	}

	b.skip(uint32(bytesToSkip))
	return utf16be2utf8(buf), nil
}

func (b *Block) calculateBytesToSkip(t string) (int, error) {
	switch t {
	case TypeBool:
		return 1, nil
	case TypeLong, TypeShor:
		return 4, nil
	case TypeComp, TypeDutc:
		return 8, nil
	case TypeBlob, TypeUstr:
		length, err := b.readUint32()
		if err != nil {
			return 0, err
		}
		if t == TypeUstr {
			return int(2 * length), nil
		}
		return int(length), nil
	default:
		return 0, fmt.Errorf("unknown type format")
	}
}

func (b *Block) skip(i uint32) {
	b.Pos += i
}

func utf16be2utf8(utf16be []byte) string {
	if len(utf16be)%2 != 0 {
		return ""
	}

	header := *(*reflect.SliceHeader)(unsafe.Pointer(&utf16be))
	header.Len /= 2
	shorts := *(*[]uint16)(unsafe.Pointer(&header))

	for i := 0; i < len(shorts); i++ {
		shorts[i] = (uint16(utf16be[i*2]) << 8) | uint16(utf16be[i*2+1])
	}

	return string(utf16.Decode(shorts))
}

func (a *Allocator) GetBlock(bid uint32) (*Block, error) {
	if int(bid) >= len(a.Offsets) {
		return nil, fmt.Errorf("invalid block ID in offset table")
	}

	addr := a.Offsets[bid]

	const (
		offsetMask = ^uint32(0x1f)
		sizeMask   = 0x1f
	)

	offset := uint32(addr) & offsetMask
	size := uint32(1) << (addr & sizeMask)

	return NewBlock(a, offset, size)
}

func (a *Allocator) TraverseFromRootNode() ([]string, error) {
	dsdbID, exists := a.Toc["DSDB"]
	if !exists {
		return nil, fmt.Errorf("DSDB entry not found in TOC")
	}

	rootBlock, err := a.GetBlock(dsdbID)
	if err != nil {
		return nil, fmt.Errorf("failed to get root block: %w", err)
	}

	rootNode, err := rootBlock.readUint32()
	if err != nil {
		return nil, fmt.Errorf("failed to read root node: %w", err)
	}

	rootBlock.skip(16) // 4 * 4 bytes

	return a.Traverse(rootNode)
}

func (a *Allocator) Traverse(bid uint32) ([]string, error) {
	node, err := a.GetBlock(bid)
	if err != nil {
		return nil, fmt.Errorf("failed to get node block: %w", err)
	}

	header, err := a.readNodeHeader(node)
	if err != nil {
		return nil, err
	}

	filenames := make([]string, 0, header.count)

	if header.nextPtr > 0 {
		// Recursive traversal
		if err := a.traverseWithNext(node, header, &filenames); err != nil {
			return nil, err
		}
	} else {
		// Leaf node traversal
		if err := a.traverseLeafNode(node, header.count, &filenames); err != nil {
			return nil, err
		}
	}

	return filenames, nil
}

type nodeHeader struct {
	nextPtr uint32
	count   int
}

func (a *Allocator) readNodeHeader(node *Block) (nodeHeader, error) {
	nextPtr, err := node.readUint32()
	if err != nil {
		return nodeHeader{}, fmt.Errorf("failed to read next pointer: %w", err)
	}

	count, err := node.readUint32()
	if err != nil {
		return nodeHeader{}, fmt.Errorf("failed to read count: %w", err)
	}

	return nodeHeader{
		nextPtr: nextPtr,
		count:   int(count),
	}, nil
}

func (a *Allocator) traverseWithNext(node *Block, header nodeHeader, filenames *[]string) error {
	for i := 0; i < header.count; i++ {
		next, err := node.readUint32()
		if err != nil {
			return fmt.Errorf("failed to read next node: %w", err)
		}

		childFiles, err := a.Traverse(next)
		if err != nil {
			return err
		}
		*filenames = append(*filenames, childFiles...)

		fname, err := node.readFileName()
		if err != nil {
			return fmt.Errorf("failed to read filename: %w", err)
		}
		*filenames = append(*filenames, fname)
	}

	nextFiles, err := a.Traverse(header.nextPtr)
	if err != nil {
		return err
	}
	*filenames = append(*filenames, nextFiles...)

	return nil
}

func (a *Allocator) traverseLeafNode(node *Block, count int, filenames *[]string) error {
	for i := 0; i < count; i++ {
		fname, err := node.readFileName()
		if err != nil {
			return fmt.Errorf("failed to read filename in leaf node: %w", err)
		}
		*filenames = append(*filenames, fname)
	}
	return nil
}

func (a *Allocator) readFreeList() error {
	if a.Root == nil {
		return fmt.Errorf("root block not initialized")
	}

	a.FreeList = make(map[uint32][]uint32, headerMinLength)

	for i := 0; i < headerMinLength; i++ {
		blkcount, err := a.Root.readUint32()
		if err != nil {
			return fmt.Errorf("reading block count: %w", err)
		}

		if blkcount == 0 {
			continue
		}

		freeBlocks := make([]uint32, 0, blkcount)

		for k := uint32(0); k < blkcount; k++ {
			val, err := a.Root.readUint32()
			if err != nil {
				return fmt.Errorf("reading free block value: %w", err)
			}

			if val != 0 {
				freeBlocks = append(freeBlocks, val)
			}
		}

		if len(freeBlocks) > 0 {
			a.FreeList[uint32(i)] = freeBlocks
		}
	}
	return nil
}

func (a *Allocator) readToc() error {
	if a.Root == nil {
		return fmt.Errorf("root block not initialized")
	}

	toccount, err := a.Root.readUint32()
	if err != nil {
		return fmt.Errorf("reading TOC count: %w", err)
	}

	a.Toc = make(map[string]uint32, toccount)

	for i := toccount; i > 0; i-- {
		nameLen, err := a.Root.readByte()
		if err != nil {
			return fmt.Errorf("reading TOC entry name length: %w", err)
		}

		nameBytes, err := a.Root.readBuf(int(nameLen))
		if err != nil {
			return fmt.Errorf("reading TOC entry name: %w", err)
		}

		value, err := a.Root.readUint32()
		if err != nil {
			return fmt.Errorf("reading TOC entry value: %w", err)
		}

		a.Toc[string(nameBytes)] = value
	}
	return nil
}

func (a *Allocator) readOffsets() error {
	if a.Root == nil {
		return fmt.Errorf("root block not initialized")
	}

	count, err := a.Root.readUint32()
	if err != nil {
		return fmt.Errorf("reading offset count: %w", err)
	}

	a.Offsets = make([]uint32, 0, count)
	a.Root.skip(4)

	const blockSize = 256
	for offcount := int(count); offcount > 0; offcount -= blockSize {
		for i := 0; i < 256; i++ {
			val, err := a.Root.readUint32()
			if err != nil {
				return fmt.Errorf("reading offset value: %w", err)
			}
			if val == 0 {
				continue
			}
			a.Offsets = append(a.Offsets, val)
		}
	}
	return nil
}

func (a *Allocator) readHeader() (offset uint32, size uint32, err error) {
	if len(a.Data) < headerMinLength {
		return 0, 0, fmt.Errorf("header too short")
	}

	reader := bytes.NewReader(a.Data)

	var header struct {
		Magic1  uint32
		Magic2  uint32
		Offset1 uint32
		Size    uint32
		Offset2 uint32
	}

	if err := binary.Read(reader, binary.BigEndian, &header); err != nil {
		return 0, 0, fmt.Errorf("reading header: %w", err)
	}

	if header.Magic1 != magicNumber1 || header.Magic2 != magicNumber2 {
		return 0, 0, fmt.Errorf("invalid magic numbers")
	}

	if header.Offset1 != header.Offset2 {
		return 0, 0, fmt.Errorf("offset mismatch")
	}

	a.Pos += 20 // 5 *4 uint32

	return header.Offset1, header.Size, nil
}
