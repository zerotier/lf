/*
 * Loser: very low overhead binary serialization
 * Copyright (C) 2018-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * Licensed under the terms of the MIT license (see LICENSE.txt).
 */

package loser

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"unsafe"
)

// These are 2-bit type IDs used in serialization. Numeric represents any integer and blob
// represents any higher level variable length type such as a byte slice, byte array, string, etc.
const (
	typeNil     = byte(0)
	typeNumeric = byte(1)
	typeBool    = byte(2)
	typeBlob    = byte(3)
)

// Loser is an instance of the Loser encoder/decoder.
// This must be initialized for a type you wish to serialize or deserialize. It is not
// safe to use concurrently in different threads.
type Loser struct {
	objectType  reflect.Type
	pig         reflect.Value
	fields      [256]int
	int8s       [256]*int8
	uint8s      [256]*uint8
	int16s      [256]*int16
	uint16s     [256]*uint16
	int32s      [256]*int32
	uint32s     [256]*uint32
	int64s      [256]*int64
	uint64s     [256]*uint64
	ints        [256]*int
	uints       [256]*uint
	bools       [256]*bool
	objects     [256]*Loser
	types       [256]byte
	intSubtypes [256]byte
	maxFieldID  byte
}

// Init initializes this encoder/decoder for a given struct type.
func (l *Loser) Init(structType reflect.Type) error {
	if structType.Kind() != reflect.Struct {
		return errors.New("only structs can be serialized or deserialized")
	}

	*l = Loser{
		objectType: structType,
		pig:        reflect.New(structType),
	}

	for fi := 0; fi < structType.NumField(); fi++ {
		f := structType.Field(fi)
		t := f.Tag.Get("loser")
		if len(t) > 0 {
			fid64, _ := strconv.ParseUint(t, 10, 64)
			if fid64 > 255 {
				return errors.New("invalid field ID (range: 0-255)")
			}
			fid := byte(fid64)

			l.fields[fid] = fi

			switch f.Type.Kind() {
			case reflect.Int8:
				l.int8s[fid] = (*int8)(unsafe.Pointer(l.pig.Field(fi).UnsafeAddr()))
				l.types[fid] = typeNumeric
				l.intSubtypes[fid] = 0
			case reflect.Uint8:
				l.uint8s[fid] = (*uint8)(unsafe.Pointer(l.pig.Field(fi).UnsafeAddr()))
				l.types[fid] = typeNumeric
				l.intSubtypes[fid] = 1
			case reflect.Int16:
				l.int16s[fid] = (*int16)(unsafe.Pointer(l.pig.Field(fi).UnsafeAddr()))
				l.types[fid] = typeNumeric
				l.intSubtypes[fid] = 2
			case reflect.Uint16:
				l.uint16s[fid] = (*uint16)(unsafe.Pointer(l.pig.Field(fi).UnsafeAddr()))
				l.types[fid] = typeNumeric
				l.intSubtypes[fid] = 3
			case reflect.Int32:
				l.int32s[fid] = (*int32)(unsafe.Pointer(l.pig.Field(fi).UnsafeAddr()))
				l.types[fid] = typeNumeric
				l.intSubtypes[fid] = 4
			case reflect.Uint32:
				l.uint32s[fid] = (*uint32)(unsafe.Pointer(l.pig.Field(fi).UnsafeAddr()))
				l.types[fid] = typeNumeric
				l.intSubtypes[fid] = 5
			case reflect.Int64:
				l.int64s[fid] = (*int64)(unsafe.Pointer(l.pig.Field(fi).UnsafeAddr()))
				l.types[fid] = typeNumeric
				l.intSubtypes[fid] = 6
			case reflect.Uint64:
				l.uint64s[fid] = (*uint64)(unsafe.Pointer(l.pig.Field(fi).UnsafeAddr()))
				l.types[fid] = typeNumeric
				l.intSubtypes[fid] = 7
			case reflect.Int:
				l.ints[fid] = (*int)(unsafe.Pointer(l.pig.Field(fi).UnsafeAddr()))
				l.types[fid] = typeNumeric
				l.intSubtypes[fid] = 8
			case reflect.Uint:
				l.uints[fid] = (*uint)(unsafe.Pointer(l.pig.Field(fi).UnsafeAddr()))
				l.types[fid] = typeNumeric
				l.intSubtypes[fid] = 9
			case reflect.Array:
				switch f.Type.Elem().Kind() {
				case reflect.Int8, reflect.Uint8, reflect.Int16, reflect.Uint16, reflect.Int32, reflect.Uint32, reflect.Int64, reflect.Uint64, reflect.Int, reflect.Uint, reflect.Bool:
					l.types[fid] = typeBlob
				default:
					return errors.New("unsupported field data type: " + f.Type.String())
				}
			case reflect.Slice:
				switch f.Type.Elem().Kind() {
				case reflect.Int8, reflect.Uint8, reflect.Int16, reflect.Uint16, reflect.Int32, reflect.Uint32, reflect.Int64, reflect.Uint64, reflect.Int, reflect.Uint, reflect.Bool:
					l.types[fid] = typeBlob
				default:
					return errors.New("unsupported field data type: " + f.Type.String())
				}
			case reflect.Bool:
				l.bools[fid] = (*bool)(unsafe.Pointer(l.pig.Field(fi).UnsafeAddr()))
				l.types[fid] = typeBool
			case reflect.String:
				l.types[fid] = typeBlob
			case reflect.Struct:
				l.objects[fid] = new(Loser)
				err := l.objects[fid].Init(f.Type)
				if err != nil {
					return err
				}
				l.types[fid] = typeBlob
			default:
				return errors.New("unsupported field data type: " + f.Type.String())
			}

			if fid > l.maxFieldID {
				l.maxFieldID = fid
			}
		}
	}

	return nil
}

// Marshal serializes obj to a byte array.
func (l *Loser) Marshal(obj interface{}) (out []byte, err error) {
	defer func() {
		e := recover()
		if e != nil {
			err = fmt.Errorf("trapped panic: %v", e)
		}
	}()

	if obj == nil {
		obj = reflect.New(l.objectType)
	}

	buf := bytes.NewBuffer(nil)
	l.pig.Set(reflect.ValueOf(obj)) // copy obj data into pig and thus into targets of typed pointers

	// Write field types as packed array of 2-bit serialization type IDs.
	buf.WriteByte(l.maxFieldID)
	var boolCount uint
	var bools [32]byte
	var fieldTypeBuf byte // holds up to 4 2-bit field types
	for fid := byte(0); fid < l.maxFieldID; fid++ {
		if l.types[fid] == typeBool {
			bools[boolCount>>3] |= 1 << (boolCount & 7)
			boolCount++
		}
		fieldTypeBuf <<= 2
		fieldTypeBuf |= l.types[fid]
		if (fid&3) == 0 && fid > 0 {
			buf.WriteByte(fieldTypeBuf)
			fieldTypeBuf = 0
		}
	}

	// Write booleans first as packed bits.
	if boolCount > 0 {
		buf.Write(bools[0 : boolCount+1])
	}

	// Write other fields...
	var tmp [10]byte
	var n int
	for fid := byte(0); fid < l.maxFieldID; fid++ {
		if l.types[fid] == typeNumeric {
			switch l.intSubtypes[fid] {
			case 0:
				n = binary.PutVarint(tmp[:], int64(*l.int8s[fid]))
			case 1:
				n = binary.PutUvarint(tmp[:], uint64(*l.uint8s[fid]))
			case 2:
				n = binary.PutVarint(tmp[:], int64(*l.int16s[fid]))
			case 3:
				n = binary.PutUvarint(tmp[:], uint64(*l.uint16s[fid]))
			case 4:
				n = binary.PutVarint(tmp[:], int64(*l.int32s[fid]))
			case 5:
				n = binary.PutUvarint(tmp[:], uint64(*l.uint32s[fid]))
			case 6:
				n = binary.PutVarint(tmp[:], int64(*l.int64s[fid]))
			case 7:
				n = binary.PutUvarint(tmp[:], uint64(*l.uint64s[fid]))
			case 8:
				n = binary.PutVarint(tmp[:], int64(*l.ints[fid]))
			case 9:
				n = binary.PutUvarint(tmp[:], uint64(*l.uints[fid]))
			}
			buf.Write(tmp[0:n])
		} else if l.types[fid] == typeBlob {
			if l.objects[fid] != nil {
				var blob []byte
				blob, err = l.objects[fid].Marshal(l.pig.Field(l.fields[fid]).Interface())
				if err != nil {
					return
				}
				n = binary.PutUvarint(tmp[:], uint64(len(blob)))
				buf.Write(tmp[0:n])
				buf.Write(blob)
			} else {
				binary.Write(buf, binary.BigEndian, l.pig.Field(l.fields[fid]))
			}
		}
	}

	out = buf.Bytes()
	return
}
