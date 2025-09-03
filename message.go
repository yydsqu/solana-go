// Copyright 2021 github.com/gagliardetto
// This file has been modified by github.com/gagliardetto
//
// Copyright 2020 dfuse Platform Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package solana

import (
	"encoding/base64"
	"fmt"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/treeout"

	"github.com/gagliardetto/solana-go/text"
)

var ErrAlreadyResolved = fmt.Errorf("lookups already resolved")

var _ bin.EncoderDecoder = &Message{}

type MessageAddressTableLookupSlice []MessageAddressTableLookup

// NumLookups returns the number of accounts from all the lookups.
func (lookups MessageAddressTableLookupSlice) NumLookups() int {
	count := 0
	for _, lookup := range lookups {
		count += len(lookup.ReadonlyIndexes)
		count += len(lookup.WritableIndexes)
	}
	return count
}

func (lookups MessageAddressTableLookupSlice) NumWritableLookups() int {
	count := 0
	for _, lookup := range lookups {
		count += len(lookup.WritableIndexes)
	}
	return count
}

func (lookups MessageAddressTableLookupSlice) GetTableIDs() PublicKeySlice {
	if lookups == nil {
		return nil
	}
	ids := make(PublicKeySlice, 0)
	for _, lookup := range lookups {
		ids.UniqueAppend(lookup.AccountKey)
	}
	return ids
}

type MessageAddressTableLookup struct {
	AccountKey      PublicKey       `json:"accountKey"` // The account key of the address table.
	WritableIndexes Uint8SliceAsNum `json:"writableIndexes"`
	ReadonlyIndexes Uint8SliceAsNum `json:"readonlyIndexes"`
}

type Uint8SliceAsNum []uint8

func (slice Uint8SliceAsNum) MarshalJSON() ([]byte, error) {
	out := make([]uint16, len(slice))
	for i, idx := range slice {
		out[i] = uint16(idx)
	}
	return json.Marshal(out)
}

type MessageVersion int

const (
	MessageVersionLegacy MessageVersion = 0 // default
	MessageVersionV0     MessageVersion = 1 // v0
)

type Message struct {
	version MessageVersion
	// List of base-58 encoded public keys used by the transaction,
	// including by the instructions and for signatures.
	// The first `message.header.numRequiredSignatures` public keys must sign the transaction.
	AccountKeys PublicKeySlice `json:"accountKeys"` // static keys; static keys + dynamic keys if after resolution (i.e. call to `ResolveLookups()`)

	// Details the account types and signatures required by the transaction.
	Header MessageHeader `json:"header"`

	// A base-58 encoded hash of a recent block in the ledger used to
	// prevent transaction duplication and to give transactions lifetimes.
	RecentBlockhash Hash `json:"recentBlockhash"`

	// List of program instructions that will be executed in sequence
	// and committed in one atomic transaction if all succeed.
	Instructions []CompiledInstruction `json:"instructions"`

	// List of address table lookups used to load additional accounts for this transaction.
	AddressTableLookups MessageAddressTableLookupSlice `json:"addressTableLookups"`

	// The actual tables that contain the list of account pubkeys.
	// NOTE: you need to fetch these from the chain, and then call `SetAddressTables`
	// before you use this transaction -- otherwise, you will get a panic.
	addressTables map[PublicKey]PublicKeySlice

	resolved bool // if true, the lookups have been resolved, and the `AccountKeys` slice contains all the accounts (static + dynamic).
}

func (m *Message) SetAddressTables(tables map[PublicKey]PublicKeySlice) error {
	if m.addressTables != nil {
		return fmt.Errorf("address tables already set")
	}
	m.addressTables = tables
	return nil
}

func (m *Message) GetAddressTables() map[PublicKey]PublicKeySlice {
	return m.addressTables
}

func (m *Message) SetVersion(version MessageVersion) *Message {
	// check if the version is valid
	switch version {
	case MessageVersionV0, MessageVersionLegacy:
	default:
		panic(fmt.Errorf("invalid message version: %d", version))
	}
	m.version = version
	return m
}

// GetVersion returns the message version.
func (m *Message) GetVersion() MessageVersion {
	return m.version
}

// SetAddressTableLookups (re)sets the lookups used by this message.
func (m *Message) SetAddressTableLookups(lookups []MessageAddressTableLookup) *Message {
	m.AddressTableLookups = lookups
	m.version = MessageVersionV0
	return m
}

// AddAddressTableLookup adds a new lookup to the message.
func (m *Message) AddAddressTableLookup(lookup MessageAddressTableLookup) *Message {
	m.AddressTableLookups = append(m.AddressTableLookups, lookup)
	m.version = MessageVersionV0
	return m
}

// GetAddressTableLookups returns the lookups used by this message.
func (m *Message) GetAddressTableLookups() MessageAddressTableLookupSlice {
	return m.AddressTableLookups
}

func (m *Message) NumLookups() int {
	if m.AddressTableLookups == nil {
		return 0
	}
	return m.AddressTableLookups.NumLookups()
}

func (m *Message) NumWritableLookups() int {
	if m.AddressTableLookups == nil {
		return 0
	}
	return m.AddressTableLookups.NumWritableLookups()
}

func (m *Message) MarshalJSON() ([]byte, error) {
	if m.version == MessageVersionLegacy {
		out := struct {
			AccountKeys     []string              `json:"accountKeys"`
			Header          MessageHeader         `json:"header"`
			RecentBlockhash string                `json:"recentBlockhash"`
			Instructions    []CompiledInstruction `json:"instructions"`
		}{
			AccountKeys:     make([]string, len(m.AccountKeys)),
			Header:          m.Header,
			RecentBlockhash: m.RecentBlockhash.String(),
			Instructions:    m.Instructions,
		}
		for i, key := range m.AccountKeys {
			out.AccountKeys[i] = key.String()
		}
		return json.Marshal(out)
	}
	// Versioned message:
	out := struct {
		AccountKeys         []string                    `json:"accountKeys"`
		Header              MessageHeader               `json:"header"`
		RecentBlockhash     string                      `json:"recentBlockhash"`
		Instructions        []CompiledInstruction       `json:"instructions"`
		AddressTableLookups []MessageAddressTableLookup `json:"addressTableLookups"`
	}{
		AccountKeys:         make([]string, len(m.AccountKeys)),
		Header:              m.Header,
		RecentBlockhash:     m.RecentBlockhash.String(),
		Instructions:        m.Instructions,
		AddressTableLookups: m.AddressTableLookups,
	}
	for i, key := range m.AccountKeys {
		out.AccountKeys[i] = key.String()
	}
	if out.AddressTableLookups == nil {
		out.AddressTableLookups = make([]MessageAddressTableLookup, 0)
	}
	return json.Marshal(out)
}

func (m *Message) EncodeToTree(txTree treeout.Branches) {
	switch m.version {
	case MessageVersionV0:
		txTree.Child("Version: v0")
	case MessageVersionLegacy:
		txTree.Child("Version: legacy")
	default:
		txTree.Child(text.Sf("Version (unknown): %v", m.version))
	}
	txTree.Child(text.Sf("RecentBlockhash: %s", m.RecentBlockhash))

	txTree.Child(fmt.Sprintf("AccountKeys[len=%v]", m.numStaticAccounts()+m.AddressTableLookups.NumLookups())).ParentFunc(func(accountKeysBranch treeout.Branches) {
		accountKeys, err := m.AccountMetaList()
		if err != nil {
			accountKeysBranch.Child(text.RedBG(fmt.Sprintf("AccountMetaList: %s", err)))
		} else {
			for keyIndex, key := range accountKeys {
				isFromTable := m.IsVersioned() && keyIndex >= m.numStaticAccounts()
				if isFromTable {
					accountKeysBranch.Child(text.Sf("%s (from Address Table Lookup)", text.ColorizeBG(key.PublicKey.String())))
				} else {
					accountKeysBranch.Child(text.ColorizeBG(key.PublicKey.String()))
				}
			}
		}
	})

	if m.IsVersioned() {
		txTree.Child(fmt.Sprintf("AddressTableLookups[len=%v]", len(m.AddressTableLookups))).ParentFunc(func(lookupsBranch treeout.Branches) {
			for _, lookup := range m.AddressTableLookups {
				lookupsBranch.Child(text.Sf("%s", text.ColorizeBG(lookup.AccountKey.String()))).ParentFunc(func(lookupBranch treeout.Branches) {
					lookupBranch.Child(text.Sf("WritableIndexes: %v", lookup.WritableIndexes))
					lookupBranch.Child(text.Sf("ReadonlyIndexes: %v", lookup.ReadonlyIndexes))
				})
			}
		})
	}

	txTree.Child("Header").ParentFunc(func(message treeout.Branches) {
		m.Header.EncodeToTree(message)
	})
}

func (m *Message) MarshalBinary() ([]byte, error) {
	switch m.version {
	case MessageVersionV0:
		return m.MarshalV0()
	case MessageVersionLegacy:
		return m.MarshalLegacy()
	default:
		return nil, fmt.Errorf("invalid message version: %d", m.version)
	}
}

func (m *Message) MarshalLegacy() ([]byte, error) {
	buf := []byte{
		m.Header.NumRequiredSignatures,
		m.Header.NumReadonlySignedAccounts,
		m.Header.NumReadonlyUnsignedAccounts,
	}

	bin.EncodeCompactU16Length(&buf, len(m.AccountKeys))
	for _, key := range m.AccountKeys {
		buf = append(buf, key[:]...)
	}

	buf = append(buf, m.RecentBlockhash[:]...)

	bin.EncodeCompactU16Length(&buf, len(m.Instructions))
	for _, instruction := range m.Instructions {
		buf = append(buf, byte(instruction.ProgramIDIndex))
		bin.EncodeCompactU16Length(&buf, len(instruction.Accounts))
		for _, accountIdx := range instruction.Accounts {
			buf = append(buf, byte(accountIdx))
		}

		bin.EncodeCompactU16Length(&buf, len(instruction.Data))
		buf = append(buf, instruction.Data...)
	}
	return buf, nil
}

func (m *Message) MarshalV0() ([]byte, error) {
	buf := []byte{
		m.Header.NumRequiredSignatures,
		m.Header.NumReadonlySignedAccounts,
		m.Header.NumReadonlyUnsignedAccounts,
	}
	{
		// Encode only the keys that are not in the address table lookups.
		staticAccountKeys := m.getStaticKeys()
		bin.EncodeCompactU16Length(&buf, len(staticAccountKeys))
		for _, key := range staticAccountKeys {
			buf = append(buf, key[:]...)
		}

		buf = append(buf, m.RecentBlockhash[:]...)

		bin.EncodeCompactU16Length(&buf, len(m.Instructions))
		for _, instruction := range m.Instructions {
			buf = append(buf, byte(instruction.ProgramIDIndex))
			bin.EncodeCompactU16Length(&buf, len(instruction.Accounts))
			for _, accountIdx := range instruction.Accounts {
				buf = append(buf, byte(accountIdx))
			}

			bin.EncodeCompactU16Length(&buf, len(instruction.Data))
			buf = append(buf, instruction.Data...)
		}
	}
	versionNum := byte(m.version)
	if versionNum > 127 {
		return nil, fmt.Errorf("invalid message version: %d", m.version)
	}
	buf = append([]byte{versionNum + 127}, buf...)

	if m.AddressTableLookups != nil && len(m.AddressTableLookups) > 0 {
		buf = append(buf, byte(len(m.AddressTableLookups)))
		for _, lookup := range m.AddressTableLookups {
			buf = append(buf, lookup.AccountKey[:]...)
			bin.EncodeCompactU16Length(&buf, len(lookup.WritableIndexes))
			buf = append(buf, lookup.WritableIndexes...)
			bin.EncodeCompactU16Length(&buf, len(lookup.ReadonlyIndexes))
			buf = append(buf, lookup.ReadonlyIndexes...)
		}
	} else {
		buf = append(buf, 0)
	}
	return buf, nil
}

func (m *Message) MarshalWithEncoder(encoder *bin.Encoder) error {
	out, err := m.MarshalBinary()
	if err != nil {
		return err
	}
	return encoder.WriteBytes(out, false)
}

func (m *Message) ToBase64() string {
	out, _ := m.MarshalBinary()
	return base64.StdEncoding.EncodeToString(out)
}

func (m *Message) UnmarshalWithDecoder(decoder *bin.Decoder) (err error) {
	// peek first byte to determine if this is a legacy or v0 message
	versionNum, err := decoder.Peek(1)
	if err != nil {
		return err
	}
	// TODO: is this the right way to determine if this is a legacy or v0 message?
	if versionNum[0] < 127 {
		m.version = MessageVersionLegacy
	} else {
		m.version = MessageVersionV0
	}
	switch m.version {
	case MessageVersionV0:
		return m.UnmarshalV0(decoder)
	case MessageVersionLegacy:
		return m.UnmarshalLegacy(decoder)
	default:
		return fmt.Errorf("invalid message version: %d", m.version)
	}
}

func (m *Message) UnmarshalBase64(b64 string) error {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	return m.UnmarshalWithDecoder(bin.NewBinDecoder(b))
}

// GetAddressTableLookupAccounts associates the lookups with the accounts
// in the actual address tables, and returns the accounts.
// NOTE: you need to call `SetAddressTables` before calling this method,
// so that the lookups can be associated with the accounts in the address tables.
func (m *Message) GetAddressTableLookupAccounts() (PublicKeySlice, error) {
	err := m.checkPreconditions()
	if err != nil {
		return nil, err
	}
	var writable PublicKeySlice
	var readonly PublicKeySlice

	for _, lookup := range m.AddressTableLookups {
		table, ok := m.addressTables[lookup.AccountKey]
		if !ok {
			return writable, fmt.Errorf("address table lookup not found for account: %s", lookup.AccountKey)
		}
		for _, idx := range lookup.WritableIndexes {
			if int(idx) >= len(table) {
				return writable, fmt.Errorf("address table lookup index out of range: %d", idx)
			}
			writable = append(writable, table[idx])
		}
		for _, idx := range lookup.ReadonlyIndexes {
			if int(idx) >= len(table) {
				return writable, fmt.Errorf("address table lookup index out of range: %d", idx)
			}
			readonly = append(readonly, table[idx])
		}
	}

	return append(writable, readonly...), nil
}

// ResolveLookups resolves the address table lookups,
// and appends the resolved accounts to the `message.AccountKeys` field.
// NOTE: you need to call `SetAddressTables` before calling this method.
func (m *Message) ResolveLookups() (err error) {
	if m.resolved {
		return nil
	}
	// add accounts from the address table lookups
	atlAccounts, err := m.GetAddressTableLookupAccounts()
	if err != nil {
		return err
	}
	m.AccountKeys = append(m.AccountKeys, atlAccounts...)
	m.resolved = true

	return nil
}

// ResolveLookupsWith resolves the address table lookups with the provided writable and readonly accounts,
// assuming that the order of the accounts is correct.
func (m *Message) ResolveLookupsWith(writable, readonly PublicKeySlice) (err error) {
	if m.resolved {
		return ErrAlreadyResolved
	}
	m.AccountKeys = append(m.AccountKeys, append(writable, readonly...)...)
	m.resolved = true
	return nil
}

func (m *Message) IsResolved() bool {
	return m.resolved
}

func (m *Message) GetAllKeys() (keys PublicKeySlice, err error) {
	if m.resolved {
		// If the message has been resolved, then the account keys have already
		// been appended to the `AccountKeys` field of the message.
		return m.AccountKeys, nil
	}
	// If not resolved, then we need to resolve the lookups first...
	atlAccounts, err := m.GetAddressTableLookupAccounts()
	if err != nil {
		return keys, err
	}
	// ...and return the account keys with the lookups appended:
	return append(m.AccountKeys, atlAccounts...), nil
}

func (m *Message) getStaticKeys() (keys PublicKeySlice) {
	if m.resolved {
		// If the message has been resolved, then the account keys have already
		// been appended to the `AccountKeys` field of the message.
		return m.AccountKeys[:m.numStaticAccounts()]
	}
	return m.AccountKeys
}

func (m *Message) UnmarshalV0(decoder *bin.Decoder) (err error) {
	version, err := decoder.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read message version: %w", err)
	}

	m.version = MessageVersion(version - 127)

	// The middle of the message is the same as the legacy message:
	err = m.UnmarshalLegacy(decoder)
	if err != nil {
		return err
	}

	// Read address table lookups length:
	addressTableLookupsLen, err := decoder.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read address table lookups length: %w", err)
	}
	if addressTableLookupsLen > 0 {
		m.AddressTableLookups = make([]MessageAddressTableLookup, addressTableLookupsLen)
		for i := 0; i < int(addressTableLookupsLen); i++ {
			// read account pubkey
			_, err = decoder.Read(m.AddressTableLookups[i].AccountKey[:])
			if err != nil {
				return fmt.Errorf("failed to read account pubkey: %w", err)
			}

			// read writable indexes
			writableIndexesLen, err := decoder.ReadCompactU16()
			if err != nil {
				return fmt.Errorf("failed to read writable indexes length: %w", err)
			}
			if writableIndexesLen > decoder.Remaining() {
				return fmt.Errorf("writable indexes length is too large: %d", writableIndexesLen)
			}
			m.AddressTableLookups[i].WritableIndexes = make([]byte, writableIndexesLen)
			_, err = decoder.Read(m.AddressTableLookups[i].WritableIndexes)
			if err != nil {
				return fmt.Errorf("failed to read writable indexes: %w", err)
			}

			// read readonly indexes
			readonlyIndexesLen, err := decoder.ReadCompactU16()
			if err != nil {
				return fmt.Errorf("failed to read readonly indexes length: %w", err)
			}
			if readonlyIndexesLen > decoder.Remaining() {
				return fmt.Errorf("readonly indexes length is too large: %d", readonlyIndexesLen)
			}
			m.AddressTableLookups[i].ReadonlyIndexes = make([]byte, readonlyIndexesLen)
			_, err = decoder.Read(m.AddressTableLookups[i].ReadonlyIndexes)
			if err != nil {
				return fmt.Errorf("failed to read readonly indexes: %w", err)
			}
		}
	}
	return nil
}

func (m *Message) UnmarshalLegacy(decoder *bin.Decoder) (err error) {
	{
		m.Header.NumRequiredSignatures, err = decoder.ReadUint8()
		if err != nil {
			return fmt.Errorf("unable to decode mx.Header.NumRequiredSignatures: %w", err)
		}
		m.Header.NumReadonlySignedAccounts, err = decoder.ReadUint8()
		if err != nil {
			return fmt.Errorf("unable to decode mx.Header.NumReadonlySignedAccounts: %w", err)
		}
		m.Header.NumReadonlyUnsignedAccounts, err = decoder.ReadUint8()
		if err != nil {
			return fmt.Errorf("unable to decode mx.Header.NumReadonlyUnsignedAccounts: %w", err)
		}
	}
	{
		numAccountKeys, err := decoder.ReadCompactU16()
		if err != nil {
			return fmt.Errorf("unable to decode numAccountKeys: %w", err)
		}
		if numAccountKeys > decoder.Remaining()/32 {
			return fmt.Errorf("numAccountKeys %d is too large for remaining bytes %d", numAccountKeys, decoder.Remaining())
		}
		m.AccountKeys = make(PublicKeySlice, numAccountKeys)
		for i := 0; i < numAccountKeys; i++ {
			_, err := decoder.Read(m.AccountKeys[i][:])
			if err != nil {
				return fmt.Errorf("unable to decode mx.AccountKeys[%d]: %w", i, err)
			}
		}
	}
	{
		_, err := decoder.Read(m.RecentBlockhash[:])
		if err != nil {
			return fmt.Errorf("unable to decode mx.RecentBlockhash: %w", err)
		}
	}
	{
		numInstructions, err := decoder.ReadCompactU16()
		if err != nil {
			return fmt.Errorf("unable to decode numInstructions: %w", err)
		}
		if numInstructions > decoder.Remaining() {
			return fmt.Errorf("numInstructions %d is greater than remaining bytes %d", numInstructions, decoder.Remaining())
		}
		m.Instructions = make([]CompiledInstruction, numInstructions)
		for instructionIndex := 0; instructionIndex < numInstructions; instructionIndex++ {
			programIDIndex, err := decoder.ReadUint8()
			if err != nil {
				return fmt.Errorf("unable to decode mx.Instructions[%d].ProgramIDIndex: %w", instructionIndex, err)
			}
			m.Instructions[instructionIndex].ProgramIDIndex = uint16(programIDIndex)

			{
				numAccounts, err := decoder.ReadCompactU16()
				if err != nil {
					return fmt.Errorf("unable to decode numAccounts for ix[%d]: %w", instructionIndex, err)
				}
				if numAccounts > decoder.Remaining() {
					return fmt.Errorf("ix[%v]: numAccounts %d is greater than remaining bytes %d", instructionIndex, numAccounts, decoder.Remaining())
				}
				m.Instructions[instructionIndex].Accounts = make([]byte, numAccounts)
				for i := 0; i < numAccounts; i++ {
					accountIndex, err := decoder.ReadUint8()
					if err != nil {
						return fmt.Errorf("unable to decode accountIndex for ix[%d].Accounts[%d]: %w", instructionIndex, i, err)
					}
					m.Instructions[instructionIndex].Accounts[i] = accountIndex
				}
			}
			{
				dataLen, err := decoder.ReadCompactU16()
				if err != nil {
					return fmt.Errorf("unable to decode dataLen for ix[%d]: %w", instructionIndex, err)
				}
				if dataLen > decoder.Remaining() {
					return fmt.Errorf("ix[%v]: dataLen %d is greater than remaining bytes %d", instructionIndex, dataLen, decoder.Remaining())
				}
				dataBytes, err := decoder.ReadBytes(dataLen)
				if err != nil {
					return fmt.Errorf("unable to decode dataBytes for ix[%d]: %w", instructionIndex, err)
				}
				m.Instructions[instructionIndex].Data = dataBytes
			}
		}
	}

	return nil
}

func (m *Message) checkPreconditions() error {
	// if this is versioned,
	// and there are > 0 lookups,
	// but the address table is empty,
	// then we can't build the account meta list:
	if m.IsVersioned() && m.AddressTableLookups.NumLookups() > 0 && (m.addressTables == nil || len(m.addressTables) == 0) {
		return fmt.Errorf("cannot build account meta list without address tables")
	}

	return nil
}

func (m *Message) AccountMetaList() (AccountMetaSlice, error) {
	err := m.checkPreconditions()
	if err != nil {
		return nil, err
	}
	accountKeys, err := m.GetAllKeys()
	if err != nil {
		return nil, err
	}
	out := make(AccountMetaSlice, len(accountKeys))

	for i, a := range accountKeys {
		isWritable, err := m.IsWritable(a)
		if err != nil {
			return nil, err
		}

		out[i] = &AccountMeta{
			PublicKey:  a,
			IsSigner:   m.IsSigner(a),
			IsWritable: isWritable,
		}
	}

	return out, nil
}

func (m *Message) IsVersioned() bool {
	return m.version != MessageVersionLegacy
}

func (m *Message) Signers() PublicKeySlice {
	// signers always in AccountKeys
	out := make(PublicKeySlice, 0, len(m.AccountKeys))
	for _, a := range m.AccountKeys {
		if m.IsSigner(a) {
			out = append(out, a)
		}
	}

	return out
}

func (m *Message) Writable() (out PublicKeySlice, err error) {
	err = m.checkPreconditions()
	if err != nil {
		return nil, err
	}
	accountKeys, err := m.GetAllKeys()
	if err != nil {
		return nil, err
	}

	for _, a := range accountKeys {
		isWritable, err := m.IsWritable(a)
		if err != nil {
			return nil, err
		}

		if isWritable {
			out = append(out, a)
		}
	}

	return out, nil
}

func (m *Message) ResolveProgramIDIndex(programIDIndex uint16) (PublicKey, error) {
	return m.Program(programIDIndex)
}

func (m *Message) Program(programIDIndex uint16) (PublicKey, error) {
	// programIDIndex always in AccountKeys
	if int(programIDIndex) < len(m.AccountKeys) {
		return m.AccountKeys[programIDIndex], nil
	}
	return PublicKey{}, fmt.Errorf("programID index not found %d", programIDIndex)
}

func (m *Message) Account(index uint16) (PublicKey, error) {
	if int(index) < len(m.AccountKeys) {
		return m.AccountKeys[index], nil
	}
	allKeys, err := m.GetAllKeys()
	if err != nil {
		return PublicKey{}, err
	}
	if int(index) < len(allKeys) {
		return allKeys[index], nil
	}
	return PublicKey{}, fmt.Errorf("account index not found %d", index)
}

func (m *Message) GetAccountIndex(account PublicKey) (uint16, error) {
	err := m.checkPreconditions()
	if err != nil {
		return 0, err
	}
	accountKeys, err := m.GetAllKeys()
	if err != nil {
		return 0, err
	}

	for idx, a := range accountKeys {
		if a.Equals(account) {
			return uint16(idx), nil
		}
	}

	return 0, fmt.Errorf("account not found: %s", account)
}

func (m *Message) HasAccount(account PublicKey) (bool, error) {
	err := m.checkPreconditions()
	if err != nil {
		return false, err
	}
	accountKeys, err := m.GetAllKeys()
	if err != nil {
		return false, err
	}

	for _, a := range accountKeys {
		if a.Equals(account) {
			return true, nil
		}
	}

	return false, nil
}

func (m *Message) IsSigner(account PublicKey) bool {
	// signers always in AccountKeys
	for idx, acc := range m.AccountKeys {
		if acc.Equals(account) {
			return idx < int(m.Header.NumRequiredSignatures)
		}
	}
	return false
}

func (m *Message) numStaticAccounts() int {
	if !m.resolved {
		return len(m.AccountKeys)
	}
	return len(m.AccountKeys) - m.NumLookups()
}

func (m *Message) isWritableInLookups(idx int) bool {
	if idx < m.numStaticAccounts() {
		return false
	}
	return idx-m.numStaticAccounts() < m.AddressTableLookups.NumWritableLookups()
}

func (m *Message) IsWritableStatic(account PublicKey) bool {
	// check only the static accounts (i.e. not the ones in the address table lookups); no check preconditions needed.
	accountKeys := m.getStaticKeys()
	index := 0
	found := false
	for idx, acc := range accountKeys {
		if acc.Equals(account) {
			found = true
			index = idx
		}
	}
	if !found {
		return false
	}
	h := m.Header
	if index >= int(h.NumRequiredSignatures) {
		// unsignedAccountIndex < numWritableUnsignedAccounts
		return index-int(h.NumRequiredSignatures) < (m.numStaticAccounts()-int(h.NumRequiredSignatures))-int(h.NumReadonlyUnsignedAccounts)
	}
	return index < int(h.NumRequiredSignatures-h.NumReadonlySignedAccounts)
}

func (m *Message) IsWritable(account PublicKey) (bool, error) {
	err := m.checkPreconditions()
	if err != nil {
		return false, err
	}
	accountKeys, err := m.GetAllKeys()
	if err != nil {
		return false, err
	}

	index := 0
	found := false
	for idx, acc := range accountKeys {
		if acc.Equals(account) {
			found = true
			index = idx
		}
	}
	if !found {
		return false, nil
	}
	h := m.Header

	if index >= m.numStaticAccounts() {
		return m.isWritableInLookups(index), nil
	} else if index >= int(h.NumRequiredSignatures) {
		// unsignedAccountIndex < numWritableUnsignedAccounts
		return index-int(h.NumRequiredSignatures) < (m.numStaticAccounts()-int(h.NumRequiredSignatures))-int(h.NumReadonlyUnsignedAccounts), nil
	}
	return index < int(h.NumRequiredSignatures-h.NumReadonlySignedAccounts), nil
}

func (m *Message) signerKeys() PublicKeySlice {
	return m.AccountKeys[0:m.Header.NumRequiredSignatures]
}

type MessageHeader struct {
	// The total number of signatures required to make the transaction valid.
	// The signatures must match the first `numRequiredSignatures` of `message.account_keys`.
	NumRequiredSignatures uint8 `json:"numRequiredSignatures"`

	// The last numReadonlySignedAccounts of the signed keys are read-only accounts.
	// Programs may process multiple transactions that load read-only accounts within
	// a single PoH entry, but are not permitted to credit or debit lamports or modify
	// account data.
	// Transactions targeting the same read-write account are evaluated sequentially.
	NumReadonlySignedAccounts uint8 `json:"numReadonlySignedAccounts"`

	// The last `numReadonlyUnsignedAccounts` of the unsigned keys are read-only accounts.
	NumReadonlyUnsignedAccounts uint8 `json:"numReadonlyUnsignedAccounts"`
}

func (header *MessageHeader) EncodeToTree(mxBranch treeout.Branches) {
	mxBranch.Child(text.Sf("NumRequiredSignatures: %v", header.NumRequiredSignatures))
	mxBranch.Child(text.Sf("NumReadonlySignedAccounts: %v", header.NumReadonlySignedAccounts))
	mxBranch.Child(text.Sf("NumReadonlyUnsignedAccounts: %v", header.NumReadonlyUnsignedAccounts))
}
