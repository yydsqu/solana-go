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
	"bytes"
	"encoding/base64"
	"fmt"
	"sort"

	"github.com/davecgh/go-spew/spew"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go/text"
	"github.com/gagliardetto/treeout"
	"github.com/mr-tron/base58"
)

const (
	MaxRawTxSize  = 1232
	SignatureSize = 64
)

var _ bin.EncoderDecoder = &Transaction{}

type Transaction struct {
	// A list of base-58 encoded signatures applied to the transaction.
	// The list is always of length `message.header.numRequiredSignatures` and not empty.
	// The signature at index `i` corresponds to the public key at index
	// `i` in `message.account_keys`. The first one is used as the transaction id.
	Signatures []Signature `json:"signatures"`

	// Defines the content of the transaction.
	Message Message `json:"message"`
}

func (tx *Transaction) UnmarshalBase64(b64 string) error {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	return tx.UnmarshalWithDecoder(bin.NewBinDecoder(b))
}

func (tx *Transaction) HasAccount(account PublicKey) (bool, error) {
	return tx.Message.HasAccount(account)
}

func (tx *Transaction) IsSigner(account PublicKey) bool {
	return tx.Message.IsSigner(account)
}

func (tx *Transaction) IsWritable(account PublicKey) (bool, error) {
	return tx.Message.IsWritable(account)
}

func (tx *Transaction) AccountMetaList() ([]*AccountMeta, error) {
	return tx.Message.AccountMetaList()
}

func (tx *Transaction) ResolveProgramIDIndex(programIDIndex uint16) (PublicKey, error) {
	return tx.Message.ResolveProgramIDIndex(programIDIndex)
}

func (tx *Transaction) GetAccountIndex(account PublicKey) (uint16, error) {
	return tx.Message.GetAccountIndex(account)
}

func (tx *Transaction) MarshalBinary() ([]byte, error) {
	messageContent, err := tx.Message.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to encode tx.Message to binary: %w", err)
	}
	if len(tx.Signatures) == 0 {
		signerKeys := tx.Message.signerKeys()
		tx.Signatures = make([]Signature, len(signerKeys))
	}
	var signatureCount []byte
	bin.EncodeCompactU16Length(&signatureCount, len(tx.Signatures))
	output := make([]byte, 0, len(signatureCount)+len(signatureCount)*64+len(messageContent))
	output = append(output, signatureCount...)
	for _, sig := range tx.Signatures {
		output = append(output, sig[:]...)
	}
	output = append(output, messageContent...)

	return output, nil
}

func (tx *Transaction) MarshalWithEncoder(encoder *bin.Encoder) error {
	out, err := tx.MarshalBinary()
	if err != nil {
		return err
	}
	return encoder.WriteBytes(out, false)
}

func (tx *Transaction) UnmarshalWithDecoder(decoder *bin.Decoder) (err error) {
	{
		numSignatures, err := decoder.ReadCompactU16()
		if err != nil {
			return fmt.Errorf("unable to read numSignatures: %w", err)
		}
		if numSignatures < 0 {
			return fmt.Errorf("numSignatures is negative")
		}
		if numSignatures > decoder.Remaining()/64 {
			return fmt.Errorf("numSignatures %d is too large for remaining bytes %d", numSignatures, decoder.Remaining())
		}
		tx.Signatures = make([]Signature, numSignatures)
		for i := 0; i < numSignatures; i++ {
			if _, err = decoder.Read(tx.Signatures[i][:]); err != nil {
				return fmt.Errorf("unable to read tx.Signatures[%d]: %w", i, err)
			}
		}
	}
	{
		if err = tx.Message.UnmarshalWithDecoder(decoder); err != nil {
			return fmt.Errorf("unable to decode tx.Message: %w", err)
		}
	}
	return nil
}

func (tx *Transaction) PartialSign(getter privateKeyGetter) (out []Signature, err error) {
	messageContent, err := tx.Message.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("unable to encode message for signing: %w", err)
	}
	if len(messageContent) > 1294 {
		return nil, fmt.Errorf("message is too large for signing")
	}
	signerKeys := tx.Message.signerKeys()
	// Ensure that the transaction has the correct number of signatures initialized
	if len(tx.Signatures) == 0 {
		// Initialize the Signatures slice to the correct length if it's empty
		tx.Signatures = make([]Signature, len(signerKeys))
	} else if len(tx.Signatures) != len(signerKeys) {
		// Return an error if the current length of the Signatures slice doesn't match the expected number
		return nil, fmt.Errorf("invalid signatures length, expected %d, actual %d", len(signerKeys), len(tx.Signatures))
	}

	for i, key := range signerKeys {
		privateKey := getter(key)
		if privateKey == nil {
			continue
		}
		if privateKey.PublicKey() != key {
			return nil, fmt.Errorf("invalid public key for signing, expected %s, actual %s", key, privateKey.PublicKey())
		}
		if tx.Signatures[i], err = privateKey.Sign(messageContent); err != nil {
			return nil, fmt.Errorf("failed to signed with key %q: %w", key.String(), err)
		}
	}

	return tx.Signatures, nil
}

func (tx *Transaction) Sign(getter privateKeyGetter) (out []Signature, err error) {
	signerKeys := tx.Message.signerKeys()
	for _, key := range signerKeys {
		if getter(key) == nil {
			return nil, fmt.Errorf("signer key %q not found. Ensure all the signer keys are in the vault", key.String())
		}
	}
	return tx.PartialSign(getter)
}

func (tx *Transaction) EncodeTree(encoder *text.TreeEncoder) (int, error) {
	tx.EncodeToTree(encoder)
	return encoder.WriteString(encoder.Tree.String())
}

func (tx *Transaction) String() string {
	buf := new(bytes.Buffer)
	_, err := tx.EncodeTree(text.NewTreeEncoder(buf, ""))
	if err != nil {
		panic(err)
	}
	return buf.String()
}

func (tx *Transaction) ToBase64() (string, error) {
	out, err := tx.MarshalBinary()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(out), nil
}

func (tx *Transaction) MustToBase64() string {
	out, err := tx.ToBase64()
	if err != nil {
		panic(err)
	}
	return out
}

func (tx *Transaction) EncodeToTree(parent treeout.Branches) {
	parent.ParentFunc(func(txTree treeout.Branches) {
		txTree.Child(fmt.Sprintf("Signatures[len=%v]", len(tx.Signatures))).ParentFunc(func(signaturesBranch treeout.Branches) {
			for _, sig := range tx.Signatures {
				signaturesBranch.Child(sig.String())
			}
		})

		txTree.Child("Message").ParentFunc(func(messageBranch treeout.Branches) {
			tx.Message.EncodeToTree(messageBranch)
		})
	})

	parent.Child(fmt.Sprintf("Instructions[len=%v]", len(tx.Message.Instructions))).ParentFunc(func(message treeout.Branches) {
		for _, inst := range tx.Message.Instructions {

			progKey, err := tx.ResolveProgramIDIndex(inst.ProgramIDIndex)
			if err == nil {
				accounts, err := inst.ResolveInstructionAccounts(&tx.Message)
				if err != nil {
					message.Child(fmt.Sprintf(text.RedBG("cannot ResolveInstructionAccounts: %s"), err))
					return
				}
				decodedInstruction, err := DecodeInstruction(progKey, accounts, inst.Data)
				if err == nil {
					if enToTree, ok := decodedInstruction.(text.EncodableToTree); ok {
						enToTree.EncodeToTree(message)
					} else {
						message.Child(spew.Sdump(decodedInstruction))
					}
				} else {
					// TODO: log error?
					message.Child(fmt.Sprintf(text.RedBG("cannot decode instruction for %s program: %s"), progKey, err)).
						Child(text.IndigoBG("Program") + ": " + text.Bold("<unknown>") + " " + text.ColorizeBG(progKey.String())).
						//
						ParentFunc(func(programBranch treeout.Branches) {
							programBranch.Child(text.Purple(text.Bold("Instruction")) + ": " + text.Bold("<unknown>")).
								//
								ParentFunc(func(instructionBranch treeout.Branches) {
									// Data of the instruction call:
									instructionBranch.Child(text.Sf("data[len=%v bytes]", len(inst.Data))).ParentFunc(func(paramsBranch treeout.Branches) {
										paramsBranch.Child(bin.FormatByteSlice(inst.Data))
									})

									// Accounts of the instruction call:
									instructionBranch.Child(text.Sf("accounts[len=%v]", len(accounts))).ParentFunc(func(accountsBranch treeout.Branches) {
										for i := range accounts {
											accountsBranch.Child(formatMeta(text.Sf("accounts[%v]", i), accounts[i]))
										}
									})
								})
						})
				}
			} else {
				message.Child(fmt.Sprintf(text.RedBG("cannot ResolveProgramIDIndex: %s"), err))
			}
		}
	})
}

func (tx *Transaction) VerifySignatures() error {
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		return err
	}

	signers := tx.Message.Signers()

	if len(signers) != len(tx.Signatures) {
		return fmt.Errorf(
			"got %v signers, but %v signatures",
			len(signers),
			len(tx.Signatures),
		)
	}

	for i, sig := range tx.Signatures {
		if !sig.Verify(signers[i], msg) {
			return fmt.Errorf("invalid signature by %s", signers[i].String())
		}
	}

	return nil
}

func (tx *Transaction) GetProgramIDs() (PublicKeySlice, error) {
	programIDs := make(PublicKeySlice, 0)
	for ixi, inst := range tx.Message.Instructions {
		progKey, err := tx.ResolveProgramIDIndex(inst.ProgramIDIndex)
		if err == nil {
			programIDs = append(programIDs, progKey)
		} else {
			return nil, fmt.Errorf("cannot resolve program ID for instruction %d: %w", ixi, err)
		}
	}
	return programIDs, nil
}

func (tx *Transaction) NumWriteableAccounts() int {
	return countWriteableAccounts(tx)
}

func (tx *Transaction) NumSigners() int {
	return countSigners(tx)
}

func (tx *Transaction) IsVote() bool {
	for _, inst := range tx.Message.Instructions {
		progKey, err := tx.ResolveProgramIDIndex(inst.ProgramIDIndex)
		if err == nil {
			if progKey.Equals(VoteProgramID) {
				return true
			}
		}
	}
	return false
}

func (tx *Transaction) NumReadonlyAccounts() int {
	return countReadonlyAccounts(tx)
}

func (tx *Transaction) SignMessage(getter privateKeyGetter) ([]byte, error) {
	messageContent, err := tx.Message.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("unable to encode message for signing: %w", err)
	}

	signerKeys := tx.Message.signerKeys()
	if len(tx.Signatures) == 0 {
		tx.Signatures = make([]Signature, len(signerKeys))
	} else if len(tx.Signatures) != len(signerKeys) {
		return nil, fmt.Errorf("invalid signatures length, expected %d, actual %d", len(signerKeys), len(tx.Signatures))
	}

	var signatureCount []byte
	bin.EncodeCompactU16Length(&signatureCount, len(tx.Signatures))
	output := make([]byte, 0, len(signatureCount)+len(signatureCount)*64+len(messageContent))
	output = append(output, signatureCount...)

	for i, key := range signerKeys {
		privateKey := getter(key)
		if privateKey == nil {
			output = append(output, tx.Signatures[i][:]...)
			continue
		}
		if privateKey.PublicKey() != key {
			return nil, fmt.Errorf("invalid public key for signing, expected %s, actual %s", key, privateKey.PublicKey())
		}
		if tx.Signatures[i], err = privateKey.Sign(messageContent); err != nil {
			return nil, fmt.Errorf("failed to signed with key %q: %w", key.String(), err)
		}
		output = append(output, tx.Signatures[i][:]...)
	}
	output = append(output, messageContent...)
	if len(output) > 1232 {
		return output, fmt.Errorf("transaction too large:max: raw 1232(%d)", len(output))
	}
	return output, nil
}

func (tx *Transaction) SignTX(signers ...PrivateKey) ([]byte, error) {
	messageContent, err := tx.Message.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("unable to encode message for signing: %w", err)
	}

	signerKeys := tx.Message.signerKeys()
	tx.Signatures = make([]Signature, len(signerKeys))

	signerMap := make(map[PublicKey]PrivateKey, len(signers))

	for _, s := range signers {
		signerMap[s.PublicKey()] = s
	}

	for i, key := range signerKeys {
		s, ok := signerMap[key]
		if !ok {
			continue
		}
		sig, err := s.Sign(messageContent)
		if err != nil {
			return nil, fmt.Errorf("failed to sign with key %q: %w", key.String(), err)
		}
		tx.Signatures[i] = sig
	}

	var signatureCount []byte
	bin.EncodeCompactU16Length(&signatureCount, len(tx.Signatures))

	totalLen := len(signatureCount) + len(tx.Signatures)*SignatureSize + len(messageContent)
	output := make([]byte, totalLen)
	off := 0
	off += copy(output[off:], signatureCount)
	for _, sig := range tx.Signatures {
		off += copy(output[off:], sig[:])
	}
	copy(output[off:], messageContent)
	if len(output) > MaxRawTxSize {
		return output, fmt.Errorf("transaction too large: max raw %d (got %d)", MaxRawTxSize, len(output))
	}
	return output, nil
}

// TransactionFromDecoder decodes a transaction from a decoder.
func TransactionFromDecoder(decoder *bin.Decoder) (*Transaction, error) {
	var out *Transaction
	err := decoder.Decode(&out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func TransactionFromBytes(data []byte) (*Transaction, error) {
	decoder := bin.NewBinDecoder(data)
	return TransactionFromDecoder(decoder)
}

func TransactionFromBase64(b64 string) (*Transaction, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return TransactionFromBytes(data)
}

func TransactionFromBase58(b58 string) (*Transaction, error) {
	data, err := base58.Decode(b58)
	if err != nil {
		return nil, err
	}
	return TransactionFromBytes(data)
}

func MustTransactionFromDecoder(decoder *bin.Decoder) *Transaction {
	out, err := TransactionFromDecoder(decoder)
	if err != nil {
		panic(err)
	}
	return out
}

const (
	AccountsTypeIndex = "Fee"
	AccountsTypeKey   = "Key"
)

type CompiledInstruction struct {
	// Index into the message.accountKeys array indicating the program account that executes this instruction.
	// NOTE: it is actually a uint8, but using a uint16 because uint8 is treated as a byte everywhere,
	// and that can be an issue.
	ProgramIDIndex uint16 `json:"programIdIndex"`

	// List of ordered indices into the message.accountKeys array indicating which accounts to pass to the program.
	// NOTE: it is actually a []uint8, but using a uint16 because []uint8 is treated as a []byte everywhere,
	// and that can be an issue.
	Accounts []byte `json:"accounts"`

	// The program input data encoded in a base-58 string.
	Data Base58 `json:"data"`
}

func (ci *CompiledInstruction) GetProgramIdIndex() uint32 {
	return uint32(ci.ProgramIDIndex)
}

func (ci *CompiledInstruction) GetAccounts() []byte {
	return ci.Accounts
}

func (ci *CompiledInstruction) GetData() []byte {
	return ci.Data
}

func (ci *CompiledInstruction) ResolveInstructionAccounts(message *Message) ([]*AccountMeta, error) {
	out := make([]*AccountMeta, len(ci.Accounts))
	metas, err := message.AccountMetaList()
	if err != nil {
		return nil, err
	}
	for i, acct := range ci.Accounts {
		out[i] = metas[acct]
	}

	return out, nil
}

type Instruction interface {
	ProgramID() PublicKey     // the programID the instruction acts on
	Accounts() []*AccountMeta // returns the list of accounts the instructions requires
	Data() ([]byte, error)    // the binary encoded instructions
}

type TransactionOption interface {
	apply(opts *transactionOptions)
}

func TransactionPayer(payer PublicKey) TransactionOption {
	return transactionOptionFunc(func(opts *transactionOptions) { opts.payer = payer })
}

func TransactionAddressTables(tables map[PublicKey]PublicKeySlice) TransactionOption {
	return transactionOptionFunc(func(opts *transactionOptions) {
		if opts.addressTablesIndex == nil {
			opts.addressTablesIndex = make(map[PublicKey]*AddressTableIndex, 50)
		}
		for addressTablePubKey, addressTable := range tables {
			if len(addressTable) > 256 {
				continue
			}
			for i, address := range addressTable {
				_, ok := opts.addressTablesIndex[address]
				if ok {
					continue
				}
				opts.addressTablesIndex[address] = &AddressTableIndex{
					Address: addressTablePubKey,
					Index:   uint8(i),
				}
			}
		}
	})
}

func TransactionAddressTablesIndex(tables map[PublicKey]*AddressTableIndex) TransactionOption {
	return transactionOptionFunc(func(opts *transactionOptions) {
		opts.addressTablesIndex = tables
	})
}

type transactionOptions struct {
	payer              PublicKey
	addressTablesIndex map[PublicKey]*AddressTableIndex
}

type transactionOptionFunc func(opts *transactionOptions)

func (f transactionOptionFunc) apply(opts *transactionOptions) {
	f(opts)
}

type TransactionBuilder struct {
	instructions    []Instruction
	recentBlockHash Hash
	opts            []TransactionOption
}

func NewTransactionBuilder() *TransactionBuilder {
	return &TransactionBuilder{}
}

func (builder *TransactionBuilder) AddInstruction(instruction Instruction) *TransactionBuilder {
	builder.instructions = append(builder.instructions, instruction)
	return builder
}

func (builder *TransactionBuilder) SetRecentBlockHash(recentBlockHash Hash) *TransactionBuilder {
	builder.recentBlockHash = recentBlockHash
	return builder
}

// WithOpt adds a TransactionOption.
func (builder *TransactionBuilder) WithOpt(opt TransactionOption) *TransactionBuilder {
	builder.opts = append(builder.opts, opt)
	return builder
}

func (builder *TransactionBuilder) SetFeePayer(feePayer PublicKey) *TransactionBuilder {
	builder.opts = append(builder.opts, TransactionPayer(feePayer))
	return builder
}

func (builder *TransactionBuilder) Build() (*Transaction, error) {
	return NewTransaction(
		builder.instructions,
		builder.recentBlockHash,
		builder.opts...,
	)
}

type AddressTableIndex struct {
	Address PublicKey
	Index   uint8
}

func NewTransaction(instructions []Instruction, recentBlockHash Hash, opts ...TransactionOption) (*Transaction, error) {
	if len(instructions) == 0 {
		return nil, fmt.Errorf("requires at-least one instruction to create a transaction")
	}
	options := transactionOptions{}
	for _, opt := range opts {
		opt.apply(&options)
	}

	feePayer := options.payer

	if feePayer.IsZero() {
		found := false
		for _, act := range instructions[0].Accounts() {
			if act.IsSigner {
				feePayer = act.PublicKey
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("cannot determine fee payer. You can ether pass the fee payer via the 'TransactionWithInstructions' option parameter or it falls back to the first instruction's first signer")
		}
	}

	programIDs := make(PublicKeySlice, 0, 6)
	accounts := make([]*AccountMeta, 0, 32)

	for _, instruction := range instructions {
		accounts = append(accounts, instruction.Accounts()...)
		programIDs.UniqueAppend(instruction.ProgramID())
	}

	programIDsMap := make(map[PublicKey]struct{}, len(programIDs))

	for _, programID := range programIDs {
		accounts = append(accounts, &AccountMeta{
			PublicKey:  programID,
			IsSigner:   false,
			IsWritable: false,
		})
		programIDsMap[programID] = struct{}{}
	}

	sort.SliceStable(accounts, func(i, j int) bool {
		return accounts[i].Less(accounts[j])
	})

	uniqAccountsMap := map[PublicKey]uint64{}
	var uniqAccounts []*AccountMeta

	for _, acc := range accounts {
		if index, found := uniqAccountsMap[acc.PublicKey]; found {
			uniqAccounts[index].IsWritable = uniqAccounts[index].IsWritable || acc.IsWritable
			continue
		}
		uniqAccounts = append(uniqAccounts, acc)
		uniqAccountsMap[acc.PublicKey] = uint64(len(uniqAccounts) - 1)
	}

	feePayerIndex := -1
	for idx, acc := range uniqAccounts {
		if acc.PublicKey.Equals(feePayer) {
			feePayerIndex = idx
		}
	}

	accountCount := len(uniqAccounts)
	if feePayerIndex < 0 {
		accountCount++
	}
	allKeys := make([]*AccountMeta, accountCount)

	itr := 1
	for idx, uniqAccount := range uniqAccounts {
		if idx == feePayerIndex {
			uniqAccount.IsSigner = true
			uniqAccount.IsWritable = true
			allKeys[0] = uniqAccount
			continue
		}
		allKeys[itr] = uniqAccount
		itr++
	}

	if feePayerIndex < 0 {
		// fee payer is not part of accounts we want to add it
		feePayerAccount := &AccountMeta{
			PublicKey:  feePayer,
			IsSigner:   true,
			IsWritable: true,
		}
		allKeys[0] = feePayerAccount
	}

	message := Message{
		RecentBlockhash: recentBlockHash,
		Instructions:    make([]CompiledInstruction, 0, len(instructions)),
		AccountKeys:     make(PublicKeySlice, 0, len(allKeys)),
	}

	lookupsMap := make(map[PublicKey]struct {
		AccountKey      PublicKey
		WritableIndexes []uint8
		Writable        []PublicKey
		ReadonlyIndexes []uint8
		Readonly        []PublicKey
	})

	for idx, acc := range allKeys {
		addressLookupKeyEntry, isPresentedInTables := options.addressTablesIndex[acc.PublicKey]
		_, isInvoked := programIDsMap[acc.PublicKey]
		if isPresentedInTables && idx != 0 && !acc.IsSigner && !isInvoked {
			lookup := lookupsMap[addressLookupKeyEntry.Address]
			if acc.IsWritable {
				lookup.WritableIndexes = append(lookup.WritableIndexes, addressLookupKeyEntry.Index)
				lookup.Writable = append(lookup.Writable, acc.PublicKey)
			} else {
				lookup.ReadonlyIndexes = append(lookup.ReadonlyIndexes, addressLookupKeyEntry.Index)
				lookup.Readonly = append(lookup.Readonly, acc.PublicKey)
			}

			lookupsMap[addressLookupKeyEntry.Address] = lookup
			continue
		}

		message.AccountKeys = append(message.AccountKeys, acc.PublicKey)

		if acc.IsSigner {
			message.Header.NumRequiredSignatures++
			if !acc.IsWritable {
				message.Header.NumReadonlySignedAccounts++
			}
			continue
		}

		if !acc.IsWritable {
			message.Header.NumReadonlyUnsignedAccounts++
		}
	}

	var lookupsWritableKeys []PublicKey
	var lookupsReadOnlyKeys []PublicKey
	if len(lookupsMap) > 0 {
		lookups := make([]MessageAddressTableLookup, 0, len(lookupsMap))

		for tablePubKey, l := range lookupsMap {
			lookupsWritableKeys = append(lookupsWritableKeys, l.Writable...)
			lookupsReadOnlyKeys = append(lookupsReadOnlyKeys, l.Readonly...)
			lookups = append(lookups, MessageAddressTableLookup{
				AccountKey:      tablePubKey,
				WritableIndexes: l.WritableIndexes,
				ReadonlyIndexes: l.ReadonlyIndexes,
			})
		}

		message.SetAddressTableLookups(lookups)
	}

	var idx uint8
	accountKeyIndex := make(map[PublicKey]uint8, len(message.AccountKeys)+len(lookupsWritableKeys)+len(lookupsReadOnlyKeys))

	for _, acc := range message.AccountKeys {
		accountKeyIndex[acc] = idx
		idx++
	}

	for _, acc := range lookupsWritableKeys {
		accountKeyIndex[acc] = idx
		idx++
	}

	for _, acc := range lookupsReadOnlyKeys {
		accountKeyIndex[acc] = idx
		idx++
	}

	for txIdx, instruction := range instructions {
		accounts = instruction.Accounts()
		accountIndex := make([]byte, len(accounts))
		for idx, acc := range accounts {
			accountIndex[idx] = accountKeyIndex[acc.PublicKey]
		}
		data, err := instruction.Data()
		if err != nil {
			return nil, fmt.Errorf("unable to encode instructions [%d]: %w", txIdx, err)
		}
		message.Instructions = append(message.Instructions, CompiledInstruction{
			ProgramIDIndex: uint16(accountKeyIndex[instruction.ProgramID()]),
			Accounts:       accountIndex,
			Data:           data,
		})
	}

	return &Transaction{
		Message: message,
	}, nil
}

type privateKeyGetter func(key PublicKey) *PrivateKey

func formatMeta(name string, meta *AccountMeta) string {
	if meta == nil {
		return text.Shakespeare(name) + ": " + "<nil>"
	}
	out := text.Shakespeare(name) + ": " + text.ColorizeBG(meta.PublicKey.String())
	out += " ["
	if meta.IsWritable {
		out += "WRITE"
	}
	if meta.IsSigner {
		if meta.IsWritable {
			out += ", "
		}
		out += "SIGN"
	}
	out += "] "
	return out
}

func countSigners(tx *Transaction) (count int) {
	if tx == nil {
		return -1
	}
	return tx.Message.Signers().Len()
}

func countReadonlyAccounts(tx *Transaction) (count int) {
	if tx == nil {
		return -1
	}
	return int(tx.Message.Header.NumReadonlyUnsignedAccounts) + int(tx.Message.Header.NumReadonlySignedAccounts)
}

func countWriteableAccounts(tx *Transaction) (count int) {
	if tx == nil {
		return -1
	}
	if !tx.Message.IsVersioned() {
		metas, err := tx.Message.AccountMetaList()
		if err != nil {
			return -1
		}
		for _, meta := range metas {
			if meta.IsWritable {
				count++
			}
		}
		return count
	}
	numStatisKeys := len(tx.Message.AccountKeys)
	statisKeys := tx.Message.AccountKeys
	h := tx.Message.Header
	for _, key := range statisKeys {
		accIndex, ok := getStaticAccountIndex(tx, key)
		if !ok {
			continue
		}
		index := int(accIndex)
		is := false
		if index >= int(h.NumRequiredSignatures) {
			// unsignedAccountIndex < numWritableUnsignedAccounts
			is = index-int(h.NumRequiredSignatures) < (numStatisKeys-int(h.NumRequiredSignatures))-int(h.NumReadonlyUnsignedAccounts)
		} else {
			is = index < int(h.NumRequiredSignatures-h.NumReadonlySignedAccounts)
		}
		if is {
			count++
		}
	}
	if tx.Message.IsResolved() {
		return count
	}
	count += tx.Message.NumWritableLookups()
	return count
}

func getStaticAccountIndex(tx *Transaction, key PublicKey) (int, bool) {
	for idx, a := range tx.Message.AccountKeys {
		if a.Equals(key) {
			return (idx), true
		}
	}
	return -1, false
}
