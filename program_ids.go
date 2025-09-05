// Copyright 2021 github.com/gagliardetto
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

var (
	SystemProgramID               = MustPublicKeyFromBase58("11111111111111111111111111111111")
	ConfigProgramID               = MustPublicKeyFromBase58("Config1111111111111111111111111111111111111")
	StakeProgramID                = MustPublicKeyFromBase58("Stake11111111111111111111111111111111111111")
	VoteProgramID                 = MustPublicKeyFromBase58("Vote111111111111111111111111111111111111111")
	BPFLoaderDeprecatedProgramID  = MustPublicKeyFromBase58("BPFLoader1111111111111111111111111111111111")
	BPFLoaderProgramID            = MustPublicKeyFromBase58("BPFLoader2111111111111111111111111111111111")
	BPFLoaderUpgradeableProgramID = MustPublicKeyFromBase58("BPFLoaderUpgradeab1e11111111111111111111111")
	Secp256k1ProgramID            = MustPublicKeyFromBase58("KeccakSecp256k11111111111111111111111111111")
	FeatureProgramID              = MustPublicKeyFromBase58("Feature111111111111111111111111111111111111")
	ComputeBudget                 = MustPublicKeyFromBase58("ComputeBudget111111111111111111111111111111")
	AddressLookupTableProgramID   = MustPublicKeyFromBase58("AddressLookupTab1e1111111111111111111111111")
)

var (
	TokenProgramID                     = MustPublicKeyFromBase58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
	Token2022ProgramID                 = MustPublicKeyFromBase58("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
	TokenSwapProgramID                 = MustPublicKeyFromBase58("SwaPpA9LAaLfeLi3a68M4DjnLqgtticKg6CnyNwgAC8")
	TokenSwapFeeOwner                  = MustPublicKeyFromBase58("HfoTxFR1Tm6kGmWgYWD6J7YHVy1UwqSULUGVLXkJqaKN")
	TokenLendingProgramID              = MustPublicKeyFromBase58("LendZqTs8gn5CTSJU1jWKhKuVpjJGom45nnwPb2AMTi")
	SPLAssociatedTokenAccountProgramID = MustPublicKeyFromBase58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
	MemoProgramID                      = MustPublicKeyFromBase58("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
	TokenMetadataProgramID             = MustPublicKeyFromBase58("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s")
	SolMint                            = MustPublicKeyFromBase58("So11111111111111111111111111111111111111112")
	WrappedSol                         = SolMint
)

var (
	SysVarClockPubkey             = MustPublicKeyFromBase58("SysvarC1ock11111111111111111111111111111111")
	SysVarEpochSchedulePubkey     = MustPublicKeyFromBase58("SysvarEpochSchedu1e111111111111111111111111")
	SysVarFeesPubkey              = MustPublicKeyFromBase58("SysvarFees111111111111111111111111111111111")
	SysVarInstructionsPubkey      = MustPublicKeyFromBase58("Sysvar1nstructions1111111111111111111111111")
	SysVarRecentBlockHashesPubkey = MustPublicKeyFromBase58("SysvarRecentB1ockHashes11111111111111111111")
	SysVarRentPubkey              = MustPublicKeyFromBase58("SysvarRent111111111111111111111111111111111")
	SysVarRewardsPubkey           = MustPublicKeyFromBase58("SysvarRewards111111111111111111111111111111")
	SysVarSlotHashesPubkey        = MustPublicKeyFromBase58("SysvarS1otHashes111111111111111111111111111")
	SysVarSlotHistoryPubkey       = MustPublicKeyFromBase58("SysvarS1otHistory11111111111111111111111111")
	SysVarStakeHistoryPubkey      = MustPublicKeyFromBase58("SysvarStakeHistory1111111111111111111111111")
	SysVarStakeConfigPubkey       = MustPublicKeyFromBase58("StakeConfig11111111111111111111111111111111")
)

var nativeProgramIDs = PublicKeySlice{
	BPFLoaderProgramID,
	BPFLoaderDeprecatedProgramID,
	FeatureProgramID,
	ConfigProgramID,
	StakeProgramID,
	VoteProgramID,
	Secp256k1ProgramID,
	SystemProgramID,
	SysVarClockPubkey,
	SysVarEpochSchedulePubkey,
	SysVarFeesPubkey,
	SysVarInstructionsPubkey,
	SysVarRecentBlockHashesPubkey,
	SysVarRentPubkey,
	SysVarRewardsPubkey,
	SysVarSlotHashesPubkey,
	SysVarSlotHistoryPubkey,
	SysVarStakeHistoryPubkey,
}

func isNativeProgramID(key PublicKey) bool {
	return nativeProgramIDs.Has(key)
}
