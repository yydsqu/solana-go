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

package rpc

import (
	"encoding/binary"
	stdjson "encoding/json"
	bin "github.com/gagliardetto/binary"
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/stretchr/testify/assert"
)

func TestData_base64_zstd(t *testing.T) {
	val := "KLUv/QQAWQAAaGVsbG8td29ybGTcLcaB"
	in := `["` + val + `", "base64+zstd"]`

	var data DataBytesOrJSON
	err := data.UnmarshalJSON([]byte(in))
	assert.NoError(t, err)

	assert.Equal(t,
		[]byte("hello-world"),
		data.GetBinary(),
	)
	assert.Equal(t,
		solana.EncodingBase64Zstd,
		data.asDecodedBinary.Encoding,
	)
	assert.Equal(t,
		[]interface{}{
			val,
			"base64+zstd",
		},
		mustJSONToInterface(mustAnyToJSON(data)),
	)
}

func TestData_base64_zstd_empty(t *testing.T) {
	in := `["", "base64+zstd"]`

	var data DataBytesOrJSON
	err := data.UnmarshalJSON([]byte(in))
	assert.NoError(t, err)

	assert.Equal(t,
		[]byte(""),
		data.GetBinary(),
	)
	assert.Equal(t,
		solana.EncodingBase64Zstd,
		data.asDecodedBinary.Encoding,
	)
	assert.Equal(t,
		[]interface{}{
			"",
			"base64+zstd",
		},
		mustJSONToInterface(mustAnyToJSON(data)),
	)
}

func TestData_jsonParsed(t *testing.T) {
	in := `{"hello":"world"}`

	var data DataBytesOrJSON
	err := data.UnmarshalJSON([]byte(in))
	assert.NoError(t, err)

	assert.Equal(t,
		stdjson.RawMessage(in),
		data.GetRawJSON(),
	)
	assert.Equal(t,
		map[string]interface{}{
			"hello": "world",
		},
		mustJSONToInterface(mustAnyToJSON(data)),
	)
}

func TestData_jsonParsed_empty(t *testing.T) {
	in := `{}`

	var data DataBytesOrJSON
	err := data.UnmarshalJSON([]byte(in))
	assert.NoError(t, err)

	assert.Equal(t,
		stdjson.RawMessage(in),
		data.GetRawJSON(),
	)
	assert.Equal(t,
		map[string]interface{}{},
		mustJSONToInterface(mustAnyToJSON(data)),
	)
}

func TestData_DataBytesOrJSONFromBytes(t *testing.T) {
	in := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	dataBytesOrJSON := DataBytesOrJSONFromBytes(in)
	out := dataBytesOrJSON.GetBinary()
	assert.Equal(t, in, out)
}

type Mint struct {
	// Optional authority used to mint new tokens. The mint authority may only be provided during
	// mint creation. If no mint authority is present then the mint has a fixed supply and no
	// further tokens may be minted.
	MintAuthority *solana.PublicKey `bin:"optional"`

	// Total supply of tokens.
	Supply uint64

	// Number of base 10 digits to the right of the decimal place.
	Decimals uint8

	// Is `true` if this structure has been initialized
	IsInitialized bool

	// Optional authority to freeze token accounts.
	FreezeAuthority *solana.PublicKey `bin:"optional"`
}

func (mint *Mint) UnmarshalWithDecoder(dec *bin.Decoder) (err error) {
	{
		v, err := dec.ReadUint32(binary.LittleEndian)
		if err != nil {
			return err
		}
		if v == 1 {
			v, err := dec.ReadNBytes(32)
			if err != nil {
				return err
			}
			mint.MintAuthority = solana.PublicKeyFromBytes(v).ToPointer()
		} else {
			// discard:
			_, err := dec.ReadNBytes(32)
			if err != nil {
				return err
			}
		}
	}
	{
		v, err := dec.ReadUint64(binary.LittleEndian)
		if err != nil {
			return err
		}
		mint.Supply = v
	}
	{
		v, err := dec.ReadUint8()
		if err != nil {
			return err
		}
		mint.Decimals = v
	}
	{
		v, err := dec.ReadBool()
		if err != nil {
			return err
		}
		mint.IsInitialized = v
	}
	{
		v, err := dec.ReadUint32(binary.LittleEndian)
		if err != nil {
			return err
		}
		if v == 1 {
			v, err := dec.ReadNBytes(32)
			if err != nil {
				return err
			}
			mint.FreezeAuthority = solana.PublicKeyFromBytes(v).ToPointer()
		} else {
			// discard:
			_, err := dec.ReadNBytes(32)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func TestName(t *testing.T) {

}
