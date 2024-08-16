package main

import (
	"bytes"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/core/vm/runtime"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/ethereum/go-ethereum/triedb/hashdb"
	"math/big"
	"strings"
	"testing"
)

// # How to use this to develop test cases...
// # First we should run some fuzzing... There are some basic seeds in this file, but additional seeds can be added to the test data folder
// go test -fuzz=FuzzEVMRunner -cover github.com/ethereum/go-ethereum/cmd/evm
// # Next, we should backup the test data folder
// cp -r cmd/evm/testdata/fuzz/FuzzEVMRunner cmd/evm/testdata/fuzz/FuzzEVMRunner.bak
// # Move the cached tests into the test data folder
// cp $(go env GOCACHE)/fuzz/github.com/ethereum/go-ethereum/cmd/evm/FuzzEVMRunner/* cmd/evm/testdata/fuzz/FuzzEVMRunner/
// # Run test coverage
// go test -cover -coverpkg=./... -coverprofile=evm.out github.com/ethereum/go-ethereum/cmd/evm
// # Narrow down the coverage to VM for now
// go test -cover -coverpkg=./core/vm/... -coverprofile=evm.out github.com/ethereum/go-ethereum/cmd/evm
// # Look at it
// go tool cover --html=evm.out
import (
	"math/rand"
)

func FuzzEVMRunner(f *testing.F) {
	setFuzzCorpus(f)

	f.Fuzz(func(t *testing.T, inputSender, inputReceiver, inputCode, inputInput []byte, initialGas, inputPrice, inputValue uint64, inputCreateContract bool) {
		inputSender = sanitizeHex(inputSender)
		inputReceiver = sanitizeHex(inputReceiver)
		inputCode = sanitizeHex(inputCode)
		inputInput = sanitizeHex(inputInput)
		err := runEVM(inputSender, inputReceiver, inputCode, inputInput, initialGas, inputPrice, inputValue, inputCreateContract)
		err = checkKnownError(err)
		if err != nil {
			t.Errorf("Execution error: %s", err.Error())
		}
	})
}

func sanitizeHex(hexString []byte) []byte {
	hexString = bytes.TrimSpace(hexString)
	if len(hexString)%2 != 0 {
		hexString = append([]byte{0x30}, hexString...)
	}

	return hexString
}

func checkKnownError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if msg == "insufficient balance for transfer" {
		return nil
	}
	if strings.Contains(msg, "stack underflow") {
		return nil
	}
	if strings.Contains(msg, "invalid opcode") {
		return nil
	}
	if strings.Contains(msg, "out of gas") {
		return nil
	}
	if strings.Contains(msg, "bad elliptic curve pairing size") {
		return nil
	}
	if strings.Contains(msg, "malformed point") {
		return nil
	}
	if strings.Contains(msg, "invalid jump destination") {
		return nil
	}
	if strings.Contains(msg, "gas uint64 overflow") {
		return nil
	}
	if strings.Contains(msg, "bn256: coordinate exceeds modulus") {
		return nil
	}
	if strings.Contains(msg, "return data out of bounds") {
		return nil
	}
	if strings.Contains(msg, "execution reverted") {
		return nil
	}
	if strings.Contains(msg, "max code size exceeded") {
		return nil
	}
	if strings.Contains(msg, "stack limit reached") {
		return nil
	}
	return err
}

func setFuzzCorpus(f *testing.F) {
	accounts := getTestEOAs()
	// do some simple transfers
	for _, account := range accounts {
		f.Add(
			[]byte(account.Hex()),
			[]byte(accounts[rand.Intn(len(accounts))].Hex()),
			[]byte(""),
			[]byte(""),
			uint64(30_000_000),
			uint64(100_000_000_000),
			uint64(100_000),
			false,
		)
	}
	// Run a contract
	f.Add(
		[]byte(accounts[rand.Intn(len(accounts))].Hex()),
		[]byte("cccccccccccccccccccccccccccccccccccccccc"),
		[]byte("600160015B8101905A60201063000000045700"),
		[]byte(""),
		uint64(30_000_000),
		uint64(100_000_000_000),
		uint64(100_000),
		false,
	)
	// deployable
	f.Add(
		[]byte(accounts[rand.Intn(len(accounts))].Hex()),
		[]byte("cccccccccccccccccccccccccccccccccccccccc"),
		[]byte("6013600C60003960136000F3600160015B8101905A60201063000000045700"),
		[]byte(""),
		uint64(30_000_000),
		uint64(100_000_000_000),
		uint64(100_000),
		true,
	)
	contracts := seedContracts()
	for _, c := range contracts {
		f.Add(
			[]byte(accounts[rand.Intn(len(accounts))].Hex()),
			[]byte("cccccccccccccccccccccccccccccccccccccccc"),
			[]byte(c),
			[]byte(""),
			uint64(30_000_000),
			uint64(100_000_000_000),
			uint64(100_000),
			true,
		)
	}
	// Hit the reserved addresses
	for i := 0; i < 256; i++ {
		f.Add(
			[]byte(accounts[rand.Intn(len(accounts))].Hex()),
			[]byte(fmt.Sprintf("%x", i)),
			[]byte(""),
			[]byte(""),
			uint64(30_000_000),
			uint64(100_000_000_000),
			uint64(100_000),
			false,
		)
	}
}

func seedContracts() []string {
	return []string{
		"4860005260206000F3",
		"6000545B60006040600060006001856000F150600101620100005A1163000000035760005500",
		"7F600A600C600039600A6000F332FF60005260206000F300000000000000000000607852601560786000F05B600060006000600060018561139CFA50506180005A11630000002B5700",
		"323331435F3515630000000E57005B60203515630000002A576000600060006000600130611000F150005B600060006000600030611000F45050",
		"7F601A600C600039601A6000F360005450600160000380806000556001556001556000527F6001545033FF00000000000000000000000000000000000000000000000000006020526020602660006000F56020602660006000F55060005260206000F3",
		"60005B60010180806000558061100010630000001C576300000002565B00",
		"60005B60010180405063000000025600",
		"60005B7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF81526020016101005A1163000000025700",
		"60005B6001018080600055806103FC10630000001C576300000002565B00",
		"60003560015500",
		"7F7375636365737300000000000000000000000000000000000000000000000000610100526007610100F35B60006000FD00",
		"FE60005260206000F3",
		"6C68656C6C6F2C20776F726C64215F52623B60006C68656C6C6F2C20776F726C642181525F205F525F6001F3",
		"6C68656C6C6F2C20776F726C64215F5260085A046C68656C6C6F2C20776F726C642181526000600059600060045AFA",
		"6C68656C6C6F2C20776F726C64215F52600E5A046C68656C6C6F2C20776F726C64218152805FA05F525F6001F3",
		"6C68656C6C6F2C20776F726C64215F5260085A046C68656C6C6F2C20776F726C642181526000600059600060025AFA",
		"6C68656C6C6F2C20776F726C64215F5260085A046C68656C6C6F2C20776F726C642181525F205F525F6001F3",
		"60005B600101805F5260205FA06102A35A1163000000025700",
		"60005B60010180545063000000025600",
		"60005B6001018054506108505A1163000000025760005260206000A000",
		"5B630000000056",
		"6101006000526101006020526101006040526C68656C6C6F2C20776F726C642160605260085A046C68656C6C6F2C20776F726C6421815260006000610360600060055AFA",
		"67FFFFFFFFFFFFFF005B7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF81526020016101005A1163000000095700",
		"60005B7F5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B815260200180615FE0116300000002575B7F5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5A6160001060005700615FE0526160006000F300",
		"600061599960005B7F5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B81526020018082116300000007575B6000F3",
		"5F5FFD",
		"3860006000396110005A106300000017573860006000F05B00",
		"60005B60010180806103FB106300000018576300000002565B3860006000396110005A106300000030573860006000F05B00",
		"5F35FF00",
		"32FF60005260206000F3",
		"600160015B810190630000000456",
		"600160015B8101905A60201063000000045700",
		"60005460010160005500",
		"600054630000004E5775600A600C600039600A6000F3600054600101600055006000527F23CB77063C40D0ECBD68298897F479477AB7D18A1108BA3A3E8A72383FE698B06016600A6000F56000555B6000545B6000600060006000600085616000F1506160005A116300000052575000",
		"60005450600160000380806000556001556001556001545033FF",
		"7E112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF6000527E112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF60015260216000A000",
		"60005B60010180405060405A1163000000025700",
	}
}

func getTestAllocs() types.GenesisAlloc {
	ga := make(types.GenesisAlloc)
	initBalance, _ := new(big.Int).SetString("1000000000000000000000000000", 10)
	accounts := getTestEOAs()
	for _, acc := range accounts {
		ga[acc] = types.Account{Balance: initBalance}
	}
	return ga

}

func getTestEOAs() []common.Address {
	return []common.Address{
		common.HexToAddress("0x85da99c8a7c2c95964c8efd687e95e632fc533d6"), // 42b6e34dc21598a807dc19d7784c71b2a7a01f6480dc6f58258f78e539f1a1fa
		common.HexToAddress("0x125fb391ba829e0865963d3b91711610049a9e78"), // 0903a9a721167e2abaa0a33553cbeb209dc9300d28e4e4d6d2fac2452f93e357
		common.HexToAddress("0x964ec59d0e05db08440c822d7c588e63bbde8c4e"), // 6421222a9964cbe1b411191dcac1afda173ed99346c47302c6fe88f65d83583e
		common.HexToAddress("0x62210af667d8c4b15ab07c88541b562426d41604"), // 1382a7ad39f49346bf890a0c5b3b8aec820cc37a06a5bd0a24dd1035f84d160c
		common.HexToAddress("0x010530c8066681d20412de14fbbfa21565956826"), // f8158fb8a9f37093d009cbf7392cf51c36cd49f1514f99c803f7d47ce3cb1f21
		common.HexToAddress("0x6e5c0ac738e7fd20227a1ca9f8bcd802e109b471"), // e79a26e98ad10db36e8d31cd0bcf93114d53f8acf99b0440d6a3ffb176a9cd98
		common.HexToAddress("0xcfe521bdf015c7cad2da8766cdc242fcb28ef028"), // 0ff28f44a47484706d12ce3ad203d5424b6d1c1c003c98853bd42b295c86f91a
		common.HexToAddress("0xfb68d6ec2636a5ee255e1d9401712409e2430d7b"), // ce509aa3945e98ffd706d3c850a6160a6ae162a4d5f6270fe1683401cf3160a5
		common.HexToAddress("0x0d4e5491610a61ca674bd0e6cf57bedb43ccbdaf"), // b5431beba55b8394ba192e8f1a6beb6e55d8cb21895a2d1957fe3a545b90b676
		common.HexToAddress("0x1fb6a1a46561a2dba2926754557fc67a1bd90d4c"), // 8894a97d70ea74dd6b088d7d4c0602897fbb01f0a408ae754c488681357e6a60
		common.HexToAddress("0x6aa64101baa3a6f1314913672e72da147c348f64"), // 3f072fbc971531da138b4b3bddd9243d79a2fedb8e6c491fb22070d3752c6c05
		common.HexToAddress("0x4358db66011ddba2baa562d1c90ac0ba12353a88"), // cca962562072f9279af1c9fa52bf2fcf084996fd44297349ba5c93fe3b0f7a3c
		common.HexToAddress("0xdaf2e00ac44bee07092a65fa0386eb6026733f40"), // 78f0aca8f5a69cea287e944b5c04d8f5b5c662485b16b59a130a90f4bd4dc38c
		common.HexToAddress("0xb8f8fbed2df96a1f67b583227084554349d87984"), // cb01b801fc0d03d3c4d34fe3fa9ffc4ca0f11498aeca0caa555e442beb5f1c91
		common.HexToAddress("0x7083957d70a24ba98dad458c05ec0ab66f3cb7dd"), // f3d72a709b49801754d7cc9c6adc903548584eb28689f163513bfaf35df1b8a6
		common.HexToAddress("0x26275d1f45ad6050bcde044e7d396a2240f63e46"), // 52fac48f0cf8935950d041c7bb1606f9172d57a133f4491700daba203985c1af
		common.HexToAddress("0x53e73e598d2832ec86527d3a836cb16c85884827"), // 2687427c877588332f56101d8473fa4cbe24c3a9bcffd6bc154c7d8240eb99f7
		common.HexToAddress("0x9fbdad4eec696ffd7fec52b036d16c926b71b4be"), // aad5f68d07131079612c5614c8df442fc87e79de83832e6359713338e9e2a065
		common.HexToAddress("0xacf4d941316677064b09354ac4aeae4d45cb828b"), // 1050eb70cea911d9d0064e29784e965eb38722291590255a23a86f90001548b6
		common.HexToAddress("0x6d5821d6d50108649480a63d6f337f8473d661ef"), // 10c07ae92d54c037aca60e6518407d65206c330441c552b2799994cef5de0f36
	}
}

func runEVM(inputSender, inputReceiver, inputCode, inputInput []byte, initialGas, inputPrice, inputValue uint64, inputCreateContract bool) error {
	var (
		tracer      *tracing.Hooks
		statedb     *state.StateDB
		chainConfig *params.ChainConfig
		sender      = common.BytesToAddress(inputSender)
		receiver    = common.BytesToAddress(inputReceiver)
		preimages   = false
		blobHashes  []common.Hash  // TODO (MariusVanDerWijden) implement blob hashes in state tests
		blobBaseFee = new(big.Int) // TODO (MariusVanDerWijden) implement blob fee in state tests
	)

	genesisConfig := new(core.Genesis)
	genesisConfig.GasLimit = initialGas
	genesisConfig.Config = params.AllDevChainProtocolChanges
	genesisConfig.Alloc = getTestAllocs()

	db := rawdb.NewMemoryDatabase()
	triedb := triedb.NewDatabase(db, &triedb.Config{
		Preimages: preimages,
		HashDB:    hashdb.Defaults,
	})
	defer triedb.Close()
	genesis := genesisConfig.MustCommit(db, triedb)

	sdb := state.NewDatabaseWithNodeDB(db, triedb)
	statedb, _ = state.New(genesis.Root(), sdb, nil)
	chainConfig = genesisConfig.Config

	statedb.CreateAccount(sender)

	var code []byte
	var hexcode []byte
	hexcode = inputCode
	hexcode = bytes.TrimSpace(hexcode)
	if len(hexcode)%2 != 0 {
		return fmt.Errorf("Invalid input length for hex data (%d)\n", len(hexcode))
	}
	code = common.FromHex(string(hexcode))
	runtimeConfig := runtime.Config{
		Origin:      sender,
		State:       statedb,
		GasLimit:    initialGas,
		GasPrice:    new(big.Int).SetUint64(inputPrice),
		Value:       new(big.Int).SetUint64(inputValue),
		Difficulty:  genesisConfig.Difficulty,
		Time:        genesisConfig.Timestamp,
		Coinbase:    genesisConfig.Coinbase,
		BlockNumber: new(big.Int).SetUint64(genesisConfig.Number),
		BlobHashes:  blobHashes,
		BlobBaseFee: blobBaseFee,
		EVMConfig: vm.Config{
			Tracer: tracer,
		},
	}

	if chainConfig != nil {
		runtimeConfig.ChainConfig = chainConfig
	} else {
		runtimeConfig.ChainConfig = params.AllEthashProtocolChanges
	}

	var hexInput []byte
	hexInput = inputInput
	hexInput = bytes.TrimSpace(hexInput)
	if len(hexInput)%2 != 0 {
		return fmt.Errorf("input length must be even")
	}
	input := common.FromHex(string(hexInput))

	var execFunc func() ([]byte, uint64, error)
	// Create or call
	if inputCreateContract {
		input = append(code, input...)
		execFunc = func() ([]byte, uint64, error) {
			output, _, gasLeft, err := runtime.Create(input, &runtimeConfig)
			return output, gasLeft, err
		}
	} else {
		if len(code) > 0 {
			statedb.SetCode(receiver, code)
		}
		execFunc = func() ([]byte, uint64, error) {
			return runtime.Call(receiver, input, &runtimeConfig)
		}
	}

	output, leftOverGas, stats, err := timedExec(false, execFunc)
	_ = output
	_ = leftOverGas
	_ = stats
	return err

	return nil
}
