package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"math/big"
	"strconv"
	"time"
)

var (
	maxNonce = math.MaxInt64
)

const targetBits = 20

type Block struct {
	Timestamp     int64
	Data          []byte
	PrevBlockHash []byte
	Hash          []byte
	Nonce         int
}

//비트코인에서 목표비트란 블록이 체쿨되는 난이도를 저장하고 있는 블록헤더이다.현재는 목표 조정 알고리즘을 구현하지 않을 것이므로 난이도를 전역상수로 정의할 수 있다.
//24는 임의의 숫자이고,우리의 목표는 256비트 이하의 메모리를 차지하는 타겟을 갖는 것이다.
type ProofOfWork struct {
	block  *Block
	target *big.Int
}

//블록포인터와 타겟포인터를 가진 Proof구조체 생성
//NewProofOfWork함수에사ㅓ bit.int를 1로 초기화 하고 256 -targetBits비트만큼 좌측 시프트 연산
//256은 SHA-256 해시의 비트길이로 SHA-256이 사용핳 해시 알고리즘
func NewProofOfWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-targetBits))
	pow := &ProofOfWork{b, target}
	return pow

}
func IntToHex(num int64) []byte {
	buff := new(bytes.Buffer)
	err := binary.Write(buff, binary.BigEndian, num)
	if err != nil {
		log.Panic(err)
	}

	return buff.Bytes()
}

//단순히 블록의 필드값들과 타겟 및 논스값을 병합하는 직관적인 코드다. **논스 (nonce)**란 해시캐시에서의 카운터와 동일한 역할을 하는 암호학 용어이다.
func (pow *ProofOfWork) prepareData(nonce int) []byte {
	data := bytes.Join(
		[][]byte{
			pow.block.PrevBlockHash,
			// pow.block.HashTransactions(),
			IntToHex(pow.block.Timestamp),
			IntToHex(int64(targetBits)),
			IntToHex(int64(nonce)),
		},
		[]byte{},
	)

	return data
}

// Run performs a proof-of-work
// 먼저 변수들을 초기화한다.
//1.데이터준비
//2.sha-256해싱
//3.해시값의 큰 정수로의 변환
//4.정수값과 타겟값 비교
func (pow *ProofOfWork) Run() (int, []byte) {
	var hashInt big.Int
	var hash [32]byte
	nonce := 0

	fmt.Printf("Mining a new block")
	for nonce < maxNonce {
		data := pow.prepareData(nonce)

		hash = sha256.Sum256(data)
		fmt.Printf("\r%x", hash)
		hashInt.SetBytes(hash[:])

		if hashInt.Cmp(pow.target) == -1 {
			break
		} else {
			nonce++
		}
	}
	fmt.Print("\n\n")

	return nonce, hash[:]
}

//비트코인 스펙에서는 timestamp,prevblockchain및 hash가 블록헤더라는 하나의 독립된 데이터 구조를 이루며 트레젝션(Data)이 또다른 독립된 데이터 구조
//를 갖는다

//블록체인은 본질적으로 특정한 구조를 지난 데이터베이스일뿐이며,순서가 지정된 링크드리스트이다 즉 블록은 순서대로 저장되며 각 블록은 이전 블록과 연결된다
//이러한 구조로 인해 블록을 빠르게 가져오기가 가능하며 해시로 블록을 효율적으로 검색할 수 잇다
type BlockChain struct {
	blocks []*Block
}

//해쉬변환
// func (b *Block) SetHash() {
// 	timestamp := []byte(strconv.FormatInt(b.Timestamp, 10))
// 	headers := bytes.Join([][]byte{b.PrevBlockHash, b.Data, timestamp}, []byte{})
// 	hash := sha256.Sum256(headers)
// 	b.Hash = hash[:]
// }

//블록생성
func NewBlock(data string, prevBlockHash []byte) *Block {
	block := &Block{time.Now().Unix(), []byte(data), prevBlockHash, []byte{}, 0}
	pow := NewProofOfWork(block)
	nonce, hash := pow.Run()

	block.Hash = hash[:]
	block.Nonce = nonce
	return block
}

//블록추가
func (bc *BlockChain) AddBlock(data string) {
	prevBlock := bc.blocks[len(bc.blocks)-1]
	NewBlock := NewBlock(data, prevBlock.Hash)
	bc.blocks = append(bc.blocks, NewBlock)
}

//새블록을 추가하려면 기본블록이 필요  모든 블록체인에는 이전 블록이 필요!! , 첫번째 블록을 제네시스 블록이라 칭함
func NewGenesisBlock() *Block {
	return NewBlock("Genesis Block", []byte{})
}

//블록체인 생성
func NewBlockchain() *BlockChain {
	return &BlockChain{[]*Block{NewGenesisBlock()}}
}

// Validate validates block's PoW
func (pow *ProofOfWork) Validate() bool {
	var hashInt big.Int

	data := pow.prepareData(pow.block.Nonce)
	hash := sha256.Sum256(data)
	hashInt.SetBytes(hash[:])

	isValid := hashInt.Cmp(pow.target) == -1

	return isValid
}

//블록체인에서 새로운 블록을 추가하는데 몇가지 작업이 필요 블록 추가 권한을 얻기 위해서 무거은 계산이 필요하다
//이 메커니즘을 작업증명이라 하며 블록체인은 단일 의사 결정자가 없는 분산화된 데이터베이스이다.
//하나의 새로운 블록은 반드시 네트워크의 참여자들로 부터 확인과 승인을 받아야한다 이 메커니즘을 컨센서스 라 한다
func main() {
	bc := NewBlockchain()

	bc.AddBlock("Send 1 BTC to Iven")
	bc.AddBlock("Send 2 more BTC to Iven")

	for _, block := range bc.blocks {
		pow := NewProofOfWork(block)
		fmt.Printf("PoW: %s\n", strconv.FormatBool(pow.Validate()))
		fmt.Printf("Prev. hash: %x\n", block.PrevBlockHash)
		fmt.Printf("Data:%s\n", block.Data)
		fmt.Printf("Hash:%x\n", block.Hash)
		fmt.Println()
	}

}

//작업증명
//네트워크의 일부 참여자들은 네트워크를 유지하기 위해 블록을 생성하고 이에 대한 보상을 받는다
//이 작업의 결과로 블록은 블록체인에 안전하게 추가되어 전체 블록체인 데이터베이스의 안정성을 유지한다
//여려운 작업을 수행하고 이를 증명한다.의 전체 메커니즘을 작업증명이라 한다.
//
//해싱
//어떠한 툭정한 데이터에 대한 해시를 얻는 과정
//1.원본 데이터는 해시에서 복원될 수 없다.
//2.툭정 데이터는 단 하나의 해시값만 가지며 해시는 고유하다
//3.입력 데이터에서 하나이 바이트만 수정해도 완전히 다른 해시값이 생성된다.
//블록체인에서 해싱은 블록의 일관성을 보장하는데 사용된다.해싱 알고리즘의 입력 데이터에는 이전 블록 해시값도 포함되어 있어 체인상의 어떤 한 블록을 변경하는 것은 불가능하다.
//하나의 블록을 변경하면 해당 블록에 대한 해시와 그 이후의 모든 블록들의 대한 해시를 다시 계산하기 때문이다

//해시캐시
//비트코인은 초기에 이메일 스팸을 방지하기 위해 개발된 작업 증명 알고리즘인 해시캐시를 사용한다
//1.공개적으로 알려진 데이터를 가져온다(이메일의 경우 수신자의 이메일주소,비트코인의 경우 블록의 헤더)
//2.여기에 카운터를 더한다.카운터는 0부터 시작한다
//3.data+counter 의 해시를 구한다.
//4.해시가 특정 요구사항을 충족하는지 확인한다.
//5.1.만족한다면 알고리즘을 끝낸다
//5.2 그렇지 않다면 카운터를 증가시켜 3번과 4번 스탭을 반복한다.

//즉 이는 무차별 대입알고리즘으로 카운터를 늘리고 새로운 해시를 계산하고 검증하는 과정을 반복한다.이게 바로 작업증명의 계산 비용이 높은 이유다
//
