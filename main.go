package main

import (
	"crypto/aes"
	"fmt"
	"net"

	"encoding/hex"
)

type encryptionKey [16]byte

// authEncryptionKey computes the authorization encryption key.
func authEncryptionKey(name, password string) encryptionKey {
	byteName := [16]byte{}
	bytePass := [16]byte{}

	copy(byteName[:], name)
	copy(bytePass[:], password)

	key := encryptionKey{}
	for i := range byteName {
		key[i] = byteName[i] ^ bytePass[i]
	}

	return key
}

// encryptData enctypts a byte array given some encryption key.
func encryptData(key encryptionKey, data []byte) ([]byte, error) {
	reversedKey := byteReverse([]byte(key[:]))

	block, err := aes.NewCipher(reversedKey)
	if err != nil {
		return nil, err
	}

	bs := block.BlockSize()

	if len(data)%bs != 0 {
		return nil, fmt.Errorf("Data must be a multiple of the block size")
	}

	// We use AES ECB to encrypt the (reversed) data using the (reversed) key.
	// Golang does not provide the ECB mode of operation in the crypto/aes
	// package, however it is trivially implemented here.

	dataLen := len(data)
	reversedData := byteReverse(data)
	cipheredData := make([]byte, dataLen)

	for len(reversedData) > 0 {
		block.Encrypt(cipheredData[dataLen-len(reversedData):], reversedData)
		reversedData = reversedData[bs:]
	}

	cipheredData = byteReverse(cipheredData)

	return cipheredData, nil
}

type LampLink struct {
	MacAddress  net.HardwareAddr
	SecretKey   encryptionKey
	PacketCount uint16
}

func (b *LampLink) Connect(name, password string) error {
	// Open bluetooth connection here
	// ...

	// The handshake starts by encrypting the authentication key using this
	// initialization key.
	initKey := encryptionKey{0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0}
	authKey := authEncryptionKey(name, password)

	encryptedAuthKey, err := encryptData(initKey, []byte(authKey[:]))
	if err != nil {
		return err
	}

	// prepare the authentication packet to be sent to the device
	authPacket := []byte{0x0c}
	authPacket = append(authPacket, initKey[:8]...)
	authPacket = append(authPacket, encryptedAuthKey[:8]...)

	fmt.Println(hex.Dump(authPacket))

	// Send encrypted auth key over bluetooth here
	// ...
	authResponse := []byte{11, 13, 118, 59, 63, 64, 156, 169, 207, 198, 199, 244, 211, 12, 123, 128, 9, 216}

	// Calculate the secret key using the initKey and auth response (???)
	encryptionData := append(initKey[:8], authResponse[2:10]...)
	secretKey, err := encryptData(authKey, encryptionData)
	if err != nil {
		return err
	}

	copy(b.SecretKey[:], secretKey)

	return nil
}

// ---------------

func main() {
	mac, err := net.ParseMAC("00:21:4d:03:07:43")
	if err != nil {
		return
	}

	b := LampLink{MacAddress: mac}

	b.Connect("Smart Light", "1325168889")
}
