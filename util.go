package main

func byteReverse(bytes []byte) []byte {
	reverse := make([]byte, len(bytes))
	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		reverse[i], reverse[j] = bytes[j], bytes[i]
	}

	return reverse
}
