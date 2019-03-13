package main

import (
        "crypto/rand"
        "crypto/rsa"
        "crypto/x509"
        "encoding/pem"
        "fmt"
        "os"
        "strconv"
        "errors"
)

var (
        ENCRYPTION_CIPHERS map[string]x509.PEMCipher = map[string]x509.PEMCipher{
                "aes-256-CBC":x509.PEMCipherAES256,
                "aes-192-CBC":x509.PEMCipherAES192,
                "aes-128-CBC":x509.PEMCipherAES128,
                "3des":x509.PEMCipher3DES,
                "des":x509.PEMCipherDES}
)

// generate creates private and public keys pair based on the specified requirements, concatenate them and return as a string
// generate accepts the bitsize, cipher and passphrase to use for keypair creation. 
// The private key is left unencrypted if the passphrase is an empty string
func generate(bits int, cipher x509.PEMCipher, passPhrase string) (string, error) {
        // if fileInfo, statError := os.Stat(saveDir); os.IsExist(statError) {
        //         return nil,
        // }
        key, err := rsa.GenerateKey(rand.Reader, bits)
        if err != nil {
                return "", err
        }
       

        // Private key
        privBytes,byteErr := x509.MarshalPKCS8PrivateKey(key)
        if byteErr != nil{
                return "", byteErr
        }
        block := &pem.Block{
                Type:  "RSA PRIVATE KEY",
                Bytes: privBytes,
        }

        if passPhrase != "" {
                var encryptErr error
                block, encryptErr = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(passPhrase), cipher)
                if encryptErr != nil {
                        return "", encryptErr
                }
        }

        // Public key
        pubBlock := &pem.Block{
                Type: "RSA PUBLIC KEY",
                Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey),
        }

        result := string(pem.EncodeToMemory(block))+string(pem.EncodeToMemory(pubBlock))
        if result == "" {
                return "", errors.New("Failed to create keypair!")
        }
        return result,nil

}

func main() {
        args := os.Args[1:]
        if len(args) < 2 {
                fmt.Println("You should provide at least 2 argument(s).")
                os.Exit(1)
        }

        bitSize, convErr := strconv.Atoi(args[0])
        if convErr != nil {
                bitSize = 2048
        }
        cipher,exists := ENCRYPTION_CIPHERS[args[1]]
        if !exists {
                cipher = x509.PEMCipherAES256
        }

        var passPhrase string
        if len(args) > 2 {
                passPhrase = args[2]
        } else {
                passPhrase = ""
        }
        key, err := generate(bitSize, cipher, passPhrase)
        if err != nil {
                fmt.Println("Fatal error: ", err.Error())
                os.Exit(1)
        }
        result := key
        fmt.Print(result)
}