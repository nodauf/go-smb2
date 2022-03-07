package ntlm

import (
	"bytes"
	"crypto/rc4"
	"errors"
	"unicode/utf16"

	"github.com/nodauf/go-smb2/internal/utf16le"
)

type Session struct {
	isClientSide bool

	user string

	negotiateFlags     uint32
	exportedSessionKey []byte
	clientSigningKey   []byte
	serverSigningKey   []byte

	clientHandle *rc4.Cipher
	serverHandle *rc4.Cipher

	infoMap           map[uint16][]byte
	ntlmTargetInfoMap map[string]string
}

func (s *Session) User() string {
	return s.user
}

func (s *Session) SessionKey() []byte {
	return s.exportedSessionKey
}

type InfoMap struct {
	NbComputerName  string
	NbDomainName    string
	DnsComputerName string
	DnsDomainName   string
	DnsTreeName     string
	// Flags           uint32
	// Timestamp       time.Time
	// SingleHost
	// TargetName string
	// ChannelBindings
}

// TODO export to somewhere
func (s *Session) InfoMap() *InfoMap {
	return &InfoMap{
		NbComputerName:  utf16le.DecodeToString(s.infoMap[MsvAvNbComputerName]),
		NbDomainName:    utf16le.DecodeToString(s.infoMap[MsvAvNbDomainName]),
		DnsComputerName: utf16le.DecodeToString(s.infoMap[MsvAvDnsComputerName]),
		DnsDomainName:   utf16le.DecodeToString(s.infoMap[MsvAvDnsDomainName]),
		DnsTreeName:     utf16le.DecodeToString(s.infoMap[MsvAvDnsTreeName]),
		// Flags:           le.Uint32(s.infoMap[MsvAvFlags]),
	}
}

func (s *Session) Overhead() int {
	return 16
}

func (s *Session) Sum(plaintext []byte, seqNum uint32) ([]byte, uint32) {
	if s.negotiateFlags&NTLMSSP_NEGOTIATE_SIGN == 0 {
		return nil, 0
	}

	if s.isClientSide {
		return mac(nil, s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
	}
	return mac(nil, s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
}

func (s *Session) CheckSum(sum, plaintext []byte, seqNum uint32) (bool, uint32) {
	if s.negotiateFlags&NTLMSSP_NEGOTIATE_SIGN == 0 {
		if sum == nil {
			return true, 0
		}
		return false, 0
	}

	if s.isClientSide {
		ret, seqNum := mac(nil, s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
		if !bytes.Equal(sum, ret) {
			return false, 0
		}
		return true, seqNum
	}
	ret, seqNum := mac(nil, s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
	if !bytes.Equal(sum, ret) {
		return false, 0
	}
	return true, seqNum
}

func (s *Session) Seal(dst, plaintext []byte, seqNum uint32) ([]byte, uint32) {
	ret, ciphertext := sliceForAppend(dst, len(plaintext)+16)

	switch {
	case s.negotiateFlags&NTLMSSP_NEGOTIATE_SEAL != 0:
		s.clientHandle.XORKeyStream(ciphertext[16:], plaintext)

		if s.isClientSide {
			_, seqNum = mac(ciphertext[:0], s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
		} else {
			_, seqNum = mac(ciphertext[:0], s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
		}
	case s.negotiateFlags&NTLMSSP_NEGOTIATE_SIGN != 0:
		copy(ciphertext[16:], plaintext)

		if s.isClientSide {
			_, seqNum = mac(ciphertext[:0], s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
		} else {
			_, seqNum = mac(ciphertext[:0], s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
		}
	}

	return ret, seqNum
}

func (s *Session) Unseal(dst, ciphertext []byte, seqNum uint32) ([]byte, uint32, error) {
	ret, plaintext := sliceForAppend(dst, len(ciphertext)-16)

	switch {
	case s.negotiateFlags&NTLMSSP_NEGOTIATE_SEAL != 0:
		s.serverHandle.XORKeyStream(plaintext, ciphertext[16:])

		var sum []byte

		if s.isClientSide {
			sum, seqNum = mac(nil, s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
		} else {
			sum, seqNum = mac(nil, s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
		}
		if !bytes.Equal(ciphertext[:16], sum) {
			return nil, 0, errors.New("signature mismatch")
		}
	case s.negotiateFlags&NTLMSSP_NEGOTIATE_SIGN != 0:
		copy(plaintext, ciphertext[16:])

		var sum []byte

		if s.isClientSide {
			sum, seqNum = mac(nil, s.negotiateFlags, s.serverHandle, s.serverSigningKey, seqNum, plaintext)
		} else {
			sum, seqNum = mac(nil, s.negotiateFlags, s.clientHandle, s.clientSigningKey, seqNum, plaintext)
		}
		if !bytes.Equal(ciphertext[:16], sum) {
			return nil, 0, errors.New("signature mismatch")
		}
	default:
		copy(plaintext, ciphertext[16:])
		for _, s := range ciphertext[:16] {
			if s != 0x0 {
				return nil, 0, errors.New("signature mismatch")
			}
		}
	}

	return ret, seqNum, nil
}

// ref: http://davenport.sourceforge.net/ntlm.html#type2MessageExample
func (s *Session) setTargetInfo(targetInfoEncoder *targetInfoEncoder) {
	targetInfo := targetInfoEncoder.InfoMap

	s.ntlmTargetInfoMap = map[string]string{
		"ServerName":    UTF16BytesToString(targetInfo[1]),
		"DomainName":    UTF16BytesToString(targetInfo[2]),
		"DnsServerName": UTF16BytesToString(targetInfo[3]),
		"DnsDomainName": UTF16BytesToString(targetInfo[4]),
	}
}

// Credits: https://github.com/elastic/go-windows/blob/main/utf16.go

// NTLMTargetInfoMap returns a map[string]string of target information gathered from NTLMSSP negotiation
func (s *Session) NTLMTargetInfoMap() map[string]string {
	return s.ntlmTargetInfoMap
}

// indexNullTerminator returns the index of a null terminator within a buffer
// containing UTF-16 encoded data. If the null terminator is not found -1 is
// returned.
func indexNullTerminator(b []byte) int {
	if len(b) < 2 {
		return -1
	}

	for i := 0; i < len(b); i += 2 {
		if b[i] == 0 && b[i+1] == 0 {
			return i
		}
	}

	return -1
}

// UTF16BytesToString returns a string that is decoded from the UTF-16 bytes.
// The byte slice must be of even length otherwise an error will be returned.
// The integer returned is the offset to the start of the next string with
// buffer if it exists, otherwise -1 is returned.
func UTF16BytesToString(b []byte) string {
	if len(b)%2 != 0 {
		return "" //, 0, fmt.Errorf("Slice must have an even length (length=%d)", len(b))
	}

	/*offset := -1

	// Find the null terminator if it exists and re-slice the b.
	if nullIndex := indexNullTerminator(b); nullIndex > -1 {
		if len(b) > nullIndex+2 {
			offset = nullIndex + 2
		}

		b = b[:nullIndex]
	}*/

	s := make([]uint16, len(b)/2)
	for i := range s {
		s[i] = uint16(b[i*2]) + uint16(b[(i*2)+1])<<8
	}

	return string(utf16.Decode(s))
}
