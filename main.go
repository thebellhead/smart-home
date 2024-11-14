package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"unicode"
)

type CMD byte
type DEVTYPE byte

const (
	TOALL     int     = 0x3FFF
	HUBNAME   string  = "HUB01"
	HOST      string  = "localhost"
	PORT      string  = "9998"
	TYPE      string  = "http"
	WHOISHERE CMD     = 0x01
	IAMHERE   CMD     = 0x02
	GETSTATUS CMD     = 0x03
	STATUS    CMD     = 0x04
	SETSTATUS CMD     = 0x05
	TICK      CMD     = 0x06
	HUB       DEVTYPE = 0x01
	SENSOR    DEVTYPE = 0x02
	SWITCH    DEVTYPE = 0x03
	LAMP      DEVTYPE = 0x04
	SOCKET    DEVTYPE = 0x05
	CLOCK     DEVTYPE = 0x06
)

type Byter interface {
	ToBytes() []byte
}

type Packets []Packet

func (pcts Packets) ToBytes() []byte {
	byteArr := make([]byte, 0)
	for _, pct := range pcts {
		byteArr = append(byteArr, pct.ToBytes()...)
	}
	return byteArr
}

func packetsFromBytes(bytes []byte) *Packets {
	n := len(bytes)
	skip := 0
	var pcts Packets
	for skip < n {
		curPacket, newSkip := packetFromBytes(bytes[skip:])
		skip += newSkip
		pcts = append(pcts, *curPacket)
	}
	return &pcts
}

type Packet struct {
	Length  byte    `json:"length"`
	Payload Payload `json:"payload"`
	Crc8    byte    `json:"crc8"`
}

func (pct Packet) ToBytes() []byte {
	byteArr := make([]byte, 0)
	byteArr = append(byteArr, pct.Length)
	byteArr = append(byteArr, pct.Payload.ToBytes()...)
	byteArr = append(byteArr, pct.Crc8)
	return byteArr
}

func packetFromBytes(bytes []byte) (*Packet, int) {
	payloadLength := bytes[0]
	payload := bytes[1 : payloadLength+1]
	crc8 := bytes[payloadLength+1]
	crc8comp := computeCRC8(payload)
	if crc8 != crc8comp {
		log.Fatal("control sums unequal")
	}
	pld := payloadFromBytes(payload)
	pct := Packet{
		Length:  payloadLength,
		Payload: *pld,
		Crc8:    crc8,
	}
	return &pct, int(payloadLength) + 2
}

type Payload struct {
	Src     int     `json:"src"`
	Dst     int     `json:"dst"`
	Serial  int     `json:"serial"`
	DevType DEVTYPE `json:"dev_type"`
	Cmd     CMD     `json:"cmd"`
	CmdBody Byter   `json:"cmd_body,omitempty"`
}

func (pld Payload) ToBytes() []byte {
	byteArr := make([]byte, 0)
	byteArr = append(byteArr, encodeULEB128(pld.Src)...)
	byteArr = append(byteArr, encodeULEB128(pld.Dst)...)
	byteArr = append(byteArr, encodeULEB128(pld.Serial)...)
	byteArr = append(byteArr, []byte{byte(pld.DevType), byte(pld.Cmd)}...)
	if pld.CmdBody != nil {
		byteArr = append(byteArr, (pld.CmdBody).ToBytes()...)
	}
	return byteArr
}

type CmdBodyName struct {
	DevName string `json:"dev_name"`
}

func (cbn CmdBodyName) ToBytes() []byte {
	byteArr := []byte{byte(len(cbn.DevName))}
	return append(byteArr, []byte(cbn.DevName)...)
}

type Trigger struct {
	Op    byte   `json:"op"`
	Value int    `json:"value"`
	Name  string `json:"name"`
}

type EnvSensorProps struct {
	Sensors  byte      `json:"sensors"`
	Triggers []Trigger `json:"triggers"`
}

type CmdBodySensors struct {
	DevName  string         `json:"dev_name"`
	DevProps EnvSensorProps `json:"dev_props"`
}

func (cbn CmdBodySensors) ToBytes() []byte {
	nameLen := byte(len(cbn.DevName))
	name := []byte(cbn.DevName)
	sensors := cbn.DevProps.Sensors
	triggerLen := len(cbn.DevProps.Triggers)
	byteArr := []byte{nameLen}
	byteArr = append(byteArr, name...)
	byteArr = append(byteArr, []byte{sensors, byte(triggerLen)}...)
	for i := 0; i < triggerLen; i++ {
		curBytes := []byte{cbn.DevProps.Triggers[i].Op}
		curBytes = append(curBytes, encodeULEB128(cbn.DevProps.Triggers[i].Value)...)
		curBytes = append(curBytes, byte(len(cbn.DevProps.Triggers[i].Name)))
		curBytes = append(curBytes, []byte(cbn.DevProps.Triggers[i].Name)...)
		byteArr = append(byteArr, curBytes...)
	}
	return byteArr
}

type CmdBodySensor struct {
	Values []int `json:"values"`
}

func (cbs CmdBodySensor) ToBytes() []byte {
	byteArrLen := byte(len(cbs.Values))
	byteArr := []byte{byteArrLen}
	for _, val := range cbs.Values {
		byteArr = append(byteArr, encodeULEB128(val)...)
	}
	return byteArr
}

type CmdBodySwitch struct {
	DevName  string   `json:"dev_name"`
	DevProps DevProps `json:"dev_props"`
}

type DevProps struct {
	DevNames []string `json:"dev_names"`
}

func (cbs CmdBodySwitch) ToBytes() []byte {
	devNameLen := byte(len(cbs.DevName))
	devName := []byte(cbs.DevName)
	devPropsLen := byte(len(cbs.DevProps.DevNames))
	byteArr := []byte{devNameLen}
	byteArr = append(byteArr, devName...)
	byteArr = append(byteArr, devPropsLen)
	for _, curDevName := range cbs.DevProps.DevNames {
		curDevNameLen := byte(len(curDevName))
		byteArr = append(byteArr, curDevNameLen)
		byteArr = append(byteArr, []byte(curDevName)...)
	}
	return byteArr
}

type CmdBodyValue struct {
	Value byte `json:"value"`
}

func (cbv CmdBodyValue) ToBytes() []byte {
	return []byte{cbv.Value}
}

type CmdBodyTimestamp struct {
	Timestamp int `json:"timestamp"`
}

func (cbt CmdBodyTimestamp) ToBytes() []byte {
	return encodeULEB128(cbt.Timestamp)
}

func parseCmdBody(device DEVTYPE, cmd CMD, cmdBodyBytes []byte) Byter {
	switch {
	case (device == HUB || device == SOCKET || device == LAMP || device == CLOCK) &&
		(cmd == WHOISHERE || cmd == IAMHERE):
		nameLength := cmdBodyBytes[0]
		name := cmdBodyBytes[1 : nameLength+1]
		return CmdBodyName{string(name)}
	case device == SENSOR && (cmd == WHOISHERE || cmd == IAMHERE):
		nameLength := cmdBodyBytes[0]
		name := cmdBodyBytes[1 : nameLength+1]
		sensors := cmdBodyBytes[nameLength+1]
		triggerLength := cmdBodyBytes[nameLength+2]
		triggers := make([]Trigger, triggerLength)
		curSkip := int(nameLength) + 3
		for i := 0; i < int(triggerLength); i++ {
			curOp := cmdBodyBytes[curSkip]
			curSkip++
			curVal, skipULEB := decodeULEB128(cmdBodyBytes[curSkip:])
			curNameLen := cmdBodyBytes[curSkip+skipULEB]
			curName := string(cmdBodyBytes[curSkip+skipULEB+1 : curSkip+skipULEB+1+int(curNameLen)])
			curSkip += skipULEB + int(curNameLen) + 1
			curTrigger := Trigger{
				Op:    curOp,
				Value: curVal,
				Name:  curName,
			}
			triggers[i] = curTrigger
		}
		return CmdBodySensors{
			DevName: string(name),
			DevProps: EnvSensorProps{
				Sensors:  sensors,
				Triggers: triggers,
			},
		}
	case cmd == GETSTATUS && (device == SENSOR || device == SWITCH || device == LAMP || device == SOCKET):
		return nil
	case device == SENSOR && cmd == STATUS:
		valuesSize := int(cmdBodyBytes[0])
		values := make([]int, valuesSize)
		curSkip := 1
		for i := 0; i < valuesSize; i++ {
			curVal, skipULEB := decodeULEB128(cmdBodyBytes[curSkip:])
			values[i] = curVal
			curSkip += skipULEB
		}
		return CmdBodySensor{Values: values}
	case device == SWITCH && (cmd == WHOISHERE || cmd == IAMHERE):
		nameLength := cmdBodyBytes[0]
		name := cmdBodyBytes[1 : nameLength+1]
		devNamesLen := int(cmdBodyBytes[nameLength+1])
		devNames := make([]string, devNamesLen)
		curSkip := nameLength + 2
		for i := 0; i < devNamesLen; i++ {
			curNameLen := cmdBodyBytes[curSkip]
			curName := cmdBodyBytes[curSkip+1 : curSkip+1+curNameLen]
			devNames[i] = string(curName)
			curSkip += curNameLen + 1
		}
		return CmdBodySwitch{
			DevName:  string(name),
			DevProps: DevProps{DevNames: devNames},
		}
	case (cmd == STATUS && (device == SWITCH || device == LAMP || device == SOCKET)) ||
		(cmd == SETSTATUS && (device == LAMP || device == SOCKET)):
		value := cmdBodyBytes[0]
		return CmdBodyValue{Value: value}
	case device == CLOCK && cmd == TICK:
		timestamp, _ := decodeULEB128(cmdBodyBytes[:])
		return CmdBodyTimestamp{Timestamp: timestamp}
	}
	return nil
}

func payloadFromBytes(bytes []byte) *Payload {
	srcULEB, skip1 := decodeULEB128(bytes)
	dstULEB, skip2 := decodeULEB128(bytes[skip1:])
	serialULEB, skip3 := decodeULEB128(bytes[skip1+skip2:])
	skip := skip1 + skip2 + skip3
	pld := Payload{
		Src:     srcULEB,
		Dst:     dstULEB,
		Serial:  serialULEB,
		DevType: DEVTYPE(bytes[skip]),
		Cmd:     CMD(bytes[skip+1]),
		CmdBody: nil,
	}

	cmdBodyBytes := bytes[skip+2:]
	cmdParsed := parseCmdBody(pld.DevType, pld.Cmd, cmdBodyBytes)
	if cmdParsed != nil {
		pld.CmdBody = cmdParsed
	}
	return &pld
}

func getConStr(commUrl string) string {
	if commUrl == "" {
		return fmt.Sprintf("%s://%s:%s", TYPE, HOST, PORT)
	} else {
		return fmt.Sprintf(commUrl)
	}
}

func encodeULEB128(value int) []byte {
	var res []byte
	for {
		bt := byte(value & 0x7f)
		value >>= 7
		if value != 0 {
			bt |= 0x80
		}
		res = append(res, bt)
		if value == 0 {
			break
		}
	}
	return res
}

func decodeULEB128(bytes []byte) (int, int) {
	res := 0
	shift := 0
	bytesParsed := 0
	for _, bt := range bytes {
		bytesParsed++
		res |= (int(bt) & 0x7f) << shift
		shift += 7
		if bt&0x80 == 0 {
			break
		}
	}
	return res, bytesParsed
}

func computeCRC8(bytes []byte) byte {
	const mask byte = 0x1D
	crc8 := byte(0)
	for _, curByte := range bytes {
		crc8 ^= curByte
		for i := 0; i < 8; i++ {
			if (crc8 & 0x80) != 0 {
				crc8 = (crc8 << 1) ^ mask
			} else {
				crc8 <<= 1
			}
		}
	}
	return crc8
}

func requestServer(commUrl, reqString string) ([]byte, int, error) {
	client := &http.Client{}
	req := new(http.Request)
	var err error
	if reqString == "" {
		req, err = http.NewRequest(
			http.MethodPost, getConStr(commUrl), nil,
		)
	} else {
		req, err = http.NewRequest(
			http.MethodPost, getConStr(commUrl), strings.NewReader(reqString),
		)
	}
	if err != nil {
		return []byte{}, http.StatusBadRequest, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, http.StatusBadRequest, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	code := resp.StatusCode
	if err != nil {
		return []byte{}, http.StatusBadRequest, err
	}
	return body, code, nil
}

func removeSpaces(str string) string {
	var b strings.Builder
	b.Grow(len(str))
	for _, ch := range str {
		if !unicode.IsSpace(ch) {
			b.WriteRune(ch)
		}
	}
	return b.String()
}

type Device struct {
	Address      int       `json:"address"`
	DevName      string    `json:"dev_name"`
	DevType      DEVTYPE   `json:"dev_type"`
	IsOn         bool      `json:"status"`
	IsPresent    bool      `json:"is_present"`
	ConnDevs     []string  `json:"conn_devs"`
	SensorValues []int     `json:"sensor_values"`
	Sensors      byte      `json:"sensors"`
	Triggers     []Trigger `json:"triggers"`
	AnswerTime   int       `json:"answer_time"`
}

func findTime(pcts *Packets) int {
	for _, pct := range *pcts {
		if pct.Payload.DevType == CLOCK && pct.Payload.Cmd == TICK {
			clockBody := pct.Payload.CmdBody.(CmdBodyTimestamp)
			return clockBody.Timestamp
		}
	}
	return -1
}

func setState(pcts *Packets, database map[int]*Device, devs []string, state byte, src int, serial *int) {
	for _, item := range database {
		name := item.DevName
		for _, dev := range devs {
			if name == dev {
				var cmdBody Byter = CmdBodyValue{Value: state}
				newPacket := Packet{
					Length: 0,
					Payload: Payload{
						Src:     src,
						Dst:     item.Address,
						Serial:  *serial,
						DevType: item.DevType,
						Cmd:     SETSTATUS,
						CmdBody: cmdBody,
					},
					Crc8: 0,
				}
				*serial++
				newPacket.Crc8 = computeCRC8(newPacket.Payload.ToBytes())
				newPacket.Length = byte(len(newPacket.Payload.ToBytes()))
				*pcts = append(*pcts, newPacket)
				break
			}
		}
	}
}

func pingSwitches(pcts *Packets, database map[int]*Device, src int, serial *int) {
	for _, dev := range database {
		if dev.DevType == SWITCH && dev.IsPresent {
			newPacket := Packet{
				Length: 0,
				Payload: Payload{
					Src:     src,
					Dst:     dev.Address,
					Serial:  *serial,
					DevType: HUB,
					Cmd:     GETSTATUS,
					CmdBody: nil,
				},
				Crc8: 0,
			}
			*serial++
			newPacket.Crc8 = computeCRC8(newPacket.Payload.ToBytes())
			newPacket.Length = byte(len(newPacket.Payload.ToBytes()))
			*pcts = append(*pcts, newPacket)
		}
	}
}

func handleResponse(database map[int]*Device, requestTimes map[int][]int, pcts, tasks *Packets, src int, serial *int) {
	answerTime := findTime(pcts)
	for _, pct := range *pcts {
		val, ok := database[pct.Payload.Src]
		if ok && !val.IsPresent && pct.Payload.Cmd != WHOISHERE {
			continue
		}
		switch pct.Payload.Cmd {
		case IAMHERE:
			dvt := pct.Payload.DevType
			adr := pct.Payload.Src
			isAlive := answerTime-requestTimes[TOALL][0] <= 300
			switch {
			case dvt == SWITCH:
				body := pct.Payload.CmdBody.(CmdBodySwitch)
				database[adr] = &Device{
					Address:      adr,
					DevName:      body.DevName,
					DevType:      pct.Payload.DevType,
					IsOn:         false, // We ping switches every iteration
					IsPresent:    isAlive,
					ConnDevs:     body.DevProps.DevNames,
					SensorValues: nil,
					Sensors:      0,
					Triggers:     nil,
					AnswerTime:   answerTime,
				}
			case dvt == SENSOR:
				body := pct.Payload.CmdBody.(CmdBodySensors)
				database[adr] = &Device{
					Address:      adr,
					DevName:      body.DevName,
					DevType:      pct.Payload.DevType,
					IsOn:         false, // Sensors don't use IsOn
					IsPresent:    isAlive,
					ConnDevs:     nil,
					SensorValues: nil,
					Sensors:      body.DevProps.Sensors,
					Triggers:     body.DevProps.Triggers,
					AnswerTime:   answerTime,
				}
			default:
				body := pct.Payload.CmdBody.(CmdBodyName)
				database[adr] = &Device{
					Address:      adr,
					DevName:      body.DevName,
					DevType:      pct.Payload.DevType,
					IsOn:         false,
					IsPresent:    isAlive,
					ConnDevs:     nil,
					SensorValues: nil,
					Sensors:      0,
					Triggers:     nil,
					AnswerTime:   answerTime,
				}
			}
		case WHOISHERE:
			var cmdBody Byter = CmdBodyName{DevName: HUBNAME}
			newPacket := Packet{
				Length: 0,
				Payload: Payload{
					Src:     src,
					Dst:     TOALL,
					Serial:  *serial,
					DevType: HUB,
					Cmd:     IAMHERE,
					CmdBody: cmdBody,
				},
				Crc8: 0,
			}
			*serial++
			newPacket.Crc8 = computeCRC8(newPacket.Payload.ToBytes())
			newPacket.Length = byte(len(newPacket.Payload.ToBytes()))
			*tasks = append(*tasks, newPacket)

			dvt := pct.Payload.DevType
			adr := pct.Payload.Src
			switch {
			case dvt == SWITCH:
				body := pct.Payload.CmdBody.(CmdBodySwitch)
				database[adr] = &Device{
					Address:      adr,
					DevName:      body.DevName,
					DevType:      pct.Payload.DevType,
					IsOn:         false, // We ping switches every iteration
					IsPresent:    true,
					ConnDevs:     body.DevProps.DevNames,
					SensorValues: nil,
					Sensors:      0,
					Triggers:     nil,
					AnswerTime:   answerTime,
				}
			case dvt == SENSOR:
				body := pct.Payload.CmdBody.(CmdBodySensors)
				database[adr] = &Device{
					Address:      adr,
					DevName:      body.DevName,
					DevType:      pct.Payload.DevType,
					IsOn:         false, // Sensors don't use IsOn
					IsPresent:    true,
					ConnDevs:     nil,
					SensorValues: nil,
					Sensors:      body.DevProps.Sensors,
					Triggers:     body.DevProps.Triggers,
					AnswerTime:   answerTime,
				}
			default:
				body := pct.Payload.CmdBody.(CmdBodyName)
				database[adr] = &Device{
					Address:      adr,
					DevName:      body.DevName,
					DevType:      pct.Payload.DevType,
					IsOn:         false, // --||--
					IsPresent:    true,
					ConnDevs:     nil,
					SensorValues: nil,
					Sensors:      0,
					Triggers:     nil,
					AnswerTime:   answerTime,
				}
			}
		case STATUS:
			if pct.Payload.Src != TOALL {
				if len(requestTimes[pct.Payload.Src]) >= 2 {
					requestTimes[pct.Payload.Src] = requestTimes[pct.Payload.Src][1:]
				} else {
					delete(requestTimes, pct.Payload.Src)
				}
			}
			switch pct.Payload.DevType {
			case LAMP:
				cbv := pct.Payload.CmdBody.(CmdBodyValue)
				if cbv.Value == 1 {
					database[pct.Payload.Src].IsOn = true
				} else {
					database[pct.Payload.Src].IsOn = false
				}
			case SOCKET:
				cbv := pct.Payload.CmdBody.(CmdBodyValue)
				if cbv.Value == 1 {
					database[pct.Payload.Src].IsOn = true
				} else {
					database[pct.Payload.Src].IsOn = false
				}
			case SWITCH:
				cbv := pct.Payload.CmdBody.(CmdBodyValue)
				switch cbv.Value {
				case 1:
					database[pct.Payload.Src].IsOn = true
					devNames2TurnOn := database[pct.Payload.Src].ConnDevs
					setState(tasks, database, devNames2TurnOn, 1, src, serial)
				default:
					database[pct.Payload.Src].IsOn = false
					devNames2TurnOff := database[pct.Payload.Src].ConnDevs
					setState(tasks, database, devNames2TurnOff, 0, src, serial)
				}
			case SENSOR:
				values := pct.Payload.CmdBody.(CmdBodySensor).Values
				database[pct.Payload.Src].SensorValues = values // Update DB
				valuesAll := [4]int{-1, -1, -1, -1}
				envSensor := database[pct.Payload.Src]
				sensorTypeMask := envSensor.Sensors
				idx := 0
				for i := 0; i < 4; i++ {
					if sensorTypeMask&1 == 1 {
						valuesAll[i] = values[idx]
						idx++
					}
					sensorTypeMask = sensorTypeMask >> 1
				}
				triggers := envSensor.Triggers
				for _, trigger := range triggers {
					thresh := trigger.Value
					device := trigger.Name
					opBits := trigger.Op

					state := opBits & 1
					opBits = opBits >> 1
					greaterThen := opBits & 1
					opBits = opBits >> 1
					sensorType := opBits

					if greaterThen == 1 {
						// >
						if valuesAll[sensorType] > thresh {
							setState(tasks, database, []string{device}, state, src, serial)
						}
					} else {
						// <
						if valuesAll[sensorType] < thresh && valuesAll[sensorType] != -1 {
							setState(tasks, database, []string{device}, state, src, serial)
						}
					}
				}
			}
		}
	}
}

func main() {
	args := os.Args[1:]
	if len(args) < 2 {
		os.Exit(99)
	}
	commUrl := args[0]
	hubAddress, err := strconv.ParseInt(args[1], 16, 64)
	if err != nil {
		os.Exit(99)
	}

	database := make(map[int]*Device)   // ADDRESS -> Device
	requestTimes := make(map[int][]int) // ADDRESS -> Timestamp

	serialCounter := 1
	var statusCode int
	var reqStr string
	var respRawBytes, respRawBytesTrimmed, respBytes []byte

	pendingTasks := Packets{} // Packets of all GETSTATUS, SETSTATUS and IAMHERE requests to be done
	var hubTime int

	// NETWORK STRUCTURE WITH WHOISHERE from HUB01
	for {
		var cbn Byter = CmdBodyName{DevName: HUBNAME}
		pcts := Packets{
			Packet{
				Length: 0,
				Payload: Payload{
					Src:     int(hubAddress),
					Dst:     TOALL,
					Serial:  serialCounter,
					DevType: HUB,
					Cmd:     WHOISHERE,
					CmdBody: cbn,
				},
				Crc8: 0,
			},
		}
		serialCounter++
		pcts[0].Length = byte(len(pcts[0].Payload.ToBytes()))
		pcts[0].Crc8 = computeCRC8(pcts[0].Payload.ToBytes())
		reqStr = base64.RawURLEncoding.EncodeToString(pcts.ToBytes())
		respRawBytes, statusCode, err = requestServer(commUrl, reqStr)
		if err != nil {
			os.Exit(99)
		}

		if statusCode == http.StatusOK {
			respRawBytesTrimmed = []byte(removeSpaces(string(respRawBytes))) // Whitespace removal
			respBytes, err = base64.RawURLEncoding.DecodeString(string(respRawBytesTrimmed))
			if err != nil {
				continue
			}
			respPcts := packetsFromBytes(respBytes)
			hubTime = findTime(respPcts)
			requestTimes[TOALL] = []int{hubTime}
			handleResponse(database, requestTimes, respPcts, &pendingTasks, int(hubAddress), &serialCounter)
			for _, dev := range database {
				dev.IsPresent = true
			}
			break
		} else if statusCode == http.StatusNoContent {
			os.Exit(0)
		} else {
			os.Exit(99)
		}
	}

	// POST GETSTATUS TO ALL SENSORS
	for _, dev := range database {
		if dev.DevType == SENSOR {
			getStatusReq := Packet{
				Length: 0,
				Payload: Payload{
					Src:     int(hubAddress),
					Dst:     dev.Address,
					Serial:  serialCounter,
					DevType: HUB,
					Cmd:     GETSTATUS,
					CmdBody: nil,
				},
				Crc8: 0,
			}
			serialCounter++
			getStatusReq.Length = byte(len(getStatusReq.Payload.ToBytes()))
			getStatusReq.Crc8 = computeCRC8(getStatusReq.Payload.ToBytes())
			pendingTasks = append(pendingTasks, getStatusReq)
		}
	}

	// MAINTAIN SYSTEM UNTIL CODE 204 OR HTTP ERROR
	for statusCode == http.StatusOK {
		pingSwitches(&pendingTasks, database, int(hubAddress), &serialCounter)
		for _, pct := range pendingTasks {
			curCmd := pct.Payload.Cmd
			curDst := pct.Payload.Dst
			if curCmd == GETSTATUS || curCmd == SETSTATUS {
				requestTimes[curDst] = append(requestTimes[curDst], hubTime)
			}
		}
		reqStr = base64.RawURLEncoding.EncodeToString(pendingTasks.ToBytes())
		pendingTasks = Packets{}

		respRawBytes, statusCode, err = requestServer(commUrl, reqStr)

		if err != nil {
			os.Exit(99)
		}
		respRawBytesTrimmed = []byte(removeSpaces(string(respRawBytes))) // Whitespace removal
		respBytes, err = base64.RawURLEncoding.DecodeString(string(respRawBytesTrimmed))
		if err != nil {
			continue
		}

		respPcts := packetsFromBytes(respBytes)
		//fmt.Printf("%+v\n", respPcts)
		hubTime = findTime(respPcts) // Update global time

		for address, timeQueue := range requestTimes {
			if hubTime-timeQueue[0] > 300 {
				if _, ok := database[address]; ok {
					database[address].IsPresent = false
				}
				delete(requestTimes, address)
			}
		}

		handleResponse(database, requestTimes, respPcts, &pendingTasks, int(hubAddress), &serialCounter)
	}

	if statusCode == http.StatusNoContent {
		os.Exit(0)
	}
	os.Exit(99)
}
