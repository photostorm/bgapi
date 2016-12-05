// this code is largely based on Michael Brown's excellent Python API
// https://github.com/mjbrown/bgapi

package bgapi

import (
	"bytes"
	"errors"
	"time"
)

// FIXME JS -- we need to workout timeouts for global funcs
// FIXME JS -- we need to initialize data structures etc.
// FIXME JS -- we need to add getter/setter methods

const (
	gapFuncNone int = iota
	gapFuncScanning
)

const (
	// GapDiscoverLimited limitted discovery mode
	GapDiscoverLimited byte = iota
	// GapDiscoverGeneric generic discovery mode
	GapDiscoverGeneric
	// GapDiscoverObservation observation discovery mode
	GapDiscoverObservation
	// GapDiscoverModeMax max discovery mode
	GapDiscoverModeMax
)

const (
	// ConnectionStatusFlagConnected re-connected?
	ConnectionStatusFlagConnected = 1
	// ConnectionStatusFlagEncrypted encrypted
	ConnectionStatusFlagEncrypted = 2
	// ConnectionStatusFlagCompleted completed
	ConnectionStatusFlagCompleted = 4
	// ConnectionStatusFlagParametersChange changed the parameters
	ConnectionStatusFlagParametersChange = 8
)

/*
   dsef get_ad_type_string(self, type_ord):
       return {
           0x01: "BLE_GAP_AD_TYPE_FLAGS",
           0x02: "BLE_GAP_AD_TYPE_16BIT_SERVICE_UUID_MORE_AVAILABLE",
           0x03: "BLE_GAP_AD_TYPE_16BIT_SERVICE_UUID_COMPLETE",
           0x04: "BLE_GAP_AD_TYPE_32BIT_SERVICE_UUID_MORE_AVAILABLE",
           0x05: "BLE_GAP_AD_TYPE_32BIT_SERVICE_UUID_COMPLETE",
           0x06: "BLE_GAP_AD_TYPE_128BIT_SERVICE_UUID_MORE_AVAILABLE",
           0x07: "BLE_GAP_AD_TYPE_128BIT_SERVICE_UUID_COMPLETE",
           0x08: "BLE_GAP_AD_TYPE_SHORT_LOCAL_NAME",
           0x09: "BLE_GAP_AD_TYPE_COMPLETE_LOCAL_NAME",
           0x0A: "BLE_GAP_AD_TYPE_TX_POWER_LEVEL",
           0x0D: "BLE_GAP_AD_TYPE_CLASS_OF_DEVICE",
           0x0E: "BLE_GAP_AD_TYPE_SIMPLE_PAIRING_HASH_C",
           0x0F: "BLE_GAP_AD_TYPE_SIMPLE_PAIRING_RANDOMIZER_R",
           0x10: "BLE_GAP_AD_TYPE_SECURITY_MANAGER_TK_VALUE",
           0x11: "BLE_GAP_AD_TYPE_SECURITY_MANAGER_OOB_FLAGS",
           0x12: "BLE_GAP_AD_TYPE_SLAVE_CONNECTION_INTERVAL_RANGE",
           0x14: "BLE_GAP_AD_TYPE_SOLICITED_SERVICE_UUIDS_16BIT",
           0x15: "BLE_GAP_AD_TYPE_SOLICITED_SERVICE_UUIDS_128BIT",
           0x16: "BLE_GAP_AD_TYPE_SERVICE_DATA",
           0x17: "BLE_GAP_AD_TYPE_PUBLIC_TARGET_ADDRESS",
           0x18: "BLE_GAP_AD_TYPE_RANDOM_TARGET_ADDRESS",
           0x19: "BLE_GAP_AD_TYPE_APPEARANCE",
           0x1A: "BLE_GAP_AD_TYPE_ADVERTISING_INTERVAL",
           0x1B: "BLE_GAP_AD_TYPE_LE_BLUETOOTH_DEVICE_ADDRESS",
           0x1C: "BLE_GAP_AD_TYPE_LE_ROLE",
           0x1D: "BLE_GAP_AD_TYPE_SIMPLE_PAIRING_HASH_C256",
           0x1E: "BLE_GAP_AD_TYPE_SIMPLE_PAIRING_RANDOMIZER_R256",
           0x20: "BLE_GAP_AD_TYPE_SERVICE_DATA_32BIT_UUID",
           0x21: "BLE_GAP_AD_TYPE_SERVICE_DATA_128BIT_UUID",
           0x3D: "BLE_GAP_AD_TYPE_3D_INFORMATION_DATA",
           0xFF: "BLE_GAP_AD_TYPE_MANUFACTURER_SPECIFIC_DATA"
       }[type_ord]
*/

// CharacteristicUUID the characteristic UUID
var CharacteristicUUID = []byte{0x03, 0x28}

// ClientCharacteristicConfigUUID the client characteristic config
var ClientCharacteristicConfigUUID = []byte{0x02, 0x29}

// UserDescriptionUUID the user descript
var UserDescriptionUUID = []byte{0x01, 0x29}

// PrimaryServiceUUID used to lookup primary service
var PrimaryServiceUUID = []byte{0x00, 0x28}

// SecondaryServiceUUID used to lookup secondary service
var SecondaryServiceUUID = []byte{0x01, 0x28}

type apiDelegate struct {
	central *Central
}

// Central a base class that implements the central role
type Central struct {
	// NOTE: using a dedicated apiDelegate (as oposed to making the Central its own
	// apiDelegate) limits the scope of these methods
	apiDelegate      *apiDelegate
	api              *API
	gapFunc          int
	knownPeripherals map[string]*GapScanRespone

	// ScanInterval time from window to window
	ScanInterval uint16

	// ScanWindow time to allow devices to advertise
	ScanWindow uint16

	// existing connections
	openConnections map[byte]*Connection
	connections     map[string]*Connection
}

// AdvertisementData parsed advertisement data
type AdvertisementData map[byte][]byte

// ServiceUUIDs BLE variable length UUID list associated with a given service
type ServiceUUIDs [][]byte

func (c *Central) gapTake(gapFunc int) error {
	var err error
	if c.gapFunc == gapFuncNone {
		c.gapFunc = gapFunc
	} else {
		err = errors.New("GAP service already in use by another function")
	}
	return err
}

func (c *Central) gapGive(gapFunc int) error {
	var err error
	if c.gapFunc != gapFunc {
		err = errors.New("Attempt to release a GAP function not in use")
	} else {
		c.gapFunc = gapFuncNone
	}

	return err
}

// StartScanning start the scanning process
func (c *Central) StartScanning(mode byte) error {
	var err error
	if err = c.gapTake(gapFuncScanning); err == nil {
		c.api.GapDiscover(mode)
	}
	return err
}

// StopScanning stop the scanning function
func (c *Central) StopScanning() error {
	var err error
	if err = c.gapGive(gapFuncScanning); err == nil {
		c.api.GapEndProcedure()
	}

	return err
}

// ScanRequestEnable enable the transmission of ScanRequest packets
func (c *Central) ScanRequestEnable() {
	c.api.GapSetScanParameters(c.ScanInterval, c.ScanWindow, 1)
}

// ScanRequestDisable disable the transmission of ScanRequest packets
func (c *Central) ScanRequestDisable() {
	c.api.GapSetScanParameters(c.ScanInterval, c.ScanWindow, 0)
}

// StartScanBasic perform the most promiscuous scanning
func (c *Central) StartScanBasic() error {
	c.ScanRequestEnable()
	return c.StartScanning(GapDiscoverObservation)
}

// StopScanBasic stop promiscuous scanning
func (c *Central) StopScanBasic() error {
	c.ScanRequestDisable()
	return c.StopScanning()
}

//
// Connetion
//

const (
	connectionStateConnected int = iota
	connectionStateDisconnected
	connectionStateEncrypted
)

const (
	procedureTimeout int = iota
	procedureConnect
	procedureDisconnect
	procedureParamsUpdated
	procedureEncrypt
	procedureGeneral
	procedureReadAttribute
)

// ConnectionDelegate connection delegate to be implemented by client
type ConnectionDelegate interface {
	OnDisconnected(reason uint16)
}

// Attribute represents GATT Characteristic Attribute
type Attribute struct {
	handle         uint16
	value          []byte
	parse          func(data []byte)
	OnValueChanged func(data []byte)
}

// update the attribute
func (at *Attribute) update(value []byte) {
	at.value = value

	if at.parse != nil {
		at.parse(value)
	}

	if at.OnValueChanged != nil {
		at.OnValueChanged(value)
	}
}

// Characteristic represents a GATT Characteristic
type Characteristic struct {
	// FIXME we should probably also order these as a list
	attribs    map[string]*Attribute
	properties byte
}

// one UUID can have multiple handles,
func (c *Characteristic) addDescriptor(uuid []byte, handle uint16, value []byte) *Attribute {
	at := Attribute{handle: handle, value: value}

	// CharacteristicUUID the characteristic UUID
	if bytes.Equal(uuid, CharacteristicUUID) {
		at.parse = func(value []byte) {
			c.properties = value[0]
			//var handle uint16
			//buf := bytes.NewBuffer(value)
			//binary.Read(buf, binary.LittleEndian, c.properties)
			//binary.Read(buf, binary.LittleEndian, handle)
		}
	}

	//var ClientCharacteristicConfigUUID

	//var UserDescriptionUUID

	c.attribs[string(uuid)] = &at
	return &at
}

func (c *Characteristic) parseCharacteristicAttribute(value []byte) {
}

// Service GATTService
type Service struct {
	startHandle uint16
	endHandle   uint16
	uuid        []byte
}

type procedureManager struct {
	operC       chan int
	procPending int
}

// perform the procedure
func (mgr *procedureManager) perform(timeoutMs time.Duration, proc int, procedure func()) error {

	mgr.procPending = proc

	// FIXME need a way to extend timeout
	// start failsafe timer
	go func() {
		time.Sleep(timeoutMs * time.Millisecond)
		mgr.operC <- procedureTimeout
	}()

	// perform operation
	procedure()

	// wait for result
	result := <-mgr.operC

	// check to see if the operation completed successfully
	var err error
	if result == procedureTimeout {
		err = errors.New("Connection.Open timed-out")
	} else if result != proc {
		err = errors.New("Connection.Open handled wrong event type")
	}
	return err
}

// complete notify that the procedure completed
func (mgr *procedureManager) complete(proc int) {
	if mgr.procPending == proc {
		mgr.operC <- proc
	}
}

// Connection represents a connection to a peripheral
type Connection struct {
	resp            GapScanRespone
	params          ConnectionParameters
	status          ConnectionStatus
	central         *Central
	delegate        ConnectionDelegate
	services        map[uint16]*Service
	characteristics map[uint16]*Characteristic
	attribs         map[uint16]*Attribute // find descriptor by handle
	charByUUID      map[string]*Characteristic
	curChar         *Characteristic // charicteristc being discovered
	procMgr         procedureManager
	state           int
}

// ConnectionParameters get the connection parameters
func (c *Connection) ConnectionParameters() ConnectionParameters {
	return c.params
}

// ConnectionStatus get the connection status
func (c *Connection) ConnectionStatus() ConnectionStatus {
	return c.status
}

func (c *Connection) attclientReadByGroupType(uuid []byte, timeoutMs time.Duration) error {
	return c.procMgr.perform(timeoutMs, procedureGeneral, func() {
		c.central.api.AttclientReadByGroupType(c.status.Connection, 1, 0xffff, uuid)
	})
}

func (c *Connection) attclientReadByType(service *Service, char []byte, timeoutMs time.Duration) error {
	return c.procMgr.perform(timeoutMs, procedureGeneral, func() {
		c.central.api.AttclientReadByType(c.status.Connection,
			service.startHandle, service.endHandle, char)
	})
}

func (c *Connection) attclientFindInformation(service *Service, timeoutMs time.Duration) error {
	return c.procMgr.perform(timeoutMs, procedureGeneral, func() {
		c.central.api.AttclientFindInformation(c.status.Connection,
			service.startHandle, service.endHandle)
	})
}

// addService add a new service
func (c *Connection) addService(service *Service) {
	if c.services[service.startHandle] == nil {
		c.services[service.startHandle] = service
	}
}

// addCharacteristicInfo update characteristic information
func (c *Connection) addCharacteristicInfo(chrHandle uint16, uuid []byte) {
	if bytes.Equal(uuid, CharacteristicUUID) {
		// found the characteristic UUID -- always listed first in a characteristic
		// and designates the begginging of a new char decl
		c.curChar = &Characteristic{}
		c.characteristics[chrHandle] = c.curChar
	}

	// populate the descriptor tables
	c.attribs[chrHandle] = c.curChar.addDescriptor(uuid, chrHandle, []byte{})
}

// updateStatus update connection status
func (c *Connection) updateStatus(status *ConnectionStatus) {
	c.status = *status

	if status.Flags&ConnectionStatusFlagCompleted != 0 {
		// connection attempt succeeded
		if c.central.openConnections[status.Connection] == nil {
			// notify listern that the connection attempt succeeded
			c.central.openConnections[status.Connection] = c
			c.state = connectionStateConnected
			c.procMgr.complete(procedureConnect)
		}
	} else if status.Flags&ConnectionStatusFlagParametersChange != 0 {
		c.procMgr.complete(procedureParamsUpdated)
	} else if status.Flags&ConnectionStatusFlagEncrypted != 0 {
		c.state = connectionStateEncrypted
		c.procMgr.complete(procedureEncrypt)
	}
}

// Open open connection
func (c *Connection) Open() error {
	var timeout time.Duration = 5000
	err := c.procMgr.perform(timeout, connectionStateConnected, func() {
		c.central.api.GapConnectDirect(c.resp.Address, &c.params)
	})

	if err == nil {
		// FIXME need to define these timeouts as global variables
		// FIXME timeout
		// connection is Open, query the primary service to find out what services are supported
		// these will be registered
		c.attclientReadByGroupType(PrimaryServiceUUID, timeout)

		// FIXME we need to add timeouts to the API
		// iterate through the list of services to discover the characteristics
		for _, s := range c.services {
			if err = c.attclientFindInformation(s, timeout); err != nil {
				break
			}

			if err = c.attclientReadByType(s, CharacteristicUUID, timeout); err != nil {
				break
			}

			if err = c.attclientReadByType(s, ClientCharacteristicConfigUUID, timeout); err != nil {
				break
			}

			if err = c.attclientReadByType(s, UserDescriptionUUID, timeout); err != nil {
				break
			}
		}
	}

	return err
}

// CharacteristicForUUID returns the Characteristic for the given UUID
func (c *Connection) CharacteristicForUUID(uuid []byte) *Characteristic {
	return c.charByUUID[string(uuid)]
}

// CharacteristicByHandle returns the Characteristic for the given handle
func (c *Connection) CharacteristicByHandle(handle uint16) *Characteristic {
	return c.characteristics[handle]
}

// NewConnection construct a new connection
func (c *Central) NewConnection(resp *GapScanRespone, params *ConnectionParameters) *Connection {
	var conn = c.connections[resp.Address.Hashable()]
	if conn == nil {
		conn = &Connection{resp: *resp, params: *params, central: c}
		c.connections[resp.Address.Hashable()] = conn
	}

	return conn
}

// ParseGapScanResponse parse a scan response
func ParseGapScanResponse(adv *GapScanRespone) *AdvertisementData {
	var cur int
	var result = AdvertisementData{}

	total := len(adv.Data)
	for (cur + 1) < total {
		// parse atrribute header
		segLen := int(adv.Data[cur])
		cur++
		segType := adv.Data[cur]
		cur++

		if (cur + segLen) >= total {
			// exit sielently
			break
		}

		// save parsed results
		result[segType] = adv.Data[cur : cur+segLen]

		cur += segLen
	}

	return &result
}

func findServicesForParsedAdvertisement(adv AdvertisementData) ServiceUUIDs {
	var head = ServiceUUIDs{}
	for segType := range adv {
		var dim = 0
		// FIXME we should define constants
		switch segType {
		case 2, 3: // incomplete/complete list of 16-bit UUIDs
			dim = 2
		case 4, 5: // incomplete list of 32-bit UUIDs
			dim = 4
		case 6, 7: // incomplete list of 128-bit UUIDs
			dim = 16
		}

		if dim > 0 {
			data := adv[segType]
			limit := len(data) - (dim - 1) // in go this statement ends up signed :)
			for i := 0; i < limit; i += dim {
				head = append(head, data[i:i+dim])
			}
		}
	}

	return head
}

//
// apiDelegate methods
//

// OnSystemBoot invoked when the BLED112 boots
func (dgt *apiDelegate) OnSystemBoot(info *SystemInfo) {

}

// OnSystemDebug invoked when BLED112 generates debug reply
func (dgt *apiDelegate) OnSystemDebug(data []byte) {

}

// OnSystemEndpointWatermarkRx inovked when receiveing Endpoint Watermark
func (dgt *apiDelegate) OnSystemEndpointWatermarkRx(endpoint byte, data byte) {

}

// OnSystemEndpointWatermarkTx inovked when transmitting Endpoint Watermark
func (dgt *apiDelegate) OnSystemEndpointWatermarkTx(endpoint byte, data byte) {

}

// OnSystemScriptFailure invoked on script failure
func (dgt *apiDelegate) OnSystemScriptFailure(addr uint16, reason uint16) {

}

// OnSystemNoLicenseKey invoked when no license key is found
func (dgt *apiDelegate) OnSystemNoLicenseKey() {

}

// OnFlashPsKey invoked when flash PS Key is updated
func (dgt *apiDelegate) OnFlashPsKey(key uint16, value []byte) {

}

// OnAttributeValue invoked when attribute value changes
func (dgt *apiDelegate) OnAttributeValue(connHandle byte, reason byte, handle uint16, offset uint16, value []byte) {
}

// OnAttributeUserReadRequest inovked by user read request
func (dgt *apiDelegate) OnAttributeUserReadRequest(connection byte, handle uint16, offset uint16, maxSize byte) {

}

// OnAttributeStatus invoked when status changes
func (dgt *apiDelegate) OnAttributeStatus(handle uint16, flags byte) {

}

// OnConnectionStatus invoked when the connection status changes
func (dgt *apiDelegate) OnConnectionStatus(status *ConnectionStatus) {
	// connection is already open
	var conn = dgt.central.connections[status.Address.Hashable()]
	if conn != nil {
		conn.updateStatus(status)
	}
}

// OnConnectionVersionIndication invoked when version indication is updated
func (dgt *apiDelegate) OnConnectionVersionIndication(ind *ConnectionVersionIndication) {
}

// OnConnectionFeatureIndication invoked when feature indication is updated
func (dgt *apiDelegate) OnConnectionFeatureIndication(connection byte, features []byte) {
}

// OnConnectionRawRx invoked when raw data is received
func (dgt *apiDelegate) OnConnectionRawRx(connection byte, data []byte) {
}

// OnConnectionDisconnected invoked when the connection is lost
func (dgt *apiDelegate) OnConnectionDisconnected(handle byte, reason uint16) {
	conn := dgt.central.openConnections[handle]
	if conn != nil {
		dgt.central.openConnections[handle] = nil
		conn.state = connectionStateDisconnected
		conn.procMgr.complete(procedureDisconnect)
		conn.delegate.OnDisconnected(reason)
	}
}

// OnAttrclientIndicated inovked when an attribute is indicated
func (dgt *apiDelegate) OnAttrclientIndicated(connection byte, attrHandle uint16) {
}

// OnAttrclientProcedureCompleted invoked upon procedure completion
func (dgt *apiDelegate) OnAttrclientProcedureCompleted(connHandle byte, result uint16, chrHandle uint16) {
	if conn := dgt.central.openConnections[connHandle]; conn != nil {
		conn.procMgr.complete(procedureGeneral)
	}
}

// OnAttrclientGroupFound invoked when the group is found
func (dgt *apiDelegate) OnAttrclientGroupFound(connHandle byte, start uint16, end uint16, uuid []byte) {
	if conn := dgt.central.openConnections[connHandle]; conn != nil {
		conn.addService(&Service{startHandle: start, endHandle: end, uuid: uuid})
	}
}

// OnAttrclientAttributeFound invoked when the attribute is found
func (dgt *apiDelegate) OnAttrclientAttributeFound(connection byte, chrdecl uint16, value uint16, properties byte, uuid []byte) {

}

// OnAttrclientFindInformationFound invoked when information is available
func (dgt *apiDelegate) OnAttrclientFindInformationFound(connHandle byte, chrHandle uint16, uuid []byte) {
	if conn := dgt.central.openConnections[connHandle]; conn != nil {
		conn.addCharacteristicInfo(chrHandle, uuid)
	}
}

// OnAttrclientAttributeValue invoked when value changes
func (dgt *apiDelegate) OnAttrclientAttributeValue(connHandle byte, atrHandle uint16, valueType byte, value []byte) {
	if conn := dgt.central.openConnections[connHandle]; conn != nil {
		if at := conn.attribs[atrHandle]; at != nil {
			at.update(value)
		}

		conn.procMgr.complete(procedureReadAttribute) // FIXME What about indications etc?
	}
}

// OnAttrclientReadMultipleResponse invoked when the client responds
func (dgt *apiDelegate) OnAttrclientReadMultipleResponse(connection byte, handles []byte) {}

// OnGapScanResponse invoked when GAP Scan Response is available
func (dgt *apiDelegate) OnGapScanResponse(resp *GapScanRespone) {
	// accumulate repsonses
	dgt.central.knownPeripherals[resp.Address.Hashable()] = resp
}

// OnGapModeChanged invoked when the GAP mode changes
func (dgt *apiDelegate) OnGapModeChanged(discover byte, connect byte) {

}

// OnSmSmpData invoked when security manager data is posted
func (dgt *apiDelegate) OnSmSmpData(handle byte, packet byte, data []byte) {}

// OnSmBondingFail invoked when the bonding fails
func (dgt *apiDelegate) OnSmBondingFail(handle byte, result uint16) {}

// OnSmPasskeyDisplay inovked when the paskey is displayed
func (dgt *apiDelegate) OnSmPasskeyDisplay(handle byte, passkey uint32) {}

// OnSmPasskeyRequest invoked when the paskey is requested
func (dgt *apiDelegate) OnSmPasskeyRequest(handle byte) {}

// OnSmBondStatus invoked when the bond status is updated
func (dgt *apiDelegate) OnSmBondStatus(status *SmBondStatus) {}

// OnHardwareIoPortStatus invoked when the IO port status is changed
func (dgt *apiDelegate) OnHardwareIoPortStatus(status *IoPortStatus) {}

// OnHardwareSoftTimer invoked upon soft timer expiry
func (dgt *apiDelegate) OnHardwareSoftTimer(handle byte) {}

// OnHardwareAdcResult invoked when ADC result is generated
func (dgt *apiDelegate) OnHardwareAdcResult(input byte, value int16) {}
